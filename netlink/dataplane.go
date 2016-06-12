// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netlink

import (
	"fmt"
	"net"
	"time"

	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/goplane/config"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
)

type Dataplane struct {
	t         tomb.Tomb
	config    *config.Config
	modRibCh  chan *api.Path
	advPathCh chan *api.Path
	vnMap     map[string]*VirtualNetwork
	addVnCh   chan config.VirtualNetwork
	delVnCh   chan config.VirtualNetwork
	grpcHost  string
	client    api.GobgpApiClient
	routerId  string
}

func (d *Dataplane) advPath(p *api.Path) error {
	arg := &api.AddPathRequest{
		Resource: api.Resource_GLOBAL,
		Path:     p,
	}
	_, err := d.client.AddPath(context.Background(), arg)
	return err
}

func (d *Dataplane) modRib(p *api.Path) error {
	var nlri bgp.AddrPrefixInterface
	var nexthop net.IP

	if len(p.Nlri) > 0 {
		nlri = &bgp.IPAddrPrefix{}
		err := nlri.DecodeFromBytes(p.Nlri)
		if err != nil {
			return err
		}
	}

	for _, attr := range p.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return err
		}

		err = p.DecodeFromBytes(attr)
		if err != nil {
			return err
		}

		switch p.GetType() {
		case bgp.BGP_ATTR_TYPE_NEXT_HOP:
			n := p.(*bgp.PathAttributeNextHop)
			nexthop = n.Value
		case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
			mpreach := p.(*bgp.PathAttributeMpReachNLRI)
			if len(mpreach.Value) != 1 {
				return fmt.Errorf("include only one route in mp_reach_nlri")
			}
			nlri = mpreach.Value[0]
			nexthop = mpreach.Nexthop
		}
	}

	if nexthop.String() == "0.0.0.0" {
		return nil
	}

	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		Dst: dst,
		Src: net.ParseIP(d.routerId),
		Gw:  nexthop,
	}
	routes, _ := netlink.RouteList(nil, netlink.FAMILY_V4)
	for _, route := range routes {
		d := "0.0.0.0/0"
		if route.Dst != nil {
			d = route.Dst.String()
		}
		if d == dst.String() {
			err := netlink.RouteDel(&route)
			if err != nil {
				return err
			}
		}
	}
	if p.IsWithdraw {
		return nil
	}
	return netlink.RouteAdd(route)
}

func (d *Dataplane) monitorBest() error {

	err := func() error {
		rsp, err := d.client.GetRib(context.Background(), &api.GetRibRequest{
			Table: &api.Table{
				Type:   api.Resource_GLOBAL,
				Family: uint32(bgp.RF_IPv4_UC),
			},
		})
		if err != nil {
			return err
		}
		rib := rsp.Table
		for _, dst := range rib.Destinations {
			for _, p := range dst.Paths {
				if p.Best {
					d.modRibCh <- p
					break
				}
			}
		}
		return nil
	}()

	if err != nil {
		return err
	}

	arg := &api.Table{
		Type:   api.Resource_GLOBAL,
		Family: uint32(bgp.RF_IPv4_UC),
	}
	stream, err := d.client.MonitorRib(context.Background(), arg)
	if err != nil {
		return err
	}
	for {
		dst, err := stream.Recv()
		if err != nil {
			return err
		}
		d.modRibCh <- dst.Paths[0]
	}
	return nil
}

func (d *Dataplane) Serve() error {
	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial(d.grpcHost, timeout, grpc.WithBlock(), grpc.WithInsecure())
	if err != nil {
		log.Fatalf("%s", err)
	}
	d.client = api.NewGobgpApiClient(conn)
	rsp, err := d.client.GetServer(context.Background(), &api.GetServerRequest{})
	if err != nil {
		return err
	}
	d.routerId = rsp.Global.RouterId

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get lo")
	}

	addrList, err := netlink.AddrList(lo, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get addr list of lo")
	}

	addr, err := netlink.ParseAddr(d.routerId + "/32")
	if err != nil {
		return fmt.Errorf("failed to parse addr: %s", d.routerId)
	}

	exist := false
	for _, a := range addrList {
		if a.Equal(*addr) {
			exist = true
		}
	}

	if !exist {
		log.Debugf("add route to lo")
		err = netlink.AddrAdd(lo, addr)
		if err != nil {
			return fmt.Errorf("failed to add addr %s to lo", addr)
		}
	}

	path := &api.Path{
		Pattrs: make([][]byte, 0),
	}
	path.Nlri, _ = bgp.NewIPAddrPrefix(uint8(32), d.routerId).Serialize()
	n, _ := bgp.NewPathAttributeNextHop("0.0.0.0").Serialize()
	path.Pattrs = append(path.Pattrs, n)
	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP).Serialize()
	path.Pattrs = append(path.Pattrs, origin)

	d.advPathCh <- path
	d.t.Go(d.monitorBest)

	for {
		select {
		case <-d.t.Dying():
			log.Error("dying! ", d.t.Err())
			return nil
		case p := <-d.modRibCh:
			err = d.modRib(p)
			if err != nil {
				log.Error("failed to mod rib: ", err)
			}
		case p := <-d.advPathCh:
			err = d.advPath(p)
			if err != nil {
				log.Error("failed to adv path: ", err)
			}
		case v := <-d.addVnCh:
			vn := NewVirtualNetwork(v, d.routerId, d.grpcHost)
			d.vnMap[v.RD] = vn
			d.t.Go(vn.Serve)
		case v := <-d.delVnCh:
			vn := d.vnMap[v.RD]
			vn.Stop()
			delete(d.vnMap, v.RD)
		}
	}
}

func (d *Dataplane) AddVirtualNetwork(c config.VirtualNetwork) error {
	d.addVnCh <- c
	return nil
}

func (d *Dataplane) DeleteVirtualNetwork(c config.VirtualNetwork) error {
	d.delVnCh <- c
	return nil
}

func NewDataplane(c *config.Config, grpcHost string) *Dataplane {
	modRibCh := make(chan *api.Path, 16)
	advPathCh := make(chan *api.Path, 16)
	addVnCh := make(chan config.VirtualNetwork)
	delVnCh := make(chan config.VirtualNetwork)
	return &Dataplane{
		config:    c,
		modRibCh:  modRibCh,
		advPathCh: advPathCh,
		addVnCh:   addVnCh,
		delVnCh:   delVnCh,
		vnMap:     make(map[string]*VirtualNetwork),
		grpcHost:  grpcHost,
	}
}
