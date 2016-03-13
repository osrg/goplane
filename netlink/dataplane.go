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
	log "github.com/Sirupsen/logrus"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/gobgp/server"
	"github.com/osrg/goplane/config"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"
	"net"
)

type Dataplane struct {
	t         tomb.Tomb
	config    *config.Config
	modRibCh  chan *api.Path
	advPathCh chan *api.Path
	vnMap     map[string]*VirtualNetwork
	addVnCh   chan config.VirtualNetwork
	delVnCh   chan config.VirtualNetwork
	apiCh     chan *server.GrpcRequest
}

func (d *Dataplane) advPath(p *api.Path) error {
	arg := &api.ModPathArguments{
		Operation: api.Operation_ADD,
		Resource:  api.Resource_GLOBAL,
		Path:      p,
	}
	ch := make(chan *server.GrpcResponse)
	d.apiCh <- &server.GrpcRequest{
		RequestType: server.REQ_MOD_PATH,
		Data:        arg,
		ResponseCh:  ch,
	}
	return (<-ch).Err()
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

	routes, _ := netlink.RouteGet(nexthop)
	if len(routes) == 0 {
		return fmt.Errorf("no route to nexthop: %s", nexthop)
	}
	dst, _ := netlink.ParseIPNet(nlri.String())
	route := &netlink.Route{
		LinkIndex: routes[0].LinkIndex,
		Dst:       dst,
		Src:       net.ParseIP(d.config.Global.Config.RouterId),
	}
	return netlink.RouteAdd(route)
}

func (d *Dataplane) monitorBest() error {

	err := func() error {
		ch := make(chan *server.GrpcResponse)
		d.apiCh <- &server.GrpcRequest{
			RequestType: server.REQ_GLOBAL_RIB,
			RouteFamily: bgp.RF_IPv4_UC,
			ResponseCh:  ch,
			Data: &api.Table{
				Type:   api.Resource_GLOBAL,
				Family: uint32(bgp.RF_IPv4_UC),
			},
		}
		res := <-ch
		if err := res.Err(); err != nil {
			return err
		}
		rib := res.Data.(*api.Table)
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

	ch := make(chan *server.GrpcResponse, 8)
	d.apiCh <- &server.GrpcRequest{
		RequestType: server.REQ_MONITOR_GLOBAL_BEST_CHANGED,
		RouteFamily: bgp.RF_IPv4_UC,
		ResponseCh:  ch,
	}
	for res := range ch {
		if err := res.Err(); err != nil {
			return err
		}
		dst := res.Data.(*api.Destination)
		d.modRibCh <- dst.Paths[0]
	}
	return nil
}

func (d *Dataplane) Serve() error {

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get lo")
	}

	addrList, err := netlink.AddrList(lo, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get addr list of lo")
	}

	routerId := d.config.Global.Config.RouterId

	addr, err := netlink.ParseAddr(routerId + "/32")
	if err != nil {
		return fmt.Errorf("failed to parse addr: %s", routerId)
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
	path.Nlri, _ = bgp.NewIPAddrPrefix(uint8(32), routerId).Serialize()
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
			vn := NewVirtualNetwork(v, d.config.Global, d.apiCh)
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

func NewDataplane(c *config.Config, apiCh chan *server.GrpcRequest) *Dataplane {
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
		apiCh:     apiCh,
	}
}
