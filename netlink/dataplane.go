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
	"github.com/osrg/gobgp/client"
	bgpconfig "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/goplane/config"
	"github.com/vishvananda/netlink"
	"gopkg.in/tomb.v2"
)

type Dataplane struct {
	t         tomb.Tomb
	config    *config.Config
	modRibCh  chan []*table.Path
	advPathCh chan *table.Path
	vnMap     map[string]*VirtualNetwork
	addVnCh   chan config.VirtualNetwork
	delVnCh   chan config.VirtualNetwork
	grpcHost  string
	client    *client.Client
	routerId  string
	localAS   uint32
}

func (d *Dataplane) getNexthop(path *table.Path) (int, net.IP, int) {
	var flags int
	if path == nil || path.IsLocal() {
		return 0, nil, flags
	}
	nh := path.GetNexthop()
	if nh.To4() != nil {
		return 0, nh.To4(), flags
	}
	list, err := netlink.NeighList(0, netlink.FAMILY_V6)
	if err != nil {
		log.Errorf("failed to get neigh list: %s", err)
		return 0, nil, flags
	}
	var neigh *netlink.Neigh
	for _, n := range list {
		if n.IP.Equal(nh) {
			neigh = &n
			break
		}
	}
	if neigh == nil {
		log.Warnf("no neighbor info for %s", path)
		return 0, nil, flags
	}
	list, err = netlink.NeighList(neigh.LinkIndex, netlink.FAMILY_V4)
	if err != nil {
		log.Errorf("failed to get neigh list: %s", err)
		return 0, nil, flags
	}
	flags = int(netlink.FLAG_ONLINK)
	for _, n := range list {
		if n.HardwareAddr.String() == neigh.HardwareAddr.String() {
			return n.LinkIndex, n.IP.To4(), flags
		}
	}
	nh = net.IPv4(169, 254, 0, 1)
	err = netlink.NeighAdd(&netlink.Neigh{
		LinkIndex:    neigh.LinkIndex,
		State:        netlink.NUD_PERMANENT,
		IP:           nh,
		HardwareAddr: neigh.HardwareAddr,
	})
	if err != nil {
		log.Errorf("neigh add: %s", err)
	}
	return neigh.LinkIndex, nh, flags
}

func (d *Dataplane) modRib(paths []*table.Path) error {
	if len(paths) == 0 {
		return nil
	}
	p := paths[0]

	dst, _ := netlink.ParseIPNet(p.GetNlri().String())
	route := &netlink.Route{
		Dst: dst,
		Src: net.ParseIP(d.routerId),
	}

	if len(paths) == 1 {
		if p.IsLocal() {
			return nil
		}
		link, gw, flags := d.getNexthop(p)
		route.Gw = gw
		route.LinkIndex = link
		route.Flags = flags
	} else {
		mp := make([]*netlink.NexthopInfo, 0, len(paths))
		for _, path := range paths {
			if path.IsLocal() {
				continue
			}
			link, gw, flags := d.getNexthop(path)
			mp = append(mp, &netlink.NexthopInfo{
				Gw:        gw,
				LinkIndex: link,
				Flags:     flags,
			})
		}
		if len(mp) == 0 {
			return nil
		}
		route.MultiPath = mp
	}
	if p.IsWithdraw {
		log.Info("del route:", route)
		return netlink.RouteDel(route)
	}
	log.Info("add route:", route)
	return netlink.RouteReplace(route)
}

func (d *Dataplane) monitorBest() error {

	watcher, err := d.client.MonitorRIB(bgp.RF_IPv4_UC, true)
	if err != nil {
		return err
	}
	for {
		dst, err := watcher.Recv()
		if err != nil {
			return err
		}
		d.modRibCh <- dst.GetAllKnownPathList()
	}
	return nil
}

func (d *Dataplane) Serve() error {
	for {
		var s *bgpconfig.Global
		client, err := client.New(d.grpcHost)
		if err != nil {
			log.Errorf("%s", err)
			goto ERR
		}
		d.client = client
		s, err = d.client.GetServer()
		if err != nil {
			log.Errorf("%s", err)
			goto ERR
		}
		d.routerId = s.Config.RouterId
		d.localAS = s.Config.As
		if d.routerId != "" && d.localAS != 0 {
			break
		}
	ERR:
		log.Debug("BGP server is not ready..waiting...")
		time.Sleep(time.Second * 10)
	}

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

	d.advPathCh <- table.NewPath(nil, bgp.NewIPAddrPrefix(uint8(32), d.routerId), false, []bgp.PathAttributeInterface{
		bgp.NewPathAttributeNextHop("0.0.0.0"),
		bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP),
	}, time.Now(), false)
	d.t.Go(d.monitorBest)

	for {
		select {
		case <-d.t.Dying():
			log.Error("dying! ", d.t.Err())
			return nil
		case paths := <-d.modRibCh:
			err = d.modRib(paths)
			if err != nil {
				log.Error("failed to mod rib: ", err)
			}
		case p := <-d.advPathCh:
			_, err := d.client.AddPath([]*table.Path{p})
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
	modRibCh := make(chan []*table.Path, 16)
	advPathCh := make(chan *table.Path, 16)
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
