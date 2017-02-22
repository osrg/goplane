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
	"syscall"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/client"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/gobgp/table"
	"github.com/osrg/goplane/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"gopkg.in/tomb.v2"
)

type netlinkEvent struct {
	mac        net.HardwareAddr
	ip         net.IP
	isWithdraw bool
}

type VirtualNetwork struct {
	t           tomb.Tomb
	connMap     map[string]net.Conn
	config      config.VirtualNetwork
	multicastCh chan *table.Path
	macadvCh    chan *table.Path
	floodCh     chan []byte
	netlinkCh   chan *netlinkEvent
	grpcHost    string
	client      *client.Client
	routerId    string
}

func (n *VirtualNetwork) Stop() {
	n.t.Kill(fmt.Errorf("admin stop"))
}

func (n *VirtualNetwork) modVrf(withdraw bool) error {
	rd, err := bgp.ParseRouteDistinguisher(n.config.RD)
	if err != nil {
		return err
	}
	rt, err := bgp.ParseRouteTarget(n.config.RD)
	if err != nil {
		return err
	}
	if withdraw {
		return n.client.DeleteVRF(n.config.RD)
	}
	return n.client.AddVRF(n.config.RD, 0, rd, []bgp.ExtendedCommunityInterface{rt}, []bgp.ExtendedCommunityInterface{rt})
}

func (n *VirtualNetwork) Serve() error {
	client, err := client.New(n.grpcHost)
	if err != nil {
		log.Fatalf("%s", err)
	}
	n.client = client

	log.Debugf("vtep intf: %s", n.config.VtepInterface)
	link, err := netlink.LinkByName(n.config.VtepInterface)
	master := 0
	if err == nil {
		log.Debug("link type:", link.Type())
		vtep := link.(*netlink.Vxlan)
		err = netlink.LinkSetDown(vtep)
		log.Debugf("set %s down", n.config.VtepInterface)
		if err != nil {
			return fmt.Errorf("failed to set link %s down", n.config.VtepInterface)
		}
		master = vtep.MasterIndex
		log.Debugf("del %s", n.config.VtepInterface)
		err = netlink.LinkDel(link)
		if err != nil {
			return fmt.Errorf("failed to del %s", n.config.VtepInterface)
		}
	}

	if master > 0 {
		b, _ := netlink.LinkByIndex(master)
		br := b.(*netlink.Bridge)
		err = netlink.LinkSetDown(br)
		log.Debugf("set %s down", br.LinkAttrs.Name)
		if err != nil {
			return fmt.Errorf("failed to set %s down", br.LinkAttrs.Name)
		}
		log.Debugf("del %s", br.LinkAttrs.Name)
		err = netlink.LinkDel(br)
		if err != nil {
			return fmt.Errorf("failed to del %s", br.LinkAttrs.Name)
		}
	}

	brName := fmt.Sprintf("br%d", n.config.VNI)

	b, err := netlink.LinkByName(brName)
	if err == nil {
		br := b.(*netlink.Bridge)
		err = netlink.LinkSetDown(br)
		log.Debugf("set %s down", br.LinkAttrs.Name)
		if err != nil {
			return fmt.Errorf("failed to set %s down", br.LinkAttrs.Name)
		}
		log.Debugf("del %s", br.LinkAttrs.Name)
		err = netlink.LinkDel(br)
		if err != nil {
			return fmt.Errorf("failed to del %s", br.LinkAttrs.Name)
		}
	}

	br := &netlink.Bridge{
		LinkAttrs: netlink.LinkAttrs{
			Name: brName,
		},
	}

	log.Debugf("add %s", brName)
	err = netlink.LinkAdd(br)
	if err != nil {
		return fmt.Errorf("failed to add link %s. %s", brName, err)
	}
	err = netlink.LinkSetUp(br)
	if err != nil {
		return fmt.Errorf("failed to set %s up", brName)
	}

	link = &netlink.Vxlan{
		LinkAttrs: netlink.LinkAttrs{
			Name: n.config.VtepInterface,
		},
		VxlanId: int(n.config.VNI),
		SrcAddr: net.ParseIP(n.routerId),
	}

	log.Debugf("add %s", n.config.VtepInterface)
	err = netlink.LinkAdd(link)
	if err != nil {
		return fmt.Errorf("failed to add link %s. %s", n.config.VtepInterface, err)
	}
	err = netlink.LinkSetUp(link)
	if err != nil {
		return fmt.Errorf("failed to set %s up", n.config.VtepInterface)
	}

	err = netlink.LinkSetMaster(link, br)
	if err != nil {
		return fmt.Errorf("failed to set master %s dev %s", brName, n.config.VtepInterface)
	}

	for _, member := range n.config.MemberInterfaces {
		m, err := netlink.LinkByName(member)
		if err != nil {
			log.Errorf("can't find %s", member)
			continue
		}
		err = netlink.LinkSetUp(m)
		if err != nil {
			return fmt.Errorf("failed to set %s up", member)
		}
		err = netlink.LinkSetMaster(m, br)
		if err != nil {
			return fmt.Errorf("failed to set master %s dev %s", brName, member)
		}
	}

	withdraw := false
	err = n.modVrf(withdraw)
	if err != nil {
		log.Fatal(err)
	}

	err = n.sendMulticast(withdraw)
	if err != nil {
		log.Fatal(err)
	}

	n.t.Go(n.monitorBest)
	n.t.Go(n.monitorNetlink)

	for _, member := range n.config.SniffInterfaces {
		n.t.Go(func() error {
			return n.sniffPkt(member)
		})
	}

	for {
		select {
		case <-n.t.Dying():
			log.Errorf("stop virtualnetwork %s", n.config.RD)
			for h, conn := range n.connMap {
				log.Debugf("close udp connection to %s", h)
				conn.Close()
			}
			withdraw = true
			n.modVrf(withdraw)
			return nil
		case p := <-n.multicastCh:
			e := p.GetNlri().(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
			if e.ETag != n.config.Etag || p.GetNexthop().String() == "0.0.0.0" {
				continue
			}
			err = n.modConnMap(p)
			if err != nil {
				log.Errorf("mod conn failed. kill main loop. err: %s", err)
				return err
			}
		case p := <-n.macadvCh:
			e := p.GetNlri().(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
			if e.ETag != n.config.Etag || p.GetNexthop().String() == "0.0.0.0" {
				continue
			}
			err = n.modFdb(p)
			if err != nil {
				log.Errorf("mod fdb failed. kill main loop. err: %s", err)
				return err
			}
		case p := <-n.floodCh:
			err = n.flood(p)
			if err != nil {
				log.Errorf("flood failed. kill main loop. err: %s", err)
				return err
			}
		case e := <-n.netlinkCh:
			err = n.modPath(e)
			if err != nil {
				log.Errorf("modpath failed. kill main loop. err: %s", err)
				return err
			}
		}
	}
}

func (f *VirtualNetwork) modConnMap(path *table.Path) error {
	addr := path.GetNexthop().String()
	e := path.GetNlri().(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
	etag := e.ETag
	log.Debugf("mod cannection map: nh %s, vtep addr %s etag %d withdraw %t", addr, path.GetNlri(), etag, path.IsWithdraw)
	if path.IsWithdraw {
		_, ok := f.connMap[addr]
		if !ok {
			return fmt.Errorf("can't find %s conn", addr)
		}

		f.connMap[addr].Close()
		delete(f.connMap, addr)
	} else {
		_, ok := f.connMap[addr]
		if ok {
			log.Debugf("refresh. close connection to %s", addr)
			f.connMap[addr].Close()
			delete(f.connMap, addr)
		}
		udpAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", addr, f.config.VxlanPort))
		if err != nil {
			log.Fatal(err)
		}

		log.Debugf("connect to %s", addr)
		conn, err := net.DialUDP("udp", nil, udpAddr)
		if err != nil {
			log.Warnf("failed to dial UDP(%s) %s", addr, err)
			return nil
		}
		f.connMap[addr] = conn
	}
	log.WithFields(log.Fields{
		"Topic": "virtualnetwork",
		"Etag":  f.config.Etag,
	}).Debugf("connMap: %s", f.connMap)
	return nil
}

func (f *VirtualNetwork) modFdb(path *table.Path) error {
	log.WithFields(log.Fields{
		"Topic": "VirtualNetwork",
		"Etag":  f.config.Etag,
	}).Debugf("modFdb new path, prefix: %s, nexthop: %s, withdraw: %t", path.GetNlri(), path.GetNexthop(), path.IsWithdraw)

	e := path.GetNlri().(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	mac := e.MacAddress
	ip := path.GetNexthop()

	link, err := netlink.LinkByName(f.config.VtepInterface)
	if err != nil {
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("failed lookup link by name: %s", f.config.VtepInterface)
		return nil
	}

	n := &netlink.Neigh{
		LinkIndex:    link.Attrs().Index,
		Family:       int(netlink.NDA_VNI),
		State:        int(netlink.NUD_NOARP | netlink.NUD_PERMANENT),
		Type:         syscall.RTM_NEWNEIGH,
		Flags:        int(netlink.NTF_SELF),
		IP:           ip,
		HardwareAddr: mac,
	}

	if path.IsWithdraw {
		err = netlink.NeighDel(n)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "VirtualNetwork",
				"Etag":  f.config.Etag,
			}).Errorf("failed to del fdb: %s, %s", n, err)
		}
	} else {
		err = netlink.NeighAppend(n)
		if err != nil {
			log.WithFields(log.Fields{
				"Topic": "VirtualNetwork",
				"Etag":  f.config.Etag,
			}).Debugf("failed to add fdb: %s, %s", n, err)
		}
	}
	return err
}

func (f *VirtualNetwork) flood(pkt []byte) error {
	vxlanHeader := NewVXLAN(f.config.VNI)
	b := vxlanHeader.Serialize()
	b = append(b, pkt...)

	for _, c := range f.connMap {
		cnt, err := c.Write(b)
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("send to %s: cnt:%d, err:%s", c.RemoteAddr(), cnt, err)
		if err != nil {
			return err
		}
	}

	return nil
}

func (n *VirtualNetwork) sendMulticast(withdraw bool) error {

	pattrs := []bgp.PathAttributeInterface{}

	pattrs = append(pattrs, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))

	var rd bgp.RouteDistinguisherInterface
	multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
		RD:              rd,
		IPAddressLength: uint8(32),
		IPAddress:       net.ParseIP(n.routerId),
		ETag:            uint32(n.config.Etag),
	}
	nlri := bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
	nexthop := "0.0.0.0"
	pattrs = append(pattrs, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))

	id := &bgp.IngressReplTunnelID{
		Value: net.ParseIP(n.routerId),
	}
	pattrs = append(pattrs, bgp.NewPathAttributePmsiTunnel(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, id))

	path := table.NewPath(nil, nlri, withdraw, pattrs, time.Now(), false)
	_, err := n.client.AddVRFPath(n.config.RD, []*table.Path{path})
	return err
}

func (f *VirtualNetwork) modPath(n *netlinkEvent) error {
	pattrs := []bgp.PathAttributeInterface{}

	macIpAdv := &bgp.EVPNMacIPAdvertisementRoute{
		ESI: bgp.EthernetSegmentIdentifier{
			Type: bgp.ESI_ARBITRARY,
		},
		MacAddressLength: 48,
		MacAddress:       n.mac,
		IPAddressLength:  0,
		Labels:           []uint32{uint32(f.config.VNI)},
		ETag:             uint32(f.config.Etag),
	}
	nlri := bgp.NewEVPNNLRI(bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT, 0, macIpAdv)
	nexthop := "0.0.0.0"
	pattrs = append(pattrs, bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}))

	pattrs = append(pattrs, bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP))

	isTransitive := true
	o := bgp.NewOpaqueExtended(isTransitive)
	o.SubType = bgp.EC_SUBTYPE_ENCAPSULATION
	o.Value = &bgp.EncapExtended{bgp.TUNNEL_TYPE_VXLAN}
	pattrs = append(pattrs, bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{o}))
	path := table.NewPath(nil, nlri, n.isWithdraw, pattrs, time.Now(), false)

	_, err := f.client.AddPath([]*table.Path{path})
	return err
}

func (n *VirtualNetwork) monitorBest() error {
	watcher, err := n.client.MonitorRIB(bgp.RF_EVPN, true)
	if err != nil {
		return err
	}
	for {
		dst, err := watcher.Recv()
		if err != nil {
			return err
		}
		path := dst.GetAllKnownPathList()[0]
		nlri := path.GetNlri()

		switch nlri.(*bgp.EVPNNLRI).RouteType {
		case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
			n.macadvCh <- path
		case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
			n.multicastCh <- path
		}
	}
}

func (f *VirtualNetwork) sniffPkt(ifname string) error {
	conn, err := NewPFConn(ifname)
	if err != nil {
		return err
	}
	buf := make([]byte, 2048)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			log.Errorf("failed to recv from %s, err: %s", conn, err)
			return err
		}
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("recv from %s, len: %d", conn, n)
		f.floodCh <- buf[:n]
	}
}

func (f *VirtualNetwork) monitorNetlink() error {
	s, err := nl.Subscribe(syscall.NETLINK_ROUTE, uint(RTMGRP_NEIGH), uint(RTMGRP_LINK), uint(RTMGRP_NOTIFY))
	if err != nil {
		return err
	}

	idxs := make([]int, 0, len(f.config.SniffInterfaces))
	for _, member := range f.config.SniffInterfaces {
		link, err := netlink.LinkByName(member)
		if err != nil {
			log.Errorf("failed to get link %s", member)
			return err
		}
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("monitoring: %s, index: %d", link.Attrs().Name, link.Attrs().Index)
		idxs = append(idxs, link.Attrs().Index)
	}

	for {
		msgs, err := s.Receive()
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			t := RTM_TYPE(msg.Header.Type)
			switch t {
			case RTM_NEWNEIGH, RTM_DELNEIGH:
				n, _ := netlink.NeighDeserialize(msg.Data)
				for _, idx := range idxs {
					if n.LinkIndex == idx {
						log.WithFields(log.Fields{
							"Topic": "VirtualNetwork",
							"Etag":  f.config.Etag,
						}).Debugf("mac: %s, ip: %s, index: %d, family: %s, state: %s, type: %s, flags: %s", n.HardwareAddr, n.IP, n.LinkIndex, NDA_TYPE(n.Family), NUD_TYPE(n.State), RTM_TYPE(n.Type), NTF_TYPE(n.Flags))
						var withdraw bool
						if t == RTM_DELNEIGH {
							withdraw = true
						}
						f.netlinkCh <- &netlinkEvent{n.HardwareAddr, n.IP, withdraw}
						break
					}
				}
			}
		}
	}
}

func NewVirtualNetwork(config config.VirtualNetwork, routerId, grpcHost string) *VirtualNetwork {
	macadvCh := make(chan *table.Path, 16)
	multicastCh := make(chan *table.Path, 16)
	floodCh := make(chan []byte, 16)
	netlinkCh := make(chan *netlinkEvent, 16)

	return &VirtualNetwork{
		config:      config,
		connMap:     map[string]net.Conn{},
		macadvCh:    macadvCh,
		multicastCh: multicastCh,
		floodCh:     floodCh,
		netlinkCh:   netlinkCh,
		routerId:    routerId,
		grpcHost:    grpcHost,
	}
}
