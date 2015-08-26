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
	"github.com/osrg/gobgp/api"
	bgpconf "github.com/osrg/gobgp/config"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/goplane/config"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
	"io"
	"net"
	"syscall"
	"time"
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
	global      bgpconf.Global
	multicastCh chan *Path
	macadvCh    chan *Path
	floodCh     chan []byte
	netlinkCh   chan *netlinkEvent
	client      api.GrpcClient
}

type Path struct {
	Nlri       bgp.AddrPrefixInterface
	Nexthop    net.IP
	Pattrs     []bgp.PathAttributeInterface
	IsWithdraw bool
}

func (n *VirtualNetwork) Stop() {
	n.t.Kill(fmt.Errorf("admin stop"))
}

func (n *VirtualNetwork) modVrf(withdraw bool) error {
	rd, err := bgp.ParseRouteDistinguisher(n.config.RD)
	if err != nil {
		return err
	}
	rdbuf, _ := rd.Serialize()
	rt, err := bgp.ParseRouteTarget(n.config.RD)
	if err != nil {
		return err
	}
	rtbuf, _ := rt.Serialize()
	op := api.Operation_ADD
	if withdraw {
		op = api.Operation_DEL
	}
	arg := &api.ModVrfArguments{
		Operation: op,
		Vrf: &api.Vrf{
			Name:     n.config.RD,
			Rd:       rdbuf,
			ImportRt: [][]byte{rtbuf},
			ExportRt: [][]byte{rtbuf},
		},
	}
	_, err = n.client.ModVrf(context.Background(), arg)
	if err != nil {
		return err
	}
	return nil
}

func (n *VirtualNetwork) Serve() error {
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
		SrcAddr: n.global.GlobalConfig.RouterId,
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

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	n.client = api.NewGrpcClient(conn)

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
		log.Debugf("start sniff %s", member)
		_, fd, err := PFPacketBind(member)
		if err != nil {
			log.Errorf("failed to sniff %s", member)
			return err
		}

		n.t.Go(func() error {
			return n.sniffPkt(fd)
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
			e := p.Nlri.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
			if e.ETag != n.config.Etag || p.Nexthop.String() == "0.0.0.0" {
				continue
			}
			err = n.modConnMap(p)
			if err != nil {
				log.Errorf("mod conn failed. kill main loop. err: %s", err)
				return err
			}
		case p := <-n.macadvCh:
			e := p.Nlri.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
			if e.ETag != n.config.Etag || p.Nexthop.String() == "0.0.0.0" {
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

func (f *VirtualNetwork) modConnMap(path *Path) error {
	addr := path.Nexthop.String()
	e := path.Nlri.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMulticastEthernetTagRoute)
	etag := e.ETag
	log.Debugf("mod cannection map: nh %s, vtep addr %s etag %d withdraw %t", addr, path.Nlri, etag, path.IsWithdraw)
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

func (f *VirtualNetwork) modFdb(path *Path) error {
	log.WithFields(log.Fields{
		"Topic": "VirtualNetwork",
		"Etag":  f.config.Etag,
	}).Debugf("modFdb new path, prefix: %s, nexthop: %s, withdraw: %t", path.Nlri, path.Nexthop, path.IsWithdraw)

	e := path.Nlri.(*bgp.EVPNNLRI).RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)
	mac := e.MacAddress
	ip := path.Nexthop

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
		Family:       int(NDA_VNI),
		State:        192,
		Type:         1,
		Flags:        int(NTF_SELF),
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
	path := &api.Path{
		Pattrs:     make([][]byte, 0),
		IsWithdraw: withdraw,
	}

	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP).Serialize()
	path.Pattrs = append(path.Pattrs, origin)

	multicastEtag := &bgp.EVPNMulticastEthernetTagRoute{
		IPAddressLength: uint8(32),
		IPAddress:       n.global.GlobalConfig.RouterId,
		ETag:            uint32(n.config.Etag),
	}
	nlri := bgp.NewEVPNNLRI(bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG, 0, multicastEtag)
	nexthop := "0.0.0.0"
	mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize()
	path.Pattrs = append(path.Pattrs, mpreach)

	id := &bgp.IngressReplTunnelID{
		Value: n.global.GlobalConfig.RouterId,
	}
	pmsi, _ := bgp.NewPathAttributePmsiTunnel(bgp.PMSI_TUNNEL_TYPE_INGRESS_REPL, false, 0, id).Serialize()
	path.Pattrs = append(path.Pattrs, pmsi)

	arg := &api.ModPathArguments{
		Resource: api.Resource_VRF,
		Name:     n.config.RD,
		Path:     path,
	}

	stream, err := n.client.ModPath(context.Background())
	if err != nil {
		return err
	}

	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s\n", res.Code, res.Msg)
	}
	return nil
}

func (f *VirtualNetwork) modPath(n *netlinkEvent) error {
	path := &api.Path{
		Pattrs:     make([][]byte, 0),
		IsWithdraw: n.isWithdraw,
	}

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
	mpreach, _ := bgp.NewPathAttributeMpReachNLRI(nexthop, []bgp.AddrPrefixInterface{nlri}).Serialize()
	path.Pattrs = append(path.Pattrs, mpreach)

	origin, _ := bgp.NewPathAttributeOrigin(bgp.BGP_ORIGIN_ATTR_TYPE_IGP).Serialize()
	path.Pattrs = append(path.Pattrs, origin)

	isTransitive := true
	o := bgp.NewOpaqueExtended(isTransitive)
	o.SubType = bgp.EC_SUBTYPE_ENCAPSULATION
	o.Value = &bgp.EncapExtended{bgp.TUNNEL_TYPE_VXLAN}
	e, _ := bgp.NewPathAttributeExtendedCommunities([]bgp.ExtendedCommunityInterface{o}).Serialize()
	path.Pattrs = append(path.Pattrs, e)

	arg := &api.ModPathArguments{
		Resource: api.Resource_VRF,
		Name:     f.config.RD,
		Path:     path,
	}

	stream, err := f.client.ModPath(context.Background())
	if err != nil {
		return err
	}

	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s\n", res.Code, res.Msg)
	}
	return nil

}

func (n *VirtualNetwork) monitorBest() error {

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGrpcClient(conn)

	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Rf:       uint32(bgp.RF_EVPN),
	}
	f := func(stream interface {
		Recv() (*api.Destination, error)
	}) error {
		for {
			dst, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			var path *api.Path
			for _, p := range dst.Paths {
				if p.Best {
					path = p
					break
				}
			}
			if path == nil {
				path = dst.Paths[0]
			}

			var nexthop net.IP
			pattrs := make([]bgp.PathAttributeInterface, 0, len(path.Pattrs))
			afi, safi := bgp.RouteFamilyToAfiSafi(bgp.RouteFamily(path.Rf))
			nlri, err := bgp.NewPrefixFromRouteFamily(afi, safi)
			if err != nil {
				return err
			}
			err = nlri.DecodeFromBytes(path.Nlri)
			if err != nil {
				return err
			}
			for _, attr := range path.Pattrs {
				p, err := bgp.GetPathAttribute(attr)
				if err != nil {
					return err
				}

				err = p.DecodeFromBytes(attr)
				if err != nil {
					return err
				}

				switch p.GetType() {
				case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
					mpreach := p.(*bgp.PathAttributeMpReachNLRI)
					if len(mpreach.Value) != 1 {
						return fmt.Errorf("include only one route in mp_reach_nlri")
					}
					nexthop = mpreach.Nexthop
				}
				pattrs = append(pattrs, p)
			}

			p := &Path{
				Nlri:       nlri,
				Nexthop:    nexthop,
				Pattrs:     pattrs,
				IsWithdraw: path.IsWithdraw,
			}

			_, ok := nlri.(*bgp.EVPNNLRI)
			if !ok {
				continue
			}

			switch nlri.(*bgp.EVPNNLRI).RouteType {
			case bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
				n.macadvCh <- p
			case bgp.EVPN_INCLUSIVE_MULTICAST_ETHERNET_TAG:
				n.multicastCh <- p
			}
		}
		return nil
	}

	stream, err := client.GetRib(context.Background(), arg)
	if err != nil {
		return err
	}
	err = f(stream)
	if err != nil {
		return err
	}

	stream, err = client.MonitorBestChanged(context.Background(), arg)
	if err != nil {
		return err
	}
	return f(stream)
}

func (f *VirtualNetwork) sniffPkt(fd int) error {
	for {
		buf, err := PFPacketRecv(fd)
		if err != nil {
			log.Errorf("failed to recv from %s", fd)
			return err
		}
		log.WithFields(log.Fields{
			"Topic": "VirtualNetwork",
			"Etag":  f.config.Etag,
		}).Debugf("recv from %s, len: %d", fd, len(buf))
		f.floodCh <- buf
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

func NewVirtualNetwork(config config.VirtualNetwork, global bgpconf.Global) *VirtualNetwork {
	macadvCh := make(chan *Path, 16)
	multicastCh := make(chan *Path, 16)
	floodCh := make(chan []byte, 16)
	netlinkCh := make(chan *netlinkEvent, 16)

	return &VirtualNetwork{
		config:      config,
		global:      global,
		connMap:     map[string]net.Conn{},
		macadvCh:    macadvCh,
		multicastCh: multicastCh,
		floodCh:     floodCh,
		netlinkCh:   netlinkCh,
	}
}
