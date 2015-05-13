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
	t          tomb.Tomb
	connMap    map[string]net.Conn
	vtepDstMap map[uint32]string
	config     config.VirtualNetwork
	global     bgpconf.Global
	encapCh    chan *api.Path
	evpnCh     chan *api.Path
	floodCh    chan []byte
	pending    []*api.Path
	netlinkCh  chan *netlinkEvent
	client     api.GrpcClient
}

func (n *VirtualNetwork) getPaths(client api.GrpcClient, af *api.AddressFamily) ([]*api.Path, error) {
	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Af:       af,
	}
	stream, err := client.GetRib(context.Background(), arg)
	if err != nil {
		return nil, err
	}
	paths := make([]*api.Path, 0)
	for {
		d, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, err
		}
		paths = append(paths, d.Paths[d.BestPathIdx])
	}
	return paths, nil
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
		SrcAddr: n.global.RouterId,
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

	path := &api.Path{
		Nlri: &api.Nlri{
			Af:     api.AF_ENCAP,
			Prefix: n.global.RouterId.String(),
		},
	}

	subTlv := &api.TunnelEncapSubTLV{
		Type:  api.ENCAP_SUBTLV_TYPE_COLOR,
		Color: n.config.Color,
	}
	tlv := &api.TunnelEncapTLV{
		Type:   api.TUNNEL_TYPE_VXLAN,
		SubTlv: []*api.TunnelEncapSubTLV{subTlv},
	}
	attr := &api.PathAttr{
		Type:        api.BGP_ATTR_TYPE_TUNNEL_ENCAP,
		TunnelEncap: []*api.TunnelEncapTLV{tlv},
	}

	path.Attrs = append(path.Attrs, attr)

	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
		Path:     path,
	}

	log.Debugf("add encap: end point: %s, color: %d", n.global.RouterId, n.config.Color)

	stream, err := n.client.ModPath(context.Background())
	if err != nil {
		return err
	}

	err = stream.Send(arg)
	if err != nil {
		return err
	}
	stream.CloseSend()

	res, err := stream.Recv()
	if err != nil {
		return err
	}

	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s\n", res.Code, res.Msg)
	}

	n.t.Go(n.monitorBest)
	for _, member := range n.config.MemberInterfaces {
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
	n.t.Go(n.monitorNetlink)

	for {
		select {
		case <-n.t.Dying():
			log.Error("dying!!")
			return nil
		case e := <-n.encapCh:
			err = n.modConnMap(e)

			if err != nil {
				log.Errorf("mod conn failed. kill main loop. err: %s", err)
				return err
			}
		case v := <-n.evpnCh:
			err = n.modFdb(v)
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

func extractColor(path *api.Path) uint32 {

	var color uint32

	iterSubTlvs := func(subTlvs []*api.TunnelEncapSubTLV) {
		for _, subTlv := range subTlvs {
			if subTlv.Type == api.ENCAP_SUBTLV_TYPE_COLOR {
				color = subTlv.Color
				break
			}
		}
	}

	iterTlvs := func(tlvs []*api.TunnelEncapTLV) {
		for _, tlv := range tlvs {
			if tlv.Type == api.TUNNEL_TYPE_VXLAN {
				iterSubTlvs(tlv.SubTlv)
				break
			}
		}
	}

	func(attrs []*api.PathAttr) {
		for _, attr := range attrs {
			if attr.Type == api.BGP_ATTR_TYPE_TUNNEL_ENCAP {
				iterTlvs(attr.TunnelEncap)
				break
			}
		}
	}(path.Attrs)

	return color
}

func (f *VirtualNetwork) modConnMap(path *api.Path) error {
	addr := path.Nlri.Prefix
	color := extractColor(path)

	if path.Nexthop == "0.0.0.0" {
		return nil
	}

	log.Debugf("mod cannection map: nh %s, vtep addr %s color %d withdraw %t", path.Nexthop, path.Nlri.Prefix, color, path.IsWithdraw)

	if path.IsWithdraw {
		_, ok := f.connMap[addr]
		if !ok {
			return fmt.Errorf("can't find %s conn", addr)
		}

		_, ok = f.vtepDstMap[color]
		if !ok {
			return fmt.Errorf("can't find %s vtep dst", path.Nlri.Nexthop)
		}

		if f.vtepDstMap[color] != addr {
			log.Debugf("already refreshed")
			return nil
		}

		f.connMap[addr].Close()

		delete(f.connMap, addr)

		delete(f.vtepDstMap, color)
	} else {
		_, ok := f.connMap[addr]
		if ok {
			log.Debugf("refresh. close connection to %s", addr)
			f.connMap[addr].Close()
			delete(f.connMap, addr)
			delete(f.vtepDstMap, color)
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

		if color > 0 {
			_, ok = f.vtepDstMap[color]
			if ok {
				log.Debugf("refresh vtep dst %s", addr)
			}
			f.vtepDstMap[color] = addr
			for _, p := range f.pending {
				f.evpnCh <- p
			}
			f.pending = []*api.Path{}
		}

	}
	log.Debugf("connMap: %s", f.connMap)
	log.Debugf("vtepDstMap: %s", f.vtepDstMap)
	return nil
}

func (f *VirtualNetwork) modFdb(path *api.Path) error {

	if path.Nexthop == "0.0.0.0" {
		return nil
	}

	color := extractColor(path)

	log.Debugf("modFdb new path, prefix: %s, nexthop: %s, color: %d, withdraw: %t", path.Nlri.Prefix, path.Nexthop, color, path.IsWithdraw)

	var mac net.HardwareAddr
	var ip net.IP

	switch path.Nlri.EvpnNlri.Type {
	case api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
		mac, _ = net.ParseMAC(path.Nlri.EvpnNlri.MacIpAdv.MacAddr)

		_, ok := f.vtepDstMap[color]
		if !ok {
			log.Warnf("no valid vtep dst for color: %d, pending len: %d", color, len(f.pending))
			f.pending = append(f.pending, path)
			return nil
		}
		ip = net.ParseIP(f.vtepDstMap[color])
	default:
		return fmt.Errorf("invalid evpn nlri type: %s", path.Nlri.EvpnNlri.Type)
	}

	link, err := netlink.LinkByName(f.config.VtepInterface)
	if err != nil {
		log.Debugf("failed lookup link by name: %s", f.config.VtepInterface)
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
		log.Debugf("del fdb: %s, %s", n, err)
	} else {
		err = netlink.NeighAppend(n)
		log.Debugf("add fdb: %s, %s", n, err)
	}
	return nil
}

func (f *VirtualNetwork) flood(pkt []byte) error {
	vxlanHeader := NewVXLAN(f.config.VNI)
	b := vxlanHeader.Serialize()
	b = append(b, pkt...)

	for _, c := range f.connMap {
		cnt, err := c.Write(b)
		log.Debugf("send to %s: cnt:%d, err:%s", c.RemoteAddr(), cnt, err)
	}

	return nil
}

func (f *VirtualNetwork) modPath(n *netlinkEvent) error {
	path := &api.Path{
		Nlri: &api.Nlri{
			Af: api.AF_EVPN,
			EvpnNlri: &api.EVPNNlri{
				Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
				MacIpAdv: &api.EvpnMacIpAdvertisement{
					MacAddr: n.mac.String(),
					IpAddr:  "0.0.0.0",
				},
			},
		},
	}

	subTlv := &api.TunnelEncapSubTLV{
		Type:  api.ENCAP_SUBTLV_TYPE_COLOR,
		Color: uint32(f.config.Color),
	}
	tlv := &api.TunnelEncapTLV{
		Type:   api.TUNNEL_TYPE_VXLAN,
		SubTlv: []*api.TunnelEncapSubTLV{subTlv},
	}
	attr := &api.PathAttr{
		Type:        api.BGP_ATTR_TYPE_TUNNEL_ENCAP,
		TunnelEncap: []*api.TunnelEncapTLV{tlv},
	}

	path.Attrs = append(path.Attrs, attr)

	path.IsWithdraw = n.isWithdraw
	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
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

	res, err := stream.Recv()
	if err != nil {
		return err
	}
	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s\n", res.Code, res.Msg)
	}
	return nil

}

func (f *VirtualNetwork) monitorBest() error {

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGrpcClient(conn)

	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Af:       api.AF_ENCAP,
	}
	err = func() error {
		stream, err := client.GetRib(context.Background(), arg)
		if err != nil {
			return err
		}
		for {
			d, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			f.encapCh <- d.Paths[d.BestPathIdx]
		}
		return nil
	}()
	if err != nil {
		return err
	}

	arg = &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Af:       api.AF_EVPN,
	}
	err = func() error {
		stream, err := client.GetRib(context.Background(), arg)
		if err != nil {
			return err
		}
		for {
			d, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			f.evpnCh <- d.Paths[d.BestPathIdx]
		}
		return nil
	}()
	if err != nil {
		return err
	}

	stream, err := client.MonitorBestChanged(context.Background(), arg)
	if err != nil {
		return err
	}

	for {
		d, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if d.Nlri.Af.Equal(api.AF_ENCAP) {
			f.encapCh <- d
		} else if d.Nlri.Af.Equal(api.AF_EVPN) {
			f.evpnCh <- d
		} else if d.Nlri.Af.Equal(api.AF_IPV4_UC) || d.Nlri.Af.Equal(api.AF_IPV6_UC) {
			paths, err := f.getPaths(client, api.AF_ENCAP)
			if err != nil {
				log.Fatal("failed to get encap pash", err)
			}
			for _, p := range paths {
				f.encapCh <- p
			}
		}
	}
	return nil
}

func (f *VirtualNetwork) sniffPkt(fd int) error {
	for {
		buf, err := PFPacketRecv(fd)
		if err != nil {
			log.Errorf("failed to recv from %s", fd)
			return err
		}
		log.Debugf("recv from %s, len: %d", fd, len(buf))
		f.floodCh <- buf
	}
}

func (f *VirtualNetwork) monitorNetlink() error {
	s, err := nl.Subscribe(syscall.NETLINK_ROUTE, uint(RTMGRP_NEIGH), uint(RTMGRP_LINK), uint(RTMGRP_NOTIFY))
	if err != nil {
		return err
	}

	idxs := make([]int, 0, len(f.config.MemberInterfaces))
	for _, member := range f.config.MemberInterfaces {
		link, err := netlink.LinkByName(member)
		if err != nil {
			log.Errorf("failed to get link %s", member)
			return err
		}
		log.Debugf("monitoring: %s, index: %d", link.Attrs().Name, link.Attrs().Index)
		idxs = append(idxs, link.Attrs().Index)
	}

	for {
		msgs, err := s.Receive()
		if err != nil {
			return err
		}

		for _, msg := range msgs {
			t := RTM_TYPE(msg.Header.Type)
			//			log.Debugf("Len: %d, Type: %s, Flags: %d, Seq: %d, Pid: %d", msg.Header.Len, t, msg.Header.Flags, msg.Header.Seq, msg.Header.Pid)
			switch t {
			case RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH:
				n, _ := netlink.NeighDeserialize(msg.Data)
				for _, idx := range idxs {
					if n.LinkIndex == idx {
						log.Debugf("mac: %s, ip: %s, index: %d, family: %s, state: %s, type: %s, flags: %s", n.HardwareAddr, n.IP, n.LinkIndex, NDA_TYPE(n.Family), NUD_TYPE(n.State), RTM_TYPE(n.Type), NTF_TYPE(n.Flags))
						log.Debugf("from monitored interface")
						// if we already have, proxy arp
						// how to write back to interfaces ?
						// write to bridge does work?
						// do experiments
						// get vxlan bridge
						f.netlinkCh <- &netlinkEvent{n.HardwareAddr, n.IP, false}
					}
				}
			}
		}
	}
}

func NewVirtualNetwork(config config.VirtualNetwork, global bgpconf.Global) *VirtualNetwork {
	encapCh := make(chan *api.Path, 16)
	evpnCh := make(chan *api.Path, 16)
	floodCh := make(chan []byte, 16)
	netlinkCh := make(chan *netlinkEvent, 16)

	return &VirtualNetwork{
		config:     config,
		global:     global,
		connMap:    map[string]net.Conn{},
		vtepDstMap: map[uint32]string{},
		encapCh:    encapCh,
		evpnCh:     evpnCh,
		floodCh:    floodCh,
		netlinkCh:  netlinkCh,
	}
}
