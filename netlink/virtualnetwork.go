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
	t           tomb.Tomb
	connMap     map[string]net.Conn
	config      config.VirtualNetwork
	global      bgpconf.Global
	multicastCh chan *api.Path
	macadvCh    chan *api.Path
	floodCh     chan []byte
	pending     []*api.Path
	netlinkCh   chan *netlinkEvent
	client      api.GrpcClient
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

	n.sendMulticast()

	n.t.Go(n.monitorBest)
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
	n.t.Go(n.monitorNetlink)

	for {
		select {
		case <-n.t.Dying():
			log.Error("dying!!")
			return nil
		case e := <-n.multicastCh:
			if e.Nlri.EvpnNlri.MulticastEtag.Etag != n.config.Etag {
				continue
			}
			err = n.modConnMap(e)

			if err != nil {
				log.Errorf("mod conn failed. kill main loop. err: %s", err)
				return err
			}
		case v := <-n.macadvCh:
			if v.Nlri.EvpnNlri.MacIpAdv.Etag != n.config.Etag {
				continue
			}
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

func (f *VirtualNetwork) modConnMap(path *api.Path) error {
	addr := path.Nexthop
	etag := path.Nlri.EvpnNlri.MulticastEtag.Etag

	if path.Nexthop == "0.0.0.0" {
		return nil
	}

	log.Debugf("mod cannection map: nh %s, vtep addr %s etag %d withdraw %t", path.Nexthop, path.Nlri.Prefix, etag, path.IsWithdraw)

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

func (f *VirtualNetwork) modFdb(path *api.Path) error {

	if path.Nexthop == "0.0.0.0" {
		return nil
	}

	log.WithFields(log.Fields{
		"Topic": "VirtualNetwork",
		"Etag":  f.config.Etag,
	}).Debugf("modFdb new path, prefix: %s, nexthop: %s, withdraw: %t", path.Nlri.Prefix, path.Nexthop, path.IsWithdraw)

	var mac net.HardwareAddr
	var ip net.IP

	switch path.Nlri.EvpnNlri.Type {
	case api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
		mac, _ = net.ParseMAC(path.Nlri.EvpnNlri.MacIpAdv.MacAddr)
		ip = net.ParseIP(path.Nexthop)
	default:
		return fmt.Errorf("invalid evpn nlri type: %s", path.Nlri.EvpnNlri.Type)
	}

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

func (n *VirtualNetwork) sendMulticast() error {
	path := &api.Path{
		Nlri: &api.Nlri{
			Af: api.AF_EVPN,
			EvpnNlri: &api.EVPNNlri{
				Type: api.EVPN_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG,
				MulticastEtag: &api.EvpnInclusiveMulticastEthernetTag{
					Etag: n.config.Etag,
				},
			},
		},
	}

	attr := &api.PathAttr{
		Type: api.BGP_ATTR_TYPE_PMSI_TUNNEL,
		PmsiTunnel: &api.PmsiTunnel{
			Type:  api.PMSI_TUNNEL_TYPE_INGRESS_REPL,
			Label: n.config.VNI,
		},
	}

	path.Attrs = append(path.Attrs, attr)

	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
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
		Nlri: &api.Nlri{
			Af: api.AF_EVPN,
			EvpnNlri: &api.EVPNNlri{
				Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
				MacIpAdv: &api.EvpnMacIpAdvertisement{
					MacAddr: n.mac.String(),
					IpAddr:  "0.0.0.0",
					Etag:    uint32(f.config.Etag),
					Labels:  []uint32{f.config.VNI},
				},
			},
		},
	}

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

	res, err := stream.CloseAndRecv()
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
			bestpath := d.Paths[d.BestPathIdx]
			switch bestpath.Nlri.EvpnNlri.Type {
			case api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
				f.macadvCh <- bestpath
			case api.EVPN_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG:
				f.multicastCh <- bestpath
			}
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

		if d.Nlri.Af.Equal(api.AF_EVPN) {
			switch d.Nlri.EvpnNlri.Type {
			case api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
				f.macadvCh <- d
			case api.EVPN_TYPE_INCLUSIVE_MULTICAST_ETHERNET_TAG:
				f.multicastCh <- d
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
			//			log.Debugf("Len: %d, Type: %s, Flags: %d, Seq: %d, Pid: %d", msg.Header.Len, t, msg.Header.Flags, msg.Header.Seq, msg.Header.Pid)
			switch t {
			case RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH:
				n, _ := netlink.NeighDeserialize(msg.Data)
				for _, idx := range idxs {
					if n.LinkIndex == idx {
						log.WithFields(log.Fields{
							"Topic": "VirtualNetwork",
							"Etag":  f.config.Etag,
						}).Debugf("mac: %s, ip: %s, index: %d, family: %s, state: %s, type: %s, flags: %s", n.HardwareAddr, n.IP, n.LinkIndex, NDA_TYPE(n.Family), NUD_TYPE(n.State), RTM_TYPE(n.Type), NTF_TYPE(n.Flags))
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
	macadvCh := make(chan *api.Path, 16)
	multicastCh := make(chan *api.Path, 16)
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
