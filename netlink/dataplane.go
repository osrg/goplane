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
	"github.com/hogecamp/goplane/config"
	"github.com/osrg/gobgp/api"
	"github.com/vishvananda/netlink"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
	"io"
	"net"
	"time"
)

type Dataplane struct {
	t         tomb.Tomb
	config    *config.ConfigSet
	client    api.GrpcClient
	modRibCh  chan *api.Path
	advPathCh chan *api.Path
}

func (d *Dataplane) advPath(p *api.Path) error {
	arg := &api.ModPathArguments{
		Resource: api.Resource_GLOBAL,
		Path:     p,
	}

	stream, err := d.client.ModPath(context.Background())
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

func (d *Dataplane) modRib(p *api.Path) error {
	if p.Nexthop == "0.0.0.0" {
		return nil
	}

	via := net.ParseIP(p.Nexthop)
	routes, _ := netlink.RouteGet(via)
	if len(routes) == 0 {
		return fmt.Errorf("no route to nexthop: %s", p.Nexthop)
	}
	net, _ := netlink.ParseIPNet(p.Nlri.Prefix)
	route := &netlink.Route{
		LinkIndex: routes[0].LinkIndex,
		Dst:       net,
		Src:       d.config.Bgp.Global.RouterId,
	}
	return netlink.RouteAdd(route)
}

func (d *Dataplane) monitorBest() error {

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	client := api.NewGrpcClient(conn)

	arg := &api.Arguments{
		Resource: api.Resource_GLOBAL,
		Af:       api.AF_IPV4_UC,
	}
	err = func() error {
		stream, err := client.GetRib(context.Background(), arg)
		if err != nil {
			return err
		}
		for {
			dst, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				return err
			}
			d.modRibCh <- dst.Paths[dst.BestPathIdx]
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
		p, err := stream.Recv()
		if err == io.EOF {
			break
		} else if err != nil {
			return err
		}

		if p.Nlri.Af.Equal(api.AF_IPV4_UC) || p.Nlri.Af.Equal(api.AF_IPV6_UC) {
			d.modRibCh <- p
		}
	}
	return nil
}

func (d *Dataplane) Serve() error {

	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial("127.0.0.1:8080", timeout)
	if err != nil {
		log.Fatal(err)
	}
	d.client = api.NewGrpcClient(conn)

	lo, err := netlink.LinkByName("lo")
	if err != nil {
		return fmt.Errorf("failed to get lo")
	}

	addrList, err := netlink.AddrList(lo, netlink.FAMILY_ALL)
	if err != nil {
		return fmt.Errorf("failed to get addr list of lo")
	}

	routerId := d.config.Bgp.Global.RouterId.String()

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

	d.advPathCh <- &api.Path{
		Nlri: &api.Nlri{
			Af:     api.AF_IPV4_UC,
			Prefix: routerId + "/32",
		},
	}

	d.t.Go(d.monitorBest)

	for _, c := range d.config.Dataplane.VirtualNetworkList {
		vn := NewVirtualNetwork(c, d.config.Bgp.Global)
		d.t.Go(vn.Serve)
	}

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
		}
	}
}

func NewDataplane(config *config.ConfigSet) *Dataplane {
	modRibCh := make(chan *api.Path, 16)
	advPathCh := make(chan *api.Path, 16)
	return &Dataplane{
		config:    config,
		modRibCh:  modRibCh,
		advPathCh: advPathCh,
	}
}
