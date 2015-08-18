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

package ovs

import (
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet"
	"github.com/osrg/goplane/config"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"gopkg.in/tomb.v2"
	"io"
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

	res, err := stream.CloseAndRecv()
	if err != nil {
		return err
	}

	if res.Code != api.Error_SUCCESS {
		return fmt.Errorf("error: code: %d, msg: %s\n", res.Code, res.Msg)
	}
	return nil
}

func (d *Dataplane) modRib(path *api.Path) error {
	var nlri bgp.AddrPrefixInterface
	var nexthop string
	for _, attr := range path.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return err
		}

		err = p.DecodeFromBytes(attr)
		if err != nil {
			return err
		}

		if p.GetType() == bgp.BGP_ATTR_TYPE_MP_REACH_NLRI {
			mpreach := p.(*bgp.PathAttributeMpReachNLRI)
			if len(mpreach.Value) != 1 {
				return fmt.Errorf("include only one route in mp_reach_nlri")
			}
			nlri = mpreach.Value[0]
			nexthop = mpreach.Nexthop.String()
			break
		}
	}
	if nlri == nil {
		return fmt.Errorf("no nlri")
	}
	n, ok := nlri.(*bgp.EVPNNLRI)
	if !ok {
		return fmt.Errorf("no evpn nlri")
	}
	addOvsFlows(n, nexthop, d.config.Bgp.Global.GlobalConfig.RouterId.String())
	return nil
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
		Rf:       uint32(bgp.RF_EVPN),
	}

	stream, err := client.MonitorBestChanged(context.Background(), arg)
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

		d.modRibCh <- dst.Paths[0]
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

	path := &api.Path{
		Pattrs: make([][]byte, 0),
	}

	routerId := d.config.Bgp.Global.GlobalConfig.RouterId.String()
	path.Nlri, _ = bgp.NewNLRInfo(uint8(32), routerId).Serialize()
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
		}
	}
}

func (d *Dataplane) AddVirtualNetwork(config config.VirtualNetwork) error {
	log.Warn("ovs dataplane doesn't support dynamic virtualnetwork addition")
	return nil
}

func (d *Dataplane) DeleteVirtualNetwork(config config.VirtualNetwork) error {
	log.Warn("ovs dataplane doesn't support dynamic virtualnetwork deletion")
	return nil
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
