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
	addOvsFlows(p.Nlri.EvpnNlri, p.Nexthop, d.config.Bgp.Global.RouterId)
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
		Af:       api.AF_EVPN,
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

		if p.Nlri.Af.Equal(api.AF_EVPN) {
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

	routerId := d.config.Bgp.Global.RouterId.String()

	d.advPathCh <- &api.Path{
		Nlri: &api.Nlri{
			Af:     api.AF_IPV4_UC,
			Prefix: routerId + "/32",
		},
	}

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

func NewDataplane(config *config.ConfigSet) *Dataplane {
	modRibCh := make(chan *api.Path, 16)
	advPathCh := make(chan *api.Path, 16)
	return &Dataplane{
		config:    config,
		modRibCh:  modRibCh,
		advPathCh: advPathCh,
	}
}
