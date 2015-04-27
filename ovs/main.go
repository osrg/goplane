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

package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/api"
	"google.golang.org/grpc"
	"golang.org/x/net/context"
	"io"
	"os"
	"sync"
	"time"
)

var globalOpts struct {
	Host     string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port     int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
}

func main() {
	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.Parse()

	var client api.GrpcClient

	g := &sync.WaitGroup{}
	
	timeout := grpc.WithTimeout(time.Second)
	conn, err := grpc.Dial(fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port), timeout)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer conn.Close()
	client = api.NewGrpcClient(conn)
	
	
	g.Add(1)
	go func() error {
		arg := &api.Arguments{
			Resource: api.Resource_GLOBAL,
			Af:       api.AF_EVPN,
		}
		stream, err := client.MonitorBestChanged(context.Background(), arg)
		if err != nil {
			g.Done()
			return err
		}
		
		for {
			d, e := stream.Recv()
			if e == io.EOF {
				break
			} else if e != nil {
				return e
			}

			if d.Nlri.Af.Equal(api.AF_EVPN){
				switch d.Nlri.EvpnNlri.Type {
				case api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:
					addOvsFlows(d.Nlri.EvpnNlri, d.Nexthop)
				}
			}
		}
		g.Done()
		return nil
	}()

	g.Wait()
}
