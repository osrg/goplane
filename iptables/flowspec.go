// Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

package iptables

import (
	"fmt"
	"io"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	api "github.com/osrg/gobgp/api"
	"github.com/osrg/gobgp/packet/bgp"
	"github.com/osrg/goplane/config"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
)

type Path struct {
	Nlri       bgp.AddrPrefixInterface
	PathAttrs  []bgp.PathAttributeInterface
	Best       bool
	IsWithdraw bool
}

func ApiStruct2Path(p *api.Path) ([]*Path, error) {
	nlris := make([]bgp.AddrPrefixInterface, 0, 1)
	pattr := make([]bgp.PathAttributeInterface, 0, len(p.Pattrs))
	for _, attr := range p.Pattrs {
		p, err := bgp.GetPathAttribute(attr)
		if err != nil {
			return nil, err
		}

		err = p.DecodeFromBytes(attr)
		if err != nil {
			return nil, err
		}

		switch p.GetType() {
		case bgp.BGP_ATTR_TYPE_MP_REACH_NLRI:
			mpreach := p.(*bgp.PathAttributeMpReachNLRI)
			for _, nlri := range mpreach.Value {
				nlris = append(nlris, nlri)
			}
			continue
		}
		pattr = append(pattr, p)
	}

	paths := make([]*Path, 0, len(nlris))
	for _, nlri := range nlris {
		paths = append(paths, &Path{
			Nlri:       nlri,
			PathAttrs:  pattr,
			Best:       p.Best,
			IsWithdraw: p.IsWithdraw,
		})
	}
	return paths, nil
}

func FlowSpec2IptablesRule(nlri []bgp.FlowSpecComponentInterface, attr []bgp.PathAttributeInterface) ([]string, error) {
	spec := make([]string, 0, len(nlri))
	m := make(map[bgp.BGPFlowSpecType]bgp.FlowSpecComponentInterface)
	for _, v := range nlri {
		m[v.Type()] = v
	}

	if v, ok := m[bgp.FLOW_SPEC_TYPE_DST_PREFIX]; ok {
		prefix := v.(*bgp.FlowSpecDestinationPrefix).Prefix.String()
		spec = append(spec, "-d")
		spec = append(spec, prefix)
	}

	if v, ok := m[bgp.FLOW_SPEC_TYPE_SRC_PREFIX]; ok {
		prefix := v.(*bgp.FlowSpecSourcePrefix).Prefix.String()
		spec = append(spec, "-s")
		spec = append(spec, prefix)
	}

	if v, ok := m[bgp.FLOW_SPEC_TYPE_IP_PROTO]; ok {
		if len(v.(*bgp.FlowSpecComponent).Items) != 1 {
			return nil, fmt.Errorf("ip proto len must be 1")
		}
		proto := bgp.Protocol(v.(*bgp.FlowSpecComponent).Items[0].Value).String()
		spec = append(spec, "-p")
		spec = append(spec, proto)
	}

	spec = append(spec, "-j")
	spec = append(spec, "DROP")

	return spec, nil
}

type FlowspecAgent struct {
	config   config.Iptables
	grpcHost string
}

func (a *FlowspecAgent) Serve() error {
	ipt, err := iptables.New()
	if err != nil {
		log.Fatalf("%s", err)
	}

	table := "filter"
	chain := "FLOWSPEC"
	if a.config.Chain != "" {
		chain = a.config.Chain
	}

	if err := ipt.ClearChain(table, chain); err != nil {
		return fmt.Errorf("failed to clear chain: %s", err)
	}
	log.Infof("cleared iptables chain: %s, table: %s", chain, table)

	ch := make(chan *Path, 16)

	go func() {

		timeout := grpc.WithTimeout(time.Second)
		conn, err := grpc.Dial(a.grpcHost, timeout, grpc.WithBlock(), grpc.WithInsecure())
		if err != nil {
			log.Fatalf("%s", err)
		}

		client := api.NewGobgpApiClient(conn)
		{
			arg := &api.Table{
				Type:   api.Resource_GLOBAL,
				Family: uint32(bgp.RF_FS_IPv4_UC),
			}

			rsp, err := client.GetRib(context.Background(), &api.GetRibRequest{
				Table: arg,
			})
			if err != nil {
				log.Fatalf("%s", err)
			}
			rib := rsp.Table
			for _, d := range rib.Destinations {
				for _, p := range d.Paths {
					if p.Best {
						if paths, err := ApiStruct2Path(p); err != nil {
							log.Fatalf("%s", err)
						} else {
							for _, path := range paths {
								ch <- path
							}
						}
					}
				}
			}
		}

		arg := &api.Table{
			Type:   api.Resource_GLOBAL,
			Family: uint32(bgp.RF_FS_IPv4_UC),
		}

		stream, err := client.MonitorRib(context.Background(), arg)
		if err != nil {
			log.Fatalf("%s", err)
		}

		for {
			d, err := stream.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatalf("%s", err)
			}
			paths, err := ApiStruct2Path(d.Paths[0])
			if err != nil {
				log.Fatalf("%s", err)
			}
			for _, p := range paths {
				ch <- p
			}
		}
	}()

	list := make([]*bgp.FlowSpecNLRI, 0, 16)

	for p := range ch {
		nlri := &p.Nlri.(*bgp.FlowSpecIPv4Unicast).FlowSpecNLRI

		spec, err := FlowSpec2IptablesRule(nlri.Value, p.PathAttrs)
		if err != nil {
			log.Warnf("failed to convert flowspec spec to iptables rule: %s", err)
			continue
		}

		idx := 0
		var q *bgp.FlowSpecNLRI
		if p.IsWithdraw {
			found := false
			for idx, q = range list {
				result, err := bgp.CompareFlowSpecNLRI(nlri, q)
				if err != nil {
					log.Fatalf("%s", err)
				}
				if result == 0 {
					found = true
					break
				}
			}
			if !found {
				log.Warnf("not found: %s", nlri)
			}
			list = append(list[:idx], list[idx+1:]...)
			if err := ipt.Delete(table, chain, spec...); err != nil {
				log.Errorf("failed to delete: %s", err)
			} else {
				log.Debugf("delete iptables rule: %v", spec)
			}
		} else {
			found := false
			for idx, q = range list {
				result, err := bgp.CompareFlowSpecNLRI(nlri, q)
				if err != nil {
					log.Fatalf("%s", err)
				}
				if result > 0 {
					found = true
					list = append(list[:idx], append([]*bgp.FlowSpecNLRI{nlri}, list[idx:]...)...)
					idx += 1
					break
				} else if result == 0 {
					found = true
					break
				}
			}

			if !found {
				list = append(list, nlri)
				idx = len(list)
			}

			if y, _ := ipt.Exists(table, chain, spec...); y {
				log.Warnf("already exists: %v", spec)
			} else if err := ipt.Insert(table, chain, idx, spec...); err != nil {
				log.Errorf("failed to insert: %s", err)
			} else {
				log.Debugf("insert iptables rule: %v", spec)
			}
		}
	}
	return nil
}

func NewFlowspecAgent(grpcHost string, c config.Iptables) *FlowspecAgent {
	return &FlowspecAgent{
		config:   c,
		grpcHost: grpcHost,
	}
}
