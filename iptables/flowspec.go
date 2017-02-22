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

	log "github.com/Sirupsen/logrus"
	"github.com/coreos/go-iptables/iptables"
	"github.com/osrg/gobgp/client"
	"github.com/osrg/gobgp/packet/bgp"
	bgptable "github.com/osrg/gobgp/table"
	"github.com/osrg/goplane/config"
)

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

	ch := make(chan *bgptable.Path, 16)

	go func() {
		client, err := client.New(a.grpcHost)
		if err != nil {
			log.Fatalf("%s", err)
		}

		watcher, err := client.MonitorRIB(bgp.RF_FS_IPv4_UC, true)
		if err != nil {
			log.Fatalf("%s", err)
		}

		for {
			d, err := watcher.Recv()
			if err == io.EOF {
				break
			} else if err != nil {
				log.Fatalf("%s", err)
			}
			for _, p := range d.GetAllKnownPathList() {
				ch <- p
			}
		}
	}()

	list := make([]*bgp.FlowSpecNLRI, 0, 16)

	for p := range ch {
		nlri := &p.GetNlri().(*bgp.FlowSpecIPv4Unicast).FlowSpecNLRI

		spec, err := FlowSpec2IptablesRule(nlri.Value, p.GetPathAttrs())
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
