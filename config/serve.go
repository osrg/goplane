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

package config

import (
	"github.com/BurntSushi/toml"
	log "github.com/Sirupsen/logrus"
	bgpconf "github.com/osrg/gobgp/config"
)

type ConfigSet struct {
	Bgp       bgpconf.Bgp
	Policy    bgpconf.RoutingPolicy
	Dataplane Dataplane
}

func ReadConfigfileServe(path string, configCh chan ConfigSet, reloadCh chan bool) {
	for {
		<-reloadCh

		c := Config{}
		md, err := toml.DecodeFile(path, &c)
		if err == nil {
			err = bgpconf.SetDefaultConfigValues(md, &c.Bgp)
		}
		if err != nil {
			log.Fatal("can't read config file ", path, ", ", err)
		}

		p := bgpconf.RoutingPolicy{}
		md, err = toml.DecodeFile(path, &p)
		if err != nil {
			log.Fatal("can't read config file ", path, ", ", err)
		}

		config := ConfigSet{Bgp: c.Bgp, Policy: p, Dataplane: c.Dataplane}
		configCh <- config
	}
}

func UpdateConfig(curC *Dataplane, newC Dataplane) ([]VirtualNetwork, []VirtualNetwork) {
	added := []VirtualNetwork{}
	deleted := []VirtualNetwork{}
	if curC == nil {
		return newC.VirtualNetworkList, deleted
	}
	for _, n := range newC.VirtualNetworkList {
		if inSlice(n, curC.VirtualNetworkList) < 0 {
			added = append(added, n)
		}
	}

	for _, n := range curC.VirtualNetworkList {
		if inSlice(n, newC.VirtualNetworkList) < 0 {
			deleted = append(deleted, n)
		}
	}
	return added, deleted
}

func inSlice(one VirtualNetwork, list []VirtualNetwork) int {
	for idx, vn := range list {
		if vn.RD == one.RD {
			return idx
		}
	}
	return -1
}
