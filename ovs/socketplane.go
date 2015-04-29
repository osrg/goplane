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
	"encoding/json"
	"fmt"
	"os/exec"
	"net"
)

/* Example output of 'socketplane info'
{
    "0b3c3af55f3f9c78615351aedd6721ad5ba8f8078efb76948a6e398fae1f465d": {
        "connection_details": {
            "gateway": "10.1.0.1",
            "ip": "10.1.0.2",
            "mac": "02:42:0a:01:00:02",
            "name": "ovs07aa099",
            "subnet": "/16"
        },
        "container_id": "0b3c3af55f3f9c78615351aedd6721ad5ba8f8078efb76948a6e398fae1f465d",
        "container_name": "/boring_blackwell",
        "container_pid": "4321",
        "network": "default",
        "ovs_port_id": "ovs07aa099"
    },
    "75620cd5ef52fe14fd7bf22115086e2ee106d7e95d9c73e18b9e0af43bf59803": {
        "connection_details": {
            "gateway": "10.1.0.1",
            "ip": "10.1.0.3",
            "mac": "02:42:0a:01:00:03",
            "name": "ovs312bbbd",
            "subnet": "/16"
        },
        "container_id": "75620cd5ef52fe14fd7bf22115086e2ee106d7e95d9c73e18b9e0af43bf59803",
        "container_name": "/dreamy_shockley",
        "container_pid": "4436",
        "network": "default",
        "ovs_port_id": "ovs312bbbd"
    }
}
*/

/* Example output of 'socketplane network list'
[
    {
        "gateway": "10.1.0.1",
        "id": "default",
        "subnet": "10.1.0.0/16",
        "vlan": 1
    },
    {
        "gateway": "192.168.0.1",
        "id": "testnw",
        "subnet": "192.168.0.0/24",
        "vlan": 2
    }
]
*/

type ContainerInfo struct {
	Ip net.IP
	Mac net.HardwareAddr
	PortName string
	Network string
}

type NetworkInfo struct {
	Subnet string
	Vni int
}

func GetContainersInfo() (map[string]ContainerInfo, map[string]NetworkInfo){
	out1, err := exec.Command("socketplane", "info").Output()

	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	
	out2, err := exec.Command("socketplane", "network", "list").Output()

	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	
	var infoData interface{}
	var listData interface{}
	json.Unmarshal(out1, &infoData)
	json.Unmarshal(out2, &listData)

	containers := make(map[string]ContainerInfo)
	networks := make(map[string]NetworkInfo)
	
	// retrieve necessary information from the result of 'socketplane info' using tons of type assertions :(
	for k, v := range infoData.(map[string]interface{}) {
		ip := net.ParseIP(v.(map[string]interface{})["connection_details"].(map[string]interface{})["ip"].(string))
		mac, _ := net.ParseMAC(v.(map[string]interface{})["connection_details"].(map[string]interface{})["mac"].(string))
		portName := v.(map[string]interface{})["ovs_port_id"].(string)
		network := v.(map[string]interface{})["network"].(string)
		
		containers[k] = ContainerInfo{
			Ip: ip,
			Mac: mac,
			PortName: portName,
			Network: network,
		}
	}

	// retrieve necessary information from the result of 'socketplane network list'
	for _, v := range listData.([]interface{}) {
		subnet := v.(map[string]interface{})["subnet"].(string)
		id := v.(map[string]interface{})["id"].(string)
		vni := int(v.(map[string]interface{})["vlan"].(float64))
			
		networks[id] = NetworkInfo{
			Subnet: subnet,
			Vni: vni,
		}
	}

	return containers, networks
}
