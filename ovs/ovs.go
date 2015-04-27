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
	"github.com/osrg/gobgp/api"
	"fmt"
	"net"
	"strings"
	"os/exec"
)

const (
	ArpResponderFlowTemplate = "priority=%d,dl_type=0x0806,nw_dst=%s,actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:%s,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],load:0x%s->NXM_NX_ARP_SHA[],load:0x%s->NXM_OF_ARP_SPA[],output:in_port"
	RemotePortSelectionFlowTemplate = "priority=%d,dl_dst=%s,actions=mod_vlan_vid:1,output:%s"
	LocalPortSelectionFlowTemplate  = "priority=%d,dl_dst=%s,dl_vlan=1,actions=strip_vlan,output:" // no %s on the tail
)

func Ipv4ToBytesStr(ip net.IP) string {
	ip = ip.To4()
	return fmt.Sprintf("%02x%02x%02x%02x", ip[0], ip[1], ip[2], ip[3])
}

func MacAddressToBytesStr(mac net.HardwareAddr) string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func addOvsArpResponderFlow(n *api.EVPNNlri, nexthop string, myIp string) {
	if nexthop == myIp || nexthop == "0.0.0.0" {
		// Never add an Arp responder flow for a container running on myself
		return
	}

 	ip := net.ParseIP(n.MacIpAdv.IpAddr)
 	mac, _ := net.ParseMAC(n.MacIpAdv.MacAddr)

	fmt.Printf("Add an ArpResponder flow for the container %s on %s\n", ip.String(), nexthop)
	flow := fmt.Sprintf(ArpResponderFlowTemplate, 100, ip, mac, MacAddressToBytesStr(mac), Ipv4ToBytesStr(ip))

	_, err := exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}


func addOvsRemotePortSelectionFlow(n *api.EVPNNlri, nexthop string, myIp string) {
	if nexthop == myIp || nexthop == "0.0.0.0" {
		// Never add a remote port selection flow for a container running on myself
		return
	}

 	ip := net.ParseIP(n.MacIpAdv.IpAddr)
	fmt.Printf("Add a RemotePortSelection flow for the container %s on %s\n", ip.String(), nexthop)

	// retrieve the port number to send packets for the new container
	command := fmt.Sprintf("ovs-ofctl show docker0-ovs | grep %s | sed -e \"s/.*\\([0-9]\\)(.*/\\1/\"", nexthop) // TODO: what happens if a port number has more than 2 digits??
	out, err := exec.Command("sh", "-c", command).Output()

	if err != nil {
		fmt.Println("Error: cannot find the appropriate port to send packets.")
		return
	}

	port := strings.Trim(string(out), "\n")

	// add a flow
 	mac, _ := net.ParseMAC(n.MacIpAdv.MacAddr)
	flow := fmt.Sprintf(RemotePortSelectionFlowTemplate, 50, mac, port)

	_, err = exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}

func addOvsLocalPortSelectionFlow(n *api.EVPNNlri, nexthop string, myIp string) {
	if nexthop != myIp && nexthop != "0.0.0.0" {
		// Never add a local port selection flow for a container running on other peers
		return
	}

 	mac, _ := net.ParseMAC(n.MacIpAdv.MacAddr)
	fmt.Printf("Add a LocalPortSelection flow for the container %s\n", mac.String())

	// retrieve ALL ovs ports connected to containers inside the host.
	// it works because local BUM inside a host is not a big problem.
	// to retrieve the correct one requires the name of the invoked container (e.g. ovs36a00da), which is not in the current grpc schema of gobgpd.
	command := "ovs-ofctl show docker0-ovs | grep -e \"(ovs\" | sed -e \"s/ *\\([0-9]*\\)(.*/\\1/\""
	out, err := exec.Command("sh", "-c", command).Output()

	if err != nil {
		fmt.Println("Error: cannot find local ports")
		return
	}

	// build a flow as a string
	flow := fmt.Sprintf(LocalPortSelectionFlowTemplate, 50, mac)

	for i, c := range out {
		if(c != 10) {
			flow = fmt.Sprintf("%s%c", flow, c)
		} else if(i != len(out) - 1) {
			flow = fmt.Sprintf("%s,", flow)
		} else {
			// do nothing
		}
	}

	// add a flow
	_, err = exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}

// get the IP address of myself (there should be an easier way?)
func getMyIp(iface string) string {
	myIp := ""
	command := fmt.Sprintf("/sbin/ifconfig %s | grep \"inet addr\" | sed \"s/.*inet addr:\\([0-9.]*\\).*/\\1/\"", iface)

	out, err := exec.Command("sh", "-c", command).Output()

	if err != nil {
		fmt.Println(err)
		myIp = "0.0.0.0"
	} else {
		myIp = strings.Trim(string(out), "\n")
	}

	return myIp
}

func addOvsFlows(n *api.EVPNNlri, nexthop string) {
	// TODO: select appropriate iface automatically
	addOvsArpResponderFlow(n, nexthop, getMyIp("eth1"))
	addOvsRemotePortSelectionFlow(n, nexthop, getMyIp("eth1"))
	addOvsLocalPortSelectionFlow(n, nexthop, getMyIp("eth1"))
}
