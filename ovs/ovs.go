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
	"github.com/osrg/gobgp/packet"
	"net"
	"os/exec"
	"strconv"
	"strings"
)

const (
	PushVniFlowTemplate             = "priority=%d,in_port=%d,actions=mod_vlan_vid:%d,resubmit(,1)"
	ArpResponderFlowTemplate        = "table=1,priority=%d,dl_type=0x0806,dl_vlan=%d,nw_dst=%s,actions=move:NXM_OF_ETH_SRC[]->NXM_OF_ETH_DST[],mod_dl_src:%s,load:0x2->NXM_OF_ARP_OP[],move:NXM_NX_ARP_SHA[]->NXM_NX_ARP_THA[],move:NXM_OF_ARP_SPA[]->NXM_OF_ARP_TPA[],load:0x%s->NXM_NX_ARP_SHA[],load:0x%s->NXM_OF_ARP_SPA[],strip_vlan,output:in_port"
	RemotePortSelectionFlowTemplate = "table=1,priority=%d,dl_dst=%s,dl_vlan=%d,actions=output:%s"
	LocalPortSelectionFlowTemplate  = "priority=%d,dl_dst=%s,dl_vlan=%d,actions=strip_vlan,output:%s"
)

func Ipv4ToBytesStr(ip net.IP) string {
	ip = ip.To4()
	return fmt.Sprintf("%02x%02x%02x%02x", ip[0], ip[1], ip[2], ip[3])
}

func MacAddressToBytesStr(mac net.HardwareAddr) string {
	return fmt.Sprintf("%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func createPortName(ip net.IP, vni uint32) string {
	// {ip:  "10.1.2.3", vni: "5"}  -> "o0050a010203"
	// For the specification of naming ports, see the comments of dockernw.sh
	return fmt.Sprintf("o%03x%s", vni, Ipv4ToBytesStr(ip))
}

func getLocalPortNumber(portName string) int {
	command := "ovs-ofctl show docker0-ovs | grep -e \"" + portName + "\" | sed -e \"s/ *\\([0-9]*\\)(.*/\\1/\""
	out, err := exec.Command("sh", "-c", command).Output()

	if err != nil {
		fmt.Printf("Error: cannot find the local port %s\n", portName)
		return 0
	}

	ret, err := strconv.Atoi(strings.Trim(string(out), "\n"))

	if err != nil {
		fmt.Println(err)
		return 0
	}

	return ret
}

func addOvsVniPushFlow(n *bgp.EVPNNLRI, nexthop string, myIp string) {
	if nexthop != myIp && nexthop != "0.0.0.0" {
		// Never add a vni push flow for a container running on other peers
		return
	}
	if n.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return
	}

	macIpAdv := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)

	vni := macIpAdv.Labels[0]
	mac := macIpAdv.MacAddress
	ip := macIpAdv.IPAddress
	fmt.Printf("Add a VniPush flow for the container %s (vlan: %d)\n", mac.String(), vni)

	portName := createPortName(ip, vni)
	port := getLocalPortNumber(portName)

	flow := fmt.Sprintf(PushVniFlowTemplate, 100, port, vni)

	_, err := exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}

func addOvsArpResponderFlow(n *bgp.EVPNNLRI, nexthop string, myIp string) {
	if nexthop == myIp || nexthop == "0.0.0.0" {
		// Never add an Arp responder flow for a container running on myself
		return
	}
	if n.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return
	}
	macIpAdv := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)

	vni := macIpAdv.Labels[0]
	mac := macIpAdv.MacAddress
	ip := macIpAdv.IPAddress

	fmt.Printf("Add an ArpResponder flow for the container %s on %s\n", ip.String(), nexthop)
	flow := fmt.Sprintf(ArpResponderFlowTemplate, 100, vni, ip, mac, MacAddressToBytesStr(mac), Ipv4ToBytesStr(ip))

	_, err := exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}

func addOvsRemotePortSelectionFlow(n *bgp.EVPNNLRI, nexthop string, myIp string) {
	if nexthop == myIp || nexthop == "0.0.0.0" {
		// Never add a remote port selection flow for a container running on myself
		return
	}
	if n.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return
	}
	macIpAdv := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)

	vni := macIpAdv.Labels[0]
	mac := macIpAdv.MacAddress
	ip := macIpAdv.IPAddress

	fmt.Printf("Add a RemotePortSelection flow for the container %s (vlan: %d) on %s\n", ip.String(), vni, nexthop)

	// retrieve the port number to send packets for the new container
	command := fmt.Sprintf("ovs-ofctl show docker0-ovs | grep %s | sed -e \"s/[^0-9]*\\([0-9]*\\)(.*/\\1/\"", nexthop)

	out, err := exec.Command("sh", "-c", command).Output()

	if err != nil {
		fmt.Println("Error: cannot find the appropriate port to send packets.")
		return
	}

	port := strings.Trim(string(out), "\n")

	// add a flow
	flow := fmt.Sprintf(RemotePortSelectionFlowTemplate, 50, mac, vni, port)

	_, err = exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}

func addOvsLocalPortSelectionFlow(n *bgp.EVPNNLRI, nexthop string, myIp string) {
	if nexthop != myIp && nexthop != "0.0.0.0" {
		// Never add a local port selection flow for a container running on other peers
		return
	}

	if n.RouteType != bgp.EVPN_ROUTE_TYPE_MAC_IP_ADVERTISEMENT {
		return
	}
	macIpAdv := n.RouteTypeData.(*bgp.EVPNMacIPAdvertisementRoute)

	vni := macIpAdv.Labels[0]
	mac := macIpAdv.MacAddress
	ip := macIpAdv.IPAddress

	fmt.Printf("Add a LocalPortSelection flow for the container %s (vlan: %d)\n", mac.String(), vni)

	portName := createPortName(ip, vni)
	command := "ovs-ofctl show docker0-ovs | grep -e \"" + portName + "\" | sed -e \"s/ *\\([0-9]*\\)(.*/\\1/\""
	out, err := exec.Command("sh", "-c", command).Output()

	if err != nil {
		fmt.Printf("Error: cannot find the local port %s\n", portName)
		return
	}

	port := string(out)

	// build a flow as a string
	flow := fmt.Sprintf(LocalPortSelectionFlowTemplate, 50, mac, vni, port)

	// add a flow
	_, err = exec.Command("ovs-ofctl", "add-flow", "docker0-ovs", flow).Output()

	if err != nil {
		fmt.Println(err)
	}
}

func addOvsFlows(n *bgp.EVPNNLRI, nexthop, routerId string) {
	// TODO: select appropriate iface automatically
	addOvsVniPushFlow(n, nexthop, routerId)
	addOvsArpResponderFlow(n, nexthop, routerId)
	addOvsRemotePortSelectionFlow(n, nexthop, routerId)
	addOvsLocalPortSelectionFlow(n, nexthop, routerId)
}
