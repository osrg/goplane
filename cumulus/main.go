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
	"code.google.com/p/gopacket"
	"code.google.com/p/gopacket/layers"
	"fmt"
	log "github.com/Sirupsen/logrus"
	"github.com/jessevdk/go-flags"
	"github.com/osrg/gobgp/api"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"io"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
)

var globalOpts struct {
	Host     string `short:"u" long:"url" description:"specifying an url" default:"127.0.0.1"`
	Port     int    `short:"p" long:"port" description:"specifying a port" default:"8080"`
	DevName  string `short:"d" long:"dev" description:"specifying an url"`
	VtepName string `long:"vtep-name"`
	VtepDst  string `long:"vtep-dst" description:"specifying an url"`
	VtepPort int    `long:"vtep-port" default:"8472"`
	VNI      int    `long:"vni" default:"10"`
	Monitor  bool   `long:"monitor" default:"false"`
}

func main() {

	parser := flags.NewParser(&globalOpts, flags.Default)
	parser.Parse()

	if globalOpts.DevName == "" {
		fmt.Println("specify input intf by -d or --dev")
		os.Exit(1)
	}

	if !globalOpts.Monitor && globalOpts.VtepName == "" {
		fmt.Println("specify vtep name by --vtep-name")
		os.Exit(1)
	}

	if !globalOpts.Monitor && globalOpts.VtepDst == "" {
		fmt.Println("specify dst vtep address by --vtep-dst")
		os.Exit(1)
	}

	var client api.GrpcClient

	g := &sync.WaitGroup{}

	if !globalOpts.Monitor {

		timeout := grpc.WithTimeout(time.Second)
		conn, err := grpc.Dial(fmt.Sprintf("%s:%d", globalOpts.Host, globalOpts.Port), timeout)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		defer conn.Close()
		client = api.NewGrpcClient(conn)

		apiCh := make(chan *api.ModPathArguments)

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
				fmt.Println("recved path:", d)
				if d.Nlri.Af.Equal(api.AF_EVPN) && d.Nexthop != "0.0.0.0" {
					switch d.Nlri.EvpnNlri.Type {
					case api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT:

						link, err := netlink.LinkByName(globalOpts.VtepName)
						if err != nil {
							fmt.Println(err)
							os.Exit(1)
						}
						fmt.Printf("name: %s, index: %d\n", link.Attrs().Name, link.Attrs().Index)

						mac, _ := net.ParseMAC(d.Nlri.EvpnNlri.MacIpAdv.MacAddr)
						ip := net.ParseIP(d.Nexthop)

						n := &netlink.Neigh{
							LinkIndex:    link.Attrs().Index,
							Family:       int(NDA_VNI),
							State:        192,
							Type:         1,
							Flags:        int(NTF_SELF),
							IP:           ip,
							HardwareAddr: mac,
						}

						if d.IsWithdraw {
							err = netlink.NeighDel(n)
							fmt.Println("NeighDel error:", err)
						} else {
							err = netlink.NeighAppend(n)
							fmt.Println("NeighAppend error:", err)
						}

					}
				}
			}
			g.Done()
			return nil
		}()

		g.Add(1)
		go func() error {
			stream, err := client.ModPath(context.Background())
			if err != nil {
				g.Done()
				return err
			}

			for {
				arg := <-apiCh
				err = stream.Send(arg)
				if err != nil {
					fmt.Println(err)
					break
				}
				res, e := stream.Recv()
				if e != nil {
					fmt.Println(err)
					break
				}
				if res.Code != api.Error_SUCCESS {
					fmt.Printf("error: code: %d, msg: %s\n", res.Code, res.Msg)
					break
				}
			}
			g.Done()
			return nil
		}()

		g.Add(1)
		go func() {
			index, fd, err := PFPacketBind(globalOpts.DevName)
			fmt.Println(index, fd, err)
			if err != nil {
				return
			}

			vtepAddr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", globalOpts.VtepDst, globalOpts.VtepPort))
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			udpConn, err := net.DialUDP("udp", nil, vtepAddr)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}

			for {
				buf, err := PFPacketRecv(fd)
				if err != nil {
					break
				}
				pkt := gopacket.NewPacket(buf, layers.LayerTypeEthernet, gopacket.Default)

				ethlayer := pkt.Layer(layers.LayerTypeEthernet)
				if ethlayer == nil {
					log.Warn("no ether header")
					continue
				}
				eth, ok := ethlayer.(*layers.Ethernet)
				if ok == false {
					log.Warn("bad ethernet header")
					continue
				}
				if arplayer := pkt.Layer(layers.LayerTypeARP); arplayer != nil {
					arp, ok := arplayer.(*layers.ARP)
					if ok == false {
						log.Warn("bad arp packet")
						continue
					}
					fmt.Println(eth.SrcMAC, eth.DstMAC, eth.EthernetType)
					fmt.Println(net.IP(arp.SourceProtAddress))

					// if we already have, proxy arp
					// how to write back to interfaces ?
					// write to bridge does work?
					// do experiments
					// get vxlan bridge

					path := &api.Path{
						Nlri: &api.Nlri{
							Af: api.AF_EVPN,
							EvpnNlri: &api.EVPNNlri{
								Type: api.EVPN_TYPE_ROUTE_TYPE_MAC_IP_ADVERTISEMENT,
								MacIpAdv: &api.EvpnMacIpAdvertisement{
									MacAddr: net.HardwareAddr(eth.SrcMAC).String(),
									IpAddr:  net.IP(arp.SourceProtAddress).String(),
								},
							},
						},
					}

					path.IsWithdraw = false
					arg := &api.ModPathArguments{
						Resource: api.Resource_GLOBAL,
						Path:     path,
					}
					apiCh <- arg

					vxlanHeader := NewVXLAN(10)
					b := vxlanHeader.Serialize()
					b = append(b, buf...)
					cnt, err := udpConn.Write(b)
					fmt.Printf("cnt: %d, err: %s\n", cnt, err)
				}

			}
			g.Done()
		}()

	}

	g.Add(1)
	go func() {
		s, err := nl.Subscribe(syscall.NETLINK_ROUTE, uint(RTMGRP_NEIGH), uint(RTMGRP_LINK), uint(RTMGRP_NOTIFY))
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		link, err := netlink.LinkByName(globalOpts.DevName)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		fmt.Printf("name: %s, index: %d\n", link.Attrs().Name, link.Attrs().Index)

		for {
			msgs, err := s.Recieve()
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			for _, msg := range msgs {
				t := RTM_TYPE(msg.Header.Type)
				fmt.Printf("Len: %d, Type: %s, Flags: %d, Seq: %d, Pid: %d\n", msg.Header.Len, t, msg.Header.Flags, msg.Header.Seq, msg.Header.Pid)
				switch t {
				case RTM_NEWNEIGH, RTM_DELNEIGH, RTM_GETNEIGH:
					n, _ := netlink.NeighDeserialize(msg.Data)
					fmt.Printf("mac: %s, ip: %s, index: %d, family: %s, state: %s, type: %s, flags: %s\n", n.HardwareAddr, n.IP, n.LinkIndex, NDA_TYPE(n.Family), NUD_TYPE(n.State), RTM_TYPE(n.Type), NTF_TYPE(n.Flags))
				}
			}
		}
		g.Done()
	}()

	g.Wait()
}
