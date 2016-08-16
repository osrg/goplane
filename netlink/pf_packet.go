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
// +build linux

package netlink

import (
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

const (
	PF_PACKET         = 17     // taken from /usr/include/x86_64-linux-gnu/bits/socket.h
	PACKET_BROADCAST  = 1      // taken from /usr/include/linux/if_packet.h
	PACKET_MR_PROMISC = 1      // taken from /usr/include/linux/if_packet.h
	ETH_P_ALL         = 0x0003 // taken from /usr/include/linux/if_ether.h
)

type packetMreq struct {
	mrIfindex int32
	mrType    uint16
	mrAlen    uint16
	mrAddress [8]uint8
}

func htons(host uint16) uint16 {
	return (host&0xff)<<8 | (host >> 8)
}

type PFConn struct {
	fd   int
	intf *net.Interface
}

func (c *PFConn) read(b []byte) (int, *syscall.RawSockaddrLinklayer, error) {
	var sll syscall.RawSockaddrLinklayer
	size := unsafe.Sizeof(sll)
	r1, _, e := syscall.Syscall6(syscall.SYS_RECVFROM, uintptr(c.fd),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, uintptr(unsafe.Pointer(&sll)), uintptr(unsafe.Pointer(&size)))
	if e > 0 {
		return 0, nil, e
	}
	return int(r1), &sll, nil
}

func (c *PFConn) Read(b []byte) (int, error) {
	for {
		n, from, err := c.read(b)
		if err != nil {
			return 0, err
		}
		if from.Pkttype == PACKET_BROADCAST {
			return n, nil
		}
	}
}

func (c *PFConn) Write(b []byte) (n int, err error) {
	sll := syscall.RawSockaddrLinklayer{
		Ifindex: int32(c.intf.Index),
	}
	r1, _, e := syscall.Syscall6(syscall.SYS_SENDTO, uintptr(c.fd),
		uintptr(unsafe.Pointer(&b[0])), uintptr(len(b)),
		0, uintptr(unsafe.Pointer(&sll)), unsafe.Sizeof(sll))
	if e > 0 {
		return 0, e
	}
	return int(r1), e
}

func (c *PFConn) Close() error {
	_, _, e := syscall.Syscall(syscall.SYS_CLOSE, uintptr(c.fd), 0, 0)
	if e > 0 {
		return e
	}
	return nil
}

func (c *PFConn) String() string {
	return fmt.Sprintf("PFConn(fd: %d, intf: %v)", c.fd, c.intf)
}

func NewPFConn(ifname string) (*PFConn, error) {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return nil, err
	}
	fd, err := syscall.Socket(PF_PACKET, syscall.SOCK_RAW, int(htons(ETH_P_ALL)))
	if err != nil {
		return nil, err
	}
	mreq := packetMreq{
		mrIfindex: int32(intf.Index),
		mrType:    PACKET_MR_PROMISC,
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_SETSOCKOPT, uintptr(fd),
		uintptr(syscall.SOL_PACKET), uintptr(syscall.PACKET_ADD_MEMBERSHIP),
		uintptr(unsafe.Pointer(&mreq)), unsafe.Sizeof(mreq), 0); e > 0 {
		return nil, e
	}
	sll := syscall.RawSockaddrLinklayer{
		Family:   PF_PACKET,
		Protocol: htons(ETH_P_ALL),
		Ifindex:  int32(intf.Index),
	}
	if _, _, e := syscall.Syscall(syscall.SYS_BIND, uintptr(fd),
		uintptr(unsafe.Pointer(&sll)), unsafe.Sizeof(sll)); e > 0 {
		return nil, e
	}
	return &PFConn{
		fd:   fd,
		intf: intf,
	}, nil
}
