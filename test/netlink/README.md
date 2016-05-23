goplane evpn/vxlan demo
===

This demo shows l2-vpn construction using [BGP/EVPN](https://tools.ietf.org/html/rfc7432) and VxLAN

## How to run
you only need to type 3 commands to play (tested in Ubuntu trusty).

1. install dependent python package to run demo.py
    
     ```
     $ pip install -r ./pip-requires.txt
     ```
2. install docker and other dependent tools. also create goplane container.
    
     ```
     $ sudo ./demo.py prepare
     ```
3. run and play!
    
     ```
     $ sudo ./demo.py
     ```

## How to play
demo.py boots 3 goplane containers (g1 to g3) and 6 host containers (h1 to h3
and j1 to j3) in the following topology. h1 to h3 belongs to the same virtual
network and j1 to j3 as well.

```
     ------------------------------
     |                            |
   ------        ------        ------
   | g1 |--------| g2 |--------| g3 |
   ------        ------        ------
   /   \          /   \        /    \
  /     \        /     \      /      \
------ ------ ------ ------ ------ ------
| h1 | | j1 | | h2 | | j2 | | h3 | | j3 |
------ ------ ------ ------ ------ ------
```

goplane containers work as bgp-speakers and are peering each other.
you can check peering state by

```
$ docker exec -it g1 gobgp neighbor
Peer            AS  Up/Down State       |#Advertised Received Accepted
192.168.10.3 65002 00:00:26 Establ      |         16        5        5
192.168.10.4 65003 00:00:26 Establ      |         13        8        8
```

For the full documentation of gobgp command, see [gobgp](https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md).

In this demo, the subnet of virtual networks is both 10.10.10.0/24.
assignment of the ip address and mac address for each hosts is


|hostname| ip address    | mac address       |
|:------:|:-------------:|:-----------------:|
| h1     | 10.10.10.1/24 | aa:aa:aa:aa:aa:01 |
| h2     | 10.10.10.2/24 | aa:aa:aa:aa:aa:02 |
| h3     | 10.10.10.3/24 | aa:aa:aa:aa:aa:03 |

|hostname| ip address    | mac address       |
|:------:|:-------------:|:-----------------:|
| j1     | 10.10.10.1/24 | aa:aa:aa:aa:aa:01 |
| j2     | 10.10.10.2/24 | aa:aa:aa:aa:aa:02 |
| j3     | 10.10.10.3/24 | aa:aa:aa:aa:aa:03 |

You can see same ip address and mac address is assigned to each host.
but evpn can distinguish them and provide multi-tenant network.

Let's try to ping around!

```
$ docker exec -it h1 ping 10.10.10.3
PING 10.10.10.3 (10.10.10.3): 56 data bytes
64 bytes from 10.10.10.3: icmp_seq=0 ttl=64 time=1.314 ms
64 bytes from 10.10.10.3: icmp_seq=1 ttl=64 time=0.313 ms
```

```
$ docker exec -it j1 ping 10.10.10.2
PING 10.10.10.2 (10.10.10.2): 56 data bytes
64 bytes from 10.10.10.2: icmp_seq=0 ttl=64 time=1.227 ms
64 bytes from 10.10.10.2: icmp_seq=1 ttl=64 time=0.358 ms
```

Does it work? For the next, try tcpdump to watch the packet is transfered
through vxlan tunnel. Continue pinging, and open another terminal and type
bellow.

```
$ docker exec -it g1 tcpdump -i eth1
tcpdump: verbose output suppressed, use -v or -vv for full protocol decode
listening on eth1, link-type EN10MB (Ethernet), capture size 262144 bytes
10:52:09.979708 IP 192.168.0.1.44544 > 192.168.0.3.8472: OTV, flags [I] (0x08), overlay 0, instance 10
IP 10.10.10.1 > 10.10.10.6: ICMP echo request, id 29, seq 9, length 64
10:52:09.979784 IP 192.168.0.3.44544 > 192.168.0.1.8472: OTV, flags [I] (0x08), overlay 0, instance 10
IP 10.10.10.6 > 10.10.10.1: ICMP echo reply, id 29, seq 9, length 64
```

You can see the traffic between goplane containers is delivered by vxlan
(OTV means it is). This means by using evpn/vxlan, you are free from the
constraints of VLAN and thanks to evpn, you are also free from the complexity of
vxlan tunnel management (no need to configure multicast!).

Last thing. let's look a little bit deeper what is happening inside this demo.
try next command.

```
$ docker exec -it g1 gobgp global rib -a evpn
   Network                                                                                                  Next Hop     AS_PATH Age        Attrs
*> [type:macadv][rd:192.168.0.1:0][esi:single-homed][etag:10][mac:22:d5:74:13:25:8f][ip:<nil>][labels:[10]] 0.0.0.0              00:00:11   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]}]
*> [type:macadv][rd:192.168.0.1:0][esi:single-homed][etag:10][mac:aa:aa:aa:aa:aa:01][ip:<nil>][labels:[10]] 0.0.0.0              00:00:10   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]}]
*> [type:macadv][rd:192.168.0.1:0][esi:single-homed][etag:20][mac:3e:72:db:f8:d2:ae][ip:<nil>][labels:[20]] 0.0.0.0              00:00:11   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]}]
*> [type:macadv][rd:192.168.0.1:0][esi:single-homed][etag:20][mac:aa:aa:aa:aa:aa:01][ip:<nil>][labels:[20]] 0.0.0.0              00:00:09   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]}]
*> [type:macadv][rd:192.168.0.2:0][esi:single-homed][etag:10][mac:62:b4:a8:b4:94:32][ip:<nil>][labels:[10]] 192.168.10.3         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.2:0][esi:single-homed][etag:10][mac:aa:aa:aa:aa:aa:02][ip:<nil>][labels:[10]] 192.168.10.3         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.2:0][esi:single-homed][etag:20][mac:5e:1c:ea:43:6b:f9][ip:<nil>][labels:[20]] 192.168.10.3         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.2:0][esi:single-homed][etag:20][mac:aa:aa:aa:aa:aa:02][ip:<nil>][labels:[20]] 192.168.10.3         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.3:0][esi:single-homed][etag:10][mac:5e:27:97:93:3d:7a][ip:<nil>][labels:[10]] 192.168.10.4         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.3:0][esi:single-homed][etag:10][mac:aa:aa:aa:aa:aa:03][ip:<nil>][labels:[10]] 192.168.10.4         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.3:0][esi:single-homed][etag:20][mac:1a:a1:d8:6d:a2:28][ip:<nil>][labels:[20]] 192.168.10.4         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]} {LocalPref: 100}]
*> [type:macadv][rd:192.168.0.3:0][esi:single-homed][etag:20][mac:aa:aa:aa:aa:aa:03][ip:<nil>][labels:[20]] 192.168.10.4         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]} {LocalPref: 100}]
*> [type:multicast][rd:192.168.0.1:0][etag:10][ip:192.168.0.1]                                              0.0.0.0              00:00:11   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]}]
*> [type:multicast][rd:192.168.0.1:0][etag:20][ip:192.168.0.1]                                              0.0.0.0              00:00:11   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]}]
*> [type:multicast][rd:192.168.0.2:0][etag:10][ip:192.168.0.2]                                              192.168.10.3         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]} {LocalPref: 100}]
*> [type:multicast][rd:192.168.0.2:0][etag:20][ip:192.168.0.2]                                              192.168.10.3         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]} {LocalPref: 100}]
*> [type:multicast][rd:192.168.0.3:0][etag:10][ip:192.168.0.3]                                              192.168.10.4         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:10 VXLAN]} {LocalPref: 100}]
*> [type:multicast][rd:192.168.0.3:0][etag:20][ip:192.168.0.3]                                              192.168.10.4         00:00:01   [{Origin: IGP} {EXTENDED_COMMUNITIES: [65000:20 VXLAN]} {LocalPref: 100}]
```

This shows mac addresses of hosts interface. you can see mac addresses are advertised through bgp.
In evpn, mac address learning doesn't occur in dataplane but in control plane (in bgp).
After learning in control plane, goplane install proper rules to linux network stack via netlink.
Let's check that.

```
$ docker exec -it g1 bridge fdb
33:33:00:00:00:01 dev eth1 self permanent
01:00:5e:00:00:01 dev eth1 self permanent
33:33:ff:88:1b:89 dev eth1 self permanent
33:33:00:00:00:01 dev eth2 self permanent
01:00:5e:00:00:01 dev eth2 self permanent
33:33:ff:2a:6c:21 dev eth2 self permanent
33:33:00:00:00:01 dev eth3 self permanent
01:00:5e:00:00:01 dev eth3 self permanent
33:33:ff:12:ff:6f dev eth3 self permanent
9e:74:40:03:55:40 dev vtep10 vlan 0 permanent
b2:2c:ef:2a:6c:21 dev eth2 vlan 0 permanent
de:5d:d1:52:dd:50 dev vtep10 dst 192.168.0.2 self permanent
33:33:ff:77:a0:f4 dev vtep10 dst 192.168.0.2 self permanent
33:33:00:00:00:16 dev vtep10 dst 192.168.0.3 self permanent
33:33:ff:c5:24:4d dev vtep10 dst 192.168.0.3 self permanent
0a:62:40:be:15:40 dev vtep10 dst 192.168.0.2 self permanent
aa:aa:aa:aa:aa:02 dev vtep10 dst 192.168.0.2 self permanent
aa:aa:aa:aa:aa:03 dev vtep10 dst 192.168.0.3 self permanent
ba:fe:66:ed:81:4e dev vtep10 dst 192.168.0.3 self permanent
fa:e1:0c:fa:28:88 dev vtep10 dst 192.168.0.2 self permanent
33:33:ff:1a:cc:15 dev vtep10 dst 192.168.0.3 self permanent
33:33:ff:f6:d1:99 dev vtep10 dst 192.168.0.2 self permanent
c6:74:3f:df:68:52 dev vtep10 dst 192.168.0.2 self permanent
2a:bc:df:a2:bf:79 dev vtep10 dst 192.168.0.3 self permanent
4e:0f:87:12:ff:6f dev eth3 vlan 0 permanent
aa:aa:aa:aa:aa:02 dev vtep20 vlan 0
6e:54:5b:0b:95:e8 dev vtep20 vlan 0 permanent
aa:aa:aa:aa:aa:01 dev eth3 vlan 0
de:5d:d1:52:dd:50 dev vtep20 dst 192.168.0.2 self permanent
33:33:ff:77:a0:f4 dev vtep20 dst 192.168.0.2 self permanent
33:33:00:00:00:16 dev vtep20 dst 192.168.0.3 self permanent
33:33:ff:c5:24:4d dev vtep20 dst 192.168.0.3 self permanent
0a:62:40:be:15:40 dev vtep20 dst 192.168.0.2 self permanent
aa:aa:aa:aa:aa:02 dev vtep20 dst 192.168.0.2 self permanent
aa:aa:aa:aa:aa:03 dev vtep20 dst 192.168.0.3 self permanent
ba:fe:66:ed:81:4e dev vtep20 dst 192.168.0.3 self permanent
fa:e1:0c:fa:28:88 dev vtep20 dst 192.168.0.2 self permanent
33:33:ff:1a:cc:15 dev vtep20 dst 192.168.0.3 self permanent
33:33:ff:f6:d1:99 dev vtep20 dst 192.168.0.2 self permanent
c6:74:3f:df:68:52 dev vtep20 dst 192.168.0.2 self permanent
2a:bc:df:a2:bf:79 dev vtep20 dst 192.168.0.3 self permanent
```

Finally, to clean up this demo, type

```
$ sudo ./demo.py clean
```
