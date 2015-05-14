goplane evpn/vxlan demo
===

This demo shows l2-vpn construction using [evpn/vxlan](https://tools.ietf.org/html/draft-ietf-bess-evpn-overlay-01).

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
demo.py boots 3 goplane containers (g1 to g3) and 6 host containers (h1 to h6)
in the following topology. 

```
     ------------------------------
     |                            |
   ------        ------        ------
   | g1 |--------| g2 |--------| g3 |
   ------        ------        ------
   /   \          /   \        /    \
  /     \        /     \      /      \
------ ------ ------ ------ ------ ------
| h1 | | h4 | | h2 | | h5 | | h3 | | h6 |
------ ------ ------ ------ ------ ------
```

goplane containers work as bgp-speaker and are peering each other.
you can check peering state by

```
$ docker exec -it g1 gobgp neighbor
Peer            AS  Up/Down State       |#Advertised Received Accepted
192.168.10.3 65002 00:00:26 Establ      |         16        5        5
192.168.10.4 65003 00:00:26 Establ      |         13        8        8
```

For the full documentation of gobgp command, see [gobgp](https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md).

In this demo, all host containers belong to the same virtual-network.
the subnet is 10.10.10.0/24 and h1's address is 10.10.10.1, h2's address is
10.10.10.2... and h6's address is 10.10.10.6.

let's try to ping around!

```
$ docker exec -it h1 ping 10.10.10.6
PING 10.10.10.6 (10.10.10.6): 56 data bytes
64 bytes from 10.10.10.6: icmp_seq=0 ttl=64 time=1.314 ms
64 bytes from 10.10.10.6: icmp_seq=1 ttl=64 time=0.313 ms
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
Please specify one command of: add or del
   Network            Next Hop        AS_PATH    Age        Attrs
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:1e:68:da:f7:80:16][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:1e:68:da:f7:80:16][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002 65003] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:42:37:75:89:5a:25][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:42:37:75:89:5a:25][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002 65003] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:4e:06:0b:6c:38:85][ip:0.0.0.0][labels:[0]] 0.0.0.0         [65001]    00:01:29   [{Origin: IGP} {Encap: < VXLAN | color: 10 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:4e:59:ec:a9:8b:69][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:4e:59:ec:a9:8b:69][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003 65002] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:6a:5b:33:aa:6e:4c][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:6a:5b:33:aa:6e:4c][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002 65003] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:7a:ea:ad:31:5c:ea][ip:0.0.0.0][labels:[0]] 0.0.0.0         [65001]    00:08:46   [{Origin: IGP} {Encap: < VXLAN | color: 10 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:8e:de:66:ab:b5:15][ip:0.0.0.0][labels:[0]] 0.0.0.0         [65001]    00:08:47   [{Origin: IGP} {Encap: < VXLAN | color: 10 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:92:ae:e8:87:ce:bc][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002]    00:08:46   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:92:ae:e8:87:ce:bc][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003 65002] 00:08:46   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:96:37:1d:19:90:9b][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:96:37:1d:19:90:9b][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003 65002] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:9e:5e:51:2b:97:f3][ip:0.0.0.0][labels:[0]] 0.0.0.0         [65001]    00:08:46   [{Origin: IGP} {Encap: < VXLAN | color: 10 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:a6:fc:87:f8:d2:aa][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:a6:fc:87:f8:d2:aa][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002 65003] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:aa:50:1a:cd:15:5f][ip:0.0.0.0][labels:[0]] 0.0.0.0         [65001]    00:08:46   [{Origin: IGP} {Encap: < VXLAN | color: 10 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ae:45:be:2d:f8:d9][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ae:45:be:2d:f8:d9][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003 65002] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 11 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ca:65:30:2a:75:dc][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ca:65:30:2a:75:dc][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002 65003] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ce:58:0e:c6:b3:bd][ip:0.0.0.0][labels:[0]] 0.0.0.0         [65001]    00:08:47   [{Origin: IGP} {Encap: < VXLAN | color: 10 >}]
   *> [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ee:5b:b6:a9:ce:76][ip:0.0.0.0][labels:[0]] 192.168.10.4    [65003]    00:13:44   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
   *  [type:macadv][rd:0:0][esi:single-homed][etag:0][mac:ee:5b:b6:a9:ce:76][ip:0.0.0.0][labels:[0]] 192.168.10.3    [65002 65003] 00:10:39   [{Origin: IGP} {Encap: < VXLAN | color: 12 >}]
```

This shows mac addresses of hosts interface. you can see mac addresses are advertised through bgp.
In evpn, mac address learning doesn't occur in dataplane but in control plane (in bgp).
After learning in control plane, goplane install proper rules to linux network stack via netlink.
Let's check that.

```
$ docker exec -it g1 bridge fdb
33:33:00:00:00:01 dev eth1 self permanent
01:00:5e:00:00:01 dev eth1 self permanent
33:33:ff:2f:56:ec dev eth1 self permanent
33:33:00:00:00:01 dev eth2 self permanent
01:00:5e:00:00:01 dev eth2 self permanent
33:33:ff:02:a1:37 dev eth2 self permanent
33:33:00:00:00:01 dev eth3 self permanent
01:00:5e:00:00:01 dev eth3 self permanent
33:33:ff:57:e5:84 dev eth3 self permanent
be:4b:9b:57:e5:84 dev eth3 vlan 0 permanent
be:f5:ff:02:a1:37 dev eth2 vlan 0 permanent
ee:3d:91:dd:e2:5b dev vtep10 vlan 0 permanent
ae:45:be:2d:f8:d9 dev vtep10 dst 192.168.0.2 self permanent
ca:65:30:2a:75:dc dev vtep10 dst 192.168.0.3 self permanent
1e:68:da:f7:80:16 dev vtep10 dst 192.168.0.3 self permanent
96:37:1d:19:90:9b dev vtep10 dst 192.168.0.2 self permanent
92:ae:e8:87:ce:bc dev vtep10 dst 192.168.0.2 self permanent
6a:5b:33:aa:6e:4c dev vtep10 dst 192.168.0.3 self permanent
4e:59:ec:a9:8b:69 dev vtep10 dst 192.168.0.2 self permanent
a6:fc:87:f8:d2:aa dev vtep10 dst 192.168.0.3 self permanent
ee:5b:b6:a9:ce:76 dev vtep10 dst 192.168.0.3 self permanent
42:37:75:89:5a:25 dev vtep10 dst 192.168.0.3 self permanent
```

Finally, to clean up this demo, type

```
$ sudo ./demo.py clean
```
