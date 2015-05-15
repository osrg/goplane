
Goplane open BUM-less L2 overlay demo
===

This demo shows how to build a BUM-less L2 overlay network by Goplane without using any vendor specific hardware/software.

## How to run
1. The demo requires capability of running 64 bit guest operating systems (most of the modern Windows PCs and MACs satsify this requirement)

2. Install dependet tools. Note that these tools, including  non-free ones, are for easy-to-use demos and not required for open BUM-less networking itself.
 - [Oracle Virtual Box](https://www.virtualbox.org/)
 - [Vagrant](https://www.vagrantup.com/)

3. Move to goplane/test/ovs directory and execute

     ```
     vagrant up
     ```


## How to play
In this demo, 3 VMs (goplane1 to goplane3) and 6 containres (2 containers/VM) are booted and connected in the following topology.

![the demo topology](./goplane_ovs_demo_topology.png)

Let's see that goplane achieves a BUM less networking. Open a terminal and execute the following commands

    $ vagrant ssh goplane2
    root@goplane3:~# docker exec -it c4 ip a
    root@goplane3:~# docker exec -it c4 tcpdump -vvv

Open another terminal and hit as follows (not the it's not the same)

    $ vagrant ssh goplane3
    root@goplane3:~# docker exec -it c5 ip a
    root@goplane3:~# docker exec -it c5 tcpdump -vvv

You have logged in to c4 (192.168.0.3 on VxLAN '11') and c5 (192.168.0.4 on VxLAN '10'), and packets coming to each container are being captured by tcpdump.

Now let's ping between c1 and c3 and see how BUM packets are suppressed.

    $ vagrant ssh goplane1
    root@goplane1:~# docker exec -it c1 ping 192.168.0.3
    PING 192.168.0.3 (192.168.0.3) 56(84) bytes of data.
    64 bytes from 192.168.0.3: icmp_seq=1 ttl=64 time=0.478 ms
    64 bytes from 192.168.0.3: icmp_seq=2 ttl=64 time=0.793 ms
    64 bytes from 192.168.0.3: icmp_seq=3 ttl=64 time=0.634 ms
    64 bytes from 192.168.0.3: icmp_seq=4 ttl=64 time=0.810 ms
    64 bytes from 192.168.0.3: icmp_seq=5 ttl=64 time=0.789 ms
    ...

While pinging, you get nothing on the both tcpdump results.
The two tcpdump looks the same, but they have different meanings:

1. No packets in the c4 (192.168.0.3 on VxLAN 11) console means that VxLAN segmentation is successfully done. Because you ping'ed to 192.168.0.3 on VxLAN '10', no packets must arrive to this container even though the IP addresses are the same.
2. No packets in the c5 (192.168.0.4 on VxLAN 10) console means the overlay network is fully BUM-less.
Normally, c1 must broadcast an ARP requrest to every containers in the same segment before it can start pinging and everytime the ARP table expires.
This broadcasting increses CPU load for replicating the packet and making the network congested (the BUM problem).
In this demo, ARP packets are not broadcated nor replicated because the OVS in each host knows {IP, Mac, VxLAN tag} pairs and act a proxy arp responder (in other words, an ARP packet sent from a container is just "hit back" at the OVS).

## Look deeper inside