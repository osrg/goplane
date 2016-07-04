goplane iptables/flowspec demo
===

This demo shows remote ACL configuration using [BGP/FLOWSPEC](https://tools.ietf.org/html/rfc5575) and iptables.

## How to run
you only need to type 3 commands to play (tested in Ubuntu trusty and xenial).

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

demo.py boots 3 goplane containers (g1, g2, g3) in the following topology
and starts goplaned and gobgpd.

```
                               40.0.0.0/24
   ------ 10.0.0.0/24 ------   30.0.0.0/24   ------
   | g1 |-------------| g2 |-----------------| g3 |
   ------.1         .2------.1             .2------
```

Check BGP sessions comes up using `gobgp neighbor` command.
It will take about 10 seconds to establish BGP sessions.

```shell
$ docker exec -it g2 gobgp neighbor
Peer                AS  Up/Down State       |#Advertised Received Accepted
192.168.10.2     65000 00:08:28 Establ      |          0        0        0
192.168.10.4     65000 00:08:29 Establ      |          0        0        0
```

For the full documentation of gobgp command, see [gobgp](https://github.com/osrg/gobgp/blob/master/docs/sources/cli-command-syntax.md).

Next, check we can ping to `g3` (30.0.0.2 and 40.0.0.2) from g1.

```shell
$ docker exec -it g1 ping 30.0.0.2
PING 30.0.0.2 (30.0.0.2): 56 data bytes
64 bytes from 30.0.0.2: icmp_seq=0 ttl=63 time=0.155 ms
^C--- 30.0.0.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.155/0.155/0.155/0.000 ms

$ docker exec -it g1 ping 40.0.0.2
PING 40.0.0.2 (40.0.0.2): 56 data bytes
64 bytes from 40.0.0.2: icmp_seq=0 ttl=63 time=0.116 ms
^C--- 40.0.0.2 ping statistics ---
1 packets transmitted, 1 packets received, 0% packet loss
round-trip min/avg/max/stddev = 0.116/0.116/0.116/0.000 ms
```

Say, `g1` is the end-user, `g2` is your border router, and `g3` is your host
serving two IP address (30.0.0.2, 40.0.0.2).

If you want to stop a traffic destined for 30.0.0.2 from `g1` at upstream
router `g2`, you can inject a flowspec route to do that from `g3` and remotely
configure `g2`'s ACL rules. Try the next command.

```shell
$ docker exec -it g3 gobgp global rib -a ipv4-flowspec add match destination 30.0.0.2/32 then discard
```

Try pinging from `g1` to `g3` (30.0.0.2 and 40.0.0.2).
If everything is working fine, ping to 30.0.0.2 won't succeed, but 40.0.0.2 will.

Let's check iptables configuration at `g2`

```shell
$ docker exec -it g2 iptables -L
Chain INPUT (policy ACCEPT)
target     prot opt source               destination

Chain FORWARD (policy ACCEPT)
target     prot opt source               destination
DROP       all  --  anywhere             30.0.0.2

Chain OUTPUT (policy ACCEPT)
target     prot opt source               destination
```

You can see iptables at `g2` is remotely configured by `g3`
