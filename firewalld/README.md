goplane/firewalld: configure iptables via bgp flowspec
---

goplane/firewalld is a small program which configures [iptables](http://www.netfilter.org/projects/iptables/index.html) via [bgp flowspec](https://tools.ietf.org/html/rfc5575).

You can make linux server as a flowspec capable firewall!

### How to install

1. install go
1. `$ go get github.com/osrg/goplane/firewalld`
1. `$ go install github.com/osrg/goplane/firewalld`

### How to use

goplane/firewalld is dependent on [GoBGP](https://github.com/osrg/gobgp).
Before using firewalld, follow [this](https://github.com/osrg/gobgp/blob/master/docs/sources/getting-started.md) instruction and install GoBGP.


#### 1. start gobgpd

```shell
$ sudo gobgpd
{"level":"info","msg":"gobgpd started","time":"2016-05-19T09:16:18Z"}
```

From another terminal type next command

```shell
$ gobgp global as 1000 router-id 1.1.1.1
```

#### 2. start firewalld

```shell
$ sudo firewalld
INFO[0000] firewalld started
INFO[0000] cleared iptables chain: FLOWSPEC, table: filter
```

For safety, `firewalld` writes rules to newly created chain `FLOWSPEC` by default
and doesn't use chain `FORWARD`.
To change the chain, use `--chain` option.

```shell
$ sudo firewalld --chain=FORWARD
INFO[0000] firewalld started
INFO[0000] cleared iptables chain: FORWARD, table: filter
```

#### 3. inject flowspec routes to gobgpd

Here we inject flowspec routes directly to `gobgpd`.
But of course, `firewalld` will configure iptables by remotely received
flowspec routes.

```shell
$ gobgp global rib -a ipv4-flowspec add match destination 20.0.0.0/24 then discard

# check the flowspec route is installed correctly in gobgpd
$ gobgp global rib -a ipv4-flowspec
    Network                  Next Hop             AS_PATH              Age        Attrs
*>  [destination:50.0.0.0/24]fictitious                                00:00:06   [{Origin: ?} {Extcomms: [discard]}]

# check iptables is configured correctly
$ sudo iptables -L FLOWSPEC -n
Chain FLOWSPEC (0 references)
target     prot opt source               destination
DROP       all  --  0.0.0.0/0            50.0.0.0/24
```
