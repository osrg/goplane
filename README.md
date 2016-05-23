# GoPlane

GoPlane is an agent for configuring linux network stack via [GoBGP](https://github.com/osrg/gobgp)

```
    +=========================+
    |          GoBGP          |
    +=========================+
                 | <- gRPC API
    +=========================+
    |         GoPlane         |
    +=========================+
                 | <- netlink/netfilter
    +=========================+
    |   linux network stack   |
    +=========================+
```

## Features
- EVPN/VxLAN L2VPN construction
    - construct multi-tenant l2 domains using [BGP/EVPN](https://tools.ietf.org/html/rfc7432) and VxLAN
    - see [test/netlink](https://github.com/osrg/goplane/tree/master/test/netlink) for more details
- Flowspec/iptables remote firewall configuration
    - configure firewall using [BGP/FLOWSPEC](https://tools.ietf.org/html/rfc5575) and iptables
    - see [test/iptables](https://github.com/osrg/goplane/tree/master/test/iptables) for more details
