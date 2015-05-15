#!/bin/sh

n=$1
shift

IPs=""
pos=""

i=1
for IP in $@; do
    if [ $i -eq $n ]; then
	myIP=$IP
	AsNumber=`expr 65000 + $i`
    else
	IPs="$IPs $IP"
	pos="$pos $i"
    fi
    
    i=`expr $i + 1`
done

echo "[Bgp.Global]"
echo "RouterId = \"$myIP\""
echo "As = $AsNumber"
echo "[Bgp]"

i=1
for IP in $IPs; do
    position=`echo $pos | cut -d ' ' -f $i`
    AsNumber=`expr 65000 + $position`

    echo "[[Bgp.NeighborList]]"
    echo "NeighborAddress = \"$IP\""
    echo "PeerAs = $AsNumber"
    echo "PeerType = 1"
    echo "AuthPassword = \"\""
    echo "[[Bgp.NeighborList.AfiSafiList]]"
    echo "AfiSafiName = \"ipv4-unicast\""
    echo "[[Bgp.NeighborList.AfiSafiList]]"
    echo "AfiSafiName = \"l2vpn-evpn\""
    echo "[[Bgp.NeighborList.AfiSafiList]]"
    echo "AfiSafiName = \"encap\""
    echo "[[Bgp.NeighborList.AfiSafiList]]"
    echo "AfiSafiName = \"rtc\""

    i=`expr $i + 1`
done

echo "[Dataplane]"
echo "Type = \"ovs\""
