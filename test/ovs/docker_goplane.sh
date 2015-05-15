# Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

image=$1
IP=$2
vlan=$3
name=$4

if [ $# -lt 3 ]; then
    echo "Usage: docker_goplane docker_image_to_invoke IP_to_assign VLAN_to_assign [name]"
    exit 1
fi

# run a container
if [ "$name" = "" ]; then
    cid=$(docker run --net=none -itd $image)
else
    cid=$(docker run --net=none --name $name -itd $image)
fi

# Create mac address
mac="02:42" # hard-coded prefix

for d in `echo "$IP" | sed -e "s/\./ /g"`; do
    # d:   each digit of the given IP (e.g. if ip=="10.1.0.5" then d: 10 1 0 5)
    # d16: 2-digit-long base 16 expression of d padded with 0 (e.g. d16: 0a 01 00 05)
    d16=`printf '%02x' $d`
    mac="$mac:$d16"
done

echo $mac

# Create an OVS port to assign to the container
# A port name contains 12 characters
#  1 234 56789012
# |o|VNI|IP      |
# 1   : "o"
# 2-4 : VNI (VLAN id) shown in base 16 (e.g. $vlan==10 -> "00a"), which is long enough as a VLAN id is less than 0xfff (4095)
# 5-12: IP address shown in base 16 without any dots (e.g. $IP=="10.1.2.3" -> "0a010203")
portName=`printf '%03x' $vlan`
portName="o$portName"
for d in `echo "$IP" | sed -e "s/\./ /g"`; do
    d16=`printf '%02x' $d`
    portName="$portName$d16"
done

ovs-vsctl add-port docker0-ovs $portName tag=$vlan -- set Interface $portName type=internal


# Set container network so that it is connected to the ovs port created above with the specified IP/VLAN
cpid=`docker inspect --format '{{.State.Pid}}' $cid`
subnetMask=24

mkdir -p /var/run/netns
ln -s /proc/$cpid/ns/net /var/run/netns/$cpid

ip link set $portName netns $cpid
ip netns exec $cpid ip link set $portName addr $mac
ip netns exec $cpid ip addr add $IP/$subnetMask dev $portName
ip netns exec $cpid ip link set $portName up


# advertise IP, mac, and VNI with BGP
goaddmac -m $mac -i $IP -v $vlan
