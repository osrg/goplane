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

# args ###########################################################
cID=$1
IP=$2
vlan=$3

if [ $# -ne 3 ]; then
  echo "Usage: dockernw container_ID IP_to_assign VLAN_to_assign"
  exit 1
fi

subnetMask=24 # dummy default
##################################################################

# Create an OVS port to assign to the container
portName="o$IP"
ovs-vsctl add-port docker0-ovs $portName tag=$vlan -- set Interface $portName type=internal

# Set container network so that it is connected to the ovs port created above with the specified IP/VLAN
cpid=`docker inspect --format '{{.State.Pid}}' $cID`

mkdir -p /var/run/netns
ln -s /proc/$cpid/ns/net /var/run/netns/$cpid

ip link set $portName netns $cpid
ip netns exec $cpid ip addr add $IP/$subnetMask dev $portName
ip netns exec $cpid ip link set $portName up
