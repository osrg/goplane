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

if [ $# -ne 3 ]; then
    echo "Usage: docker_goplane docker_image_to_invoke IP_to_assign VLAN_to_assign"
    exit 1
fi


cid=$(docker run --net=none -itd $image)
mac=`ip_to_mac $IP`

dockernw $cid $IP $vlan
goaddmac -m $mac -i $IP -v $vlan
