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

# transform an IP address to a MAC address
ip=$1
mac="02:42" # hard-coded prefix

# d:   each digit of the given IP (e.g. if ip=="10.1.0.5" then d: 10 1 0 5)
# d16: 2-digit-long base 16 expression of d padded with 0 (e.g. d16: 0a 01 00 05)
for d in `echo "$ip" | sed -e "s/\./ /g"`; do
    d16=`printf '%02x' $d`
    mac="$mac:$d16"
done

echo $mac
