// Copyright (C) 2015 Nippon Telegraph and Telephone Corporation.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
// implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

type VXLAN struct {
	VNI uint32
}

func NewVXLAN(vni uint32) *VXLAN {
	return &VXLAN{
		VNI: vni,
	}
}

func (v *VXLAN) Serialize() []byte {
	buf := make([]byte, 8)
	buf[0] = 1 << 3
	buf[4] = byte((v.VNI >> 16) & 0xff)
	buf[5] = byte((v.VNI >> 8) & 0xff)
	buf[6] = byte(v.VNI & 0xff)
	return buf
}
