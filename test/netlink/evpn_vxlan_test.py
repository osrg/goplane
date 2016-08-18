# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
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

import unittest
import nose
import os
import sys
import time
import logging
import json
from noseplugin import OptionParser
from base import *

class Test(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        h1 = Container(name='h1', image='osrg/gobgp')
        h2 = Container(name='h2', image='osrg/gobgp')
        h3 = Container(name='h3', image='osrg/gobgp')
        j1 = Container(name='j1', image='osrg/gobgp')
        j2 = Container(name='j2', image='osrg/gobgp')
        j3 = Container(name='j3', image='osrg/gobgp')
        hs = [h1, h2, h3]
        js = [j1, j2, j3]
        hosts = hs + js

        g1 = GoPlaneContainer(name='g1', asn=65000, router_id='192.168.0.1')
        g2 = GoPlaneContainer(name='g2', asn=65000, router_id='192.168.0.2')
        g3 = GoPlaneContainer(name='g3', asn=65000, router_id='192.168.0.3')
        bgps = [g1, g2, g3]

        for idx, ctn in enumerate(bgps):
            ctn.add_vn(10, 'vtep10', 10, ['eth2'])

        for idx, ctn in enumerate(bgps):
            ctn.add_vn(20, 'vtep20', 20, ['eth3'])

        ctns = bgps + hosts
        [ctn.run() for ctn in ctns]

        br01 = Bridge(name='br01', subnet='192.168.10.0/24')
        [br01.addif(ctn, 'eth1') for ctn in bgps]

        for lfs, rfs in itertools.permutations(bgps, 2):
            lfs.add_peer(rfs, evpn=True)

        br02 = Bridge(name='br02', with_ip=False)
        br02.addif(g1, 'eth2')
        br02.addif(h1, 'eth1', 'aa:aa:aa:aa:aa:01')

        br03 = Bridge(name='br03', with_ip=False)
        br03.addif(g2, 'eth2')
        br03.addif(h2, 'eth1', 'aa:aa:aa:aa:aa:02')

        br04 = Bridge(name='br04', with_ip=False)
        br04.addif(g3, 'eth2')
        br04.addif(h3, 'eth1', 'aa:aa:aa:aa:aa:03')

        br05 = Bridge(name='br05', with_ip=False)
        br05.addif(g1, 'eth3')
        br05.addif(j1, 'eth1', 'aa:aa:aa:aa:aa:01')

        br06 = Bridge(name='br06', with_ip=False)
        br06.addif(g2, 'eth3')
        br06.addif(j2, 'eth1', 'aa:aa:aa:aa:aa:02')

        br07 = Bridge(name='br07', with_ip=False)
        br07.addif(g3, 'eth3')
        br07.addif(j3, 'eth1', 'aa:aa:aa:aa:aa:03')

        [ctn.local("ip a add 10.10.10.{0}/24 dev eth1".format(i+1)) for i, ctn in enumerate(hs)]
        [ctn.local("ip a add 10.10.10.{0}/24 dev eth1".format(i+1)) for i, ctn in enumerate(js)]

        [ctn.start_goplane() for ctn in bgps]

        cls.ctns = {ctn.name: ctn for ctn in ctns}

    def test_01_neighbor_established(self):
        for i in range(20):
            if all(v['info']['bgp_state'] == 'BGP_FSM_ESTABLISHED' for v in json.loads(self.ctns['g1'].local('gobgp neighbor -j'))):
                    logging.debug('all peers got established')
                    return
            time.sleep(1)
        raise Exception('timeout')

    def test_02_ping_check(self):
        for i in range(10):
            out = self.ctns['h1'].local("bash -c 'ping -c 1 10.10.10.3 2>&1 > /dev/null && echo true || echo false'").strip()
            if out == 'true':
                logging.debug('ping reachable')
                return
            time.sleep(1)
        raise Exception('timeout')

    def test_03_show_evpn_bgp_table(self):
        logging.debug(self.ctns['g1'].local('gobgp global rib -a evpn'))

if __name__ == '__main__':
    if os.geteuid() is not 0:
        print "you are not root."
        sys.exit(1)
    logging.basicConfig(stream=sys.stderr)
    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
