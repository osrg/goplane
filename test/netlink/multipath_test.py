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

        g1 = GoPlaneContainer(name='g1', asn=65000, router_id='192.168.0.1')
        g2 = GoPlaneContainer(name='g2', asn=65000, router_id='192.168.0.2')
        g3 = GoPlaneContainer(name='g3', asn=65000, router_id='192.168.0.3')
        bgps = [g1, g2, g3]

        ctns = bgps
        [ctn.run() for ctn in ctns]

        br01 = Bridge(name='br01', subnet='192.168.10.0/24')
        [br01.addif(ctn, 'eth1') for ctn in bgps]

        for lfs, rfs in itertools.permutations(bgps, 2):
            lfs.add_peer(rfs)

        [ctn.start_goplane() for ctn in bgps]

        cls.ctns = {ctn.name: ctn for ctn in ctns}

    def test_01_neighbor_established(self):
        for i in range(20):
            if all(v['state']['session-state'] == 'established' for v in json.loads(self.ctns['g1'].local('gobgp neighbor -j'))):
                    logging.debug('all peers got established')
                    return
            time.sleep(1)
        raise Exception('timeout')

    def test_02_check_multipath(self):
        for ctn in ['g2', 'g3']:
            self.ctns[ctn].local('gobgp global rib add 10.0.0.0/24')

        time.sleep(1)

        out = self.ctns['g1'].local('ip route')
        logging.debug(out)
        self.assertTrue(len([l for l in out.split('\n') if 'weight' in l.strip().split(' ')]), 2)

if __name__ == '__main__':
    if os.geteuid() is not 0:
        print "you are not root."
        sys.exit(1)
    logging.basicConfig(stream=sys.stderr)
    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
