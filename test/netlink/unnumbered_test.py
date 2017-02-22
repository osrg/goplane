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

        ctn = 1
        for lhs, rhs in itertools.combinations(bgps, 2):
            br = Bridge(name='br0{0}'.format(ctn), with_ip=False)
            lhs_ifname = br.addif(lhs)
            rhs_ifname = br.addif(rhs)

            done = False
            def f(ifname, ctn):
                out = ctn.local('ip -6 n')
                l = [line for line in out.split('\n') if ifname in line]
                if len(l) == 0:
                    return False
                elif len(l) > 1:
                    raise Exception('not p2p link')
                return 'REACHABLE' in l[0]

            for i in range(20):
                try:
                    lhs.local('ping6 --numeric -c 1 ff02::1%{0}'.format(lhs_ifname))
                    rhs.local('ping6 --numeric -c 1 ff02::1%{0}'.format(rhs_ifname))
                    if f(lhs_ifname, lhs) and f(rhs_ifname, rhs):
                        done = True
                        break
                    time.sleep(1)
                except SystemExit:
                    time.sleep(1)

            if not done:
                raise Exception('timeout')

            lhs.add_peer(rhs, interface=lhs_ifname)
            rhs.add_peer(lhs, interface=rhs_ifname)
            ctn += 1

        [ctn.start_goplane() for ctn in bgps]

        cls.ctns = {ctn.name: ctn for ctn in ctns}

    def test_01_neighbor_established(self):
        for i in range(20):
            if all(v['state']['session-state'] == 'established' for v in json.loads(self.ctns['g1'].local('gobgp neighbor -j'))):
                    logging.debug('all peers got established')
                    return
            time.sleep(1)
        raise Exception('timeout')

    def test_02_ping_check(self):
        def ping(ip):
            for i in range(10):
                out = self.ctns['g1'].local("bash -c 'ping --numeric -c 1 {0} 2>&1 > /dev/null && echo true || echo false'".format(ip)).strip()
                if out == 'true':
                    logging.debug('ping reachable')
                    return
                time.sleep(1)
            raise Exception('timeout')
        ping(self.ctns['g2'].router_id)
        ping(self.ctns['g3'].router_id)

if __name__ == '__main__':
    if os.geteuid() is not 0:
        print "you are not root."
        sys.exit(1)
    logging.basicConfig(stream=sys.stderr)
    nose.main(argv=sys.argv, addplugins=[OptionParser()],
              defaultTest=sys.argv[0])
