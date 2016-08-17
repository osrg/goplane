#!/usr/bin/env python
# Copyright (C) 2015,2016 Nippon Telegraph and Telephone Corporation.
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

import os
import sys
import itertools
import string
import random
from optparse import OptionParser

import netaddr
import toml
from pyroute2 import IPRoute
from docker import Client
from nsenter import Namespace

TEST_BASE_DIR = '/tmp/goplane'

dckr = Client()

flatten = lambda l: itertools.chain.from_iterable(l)
random_str = lambda n : ''.join([random.choice(string.ascii_letters + string.digits) for i in range(n)])
get_containers = lambda : [str(x)[1:] for x in list(flatten(n['Names'] for n in dckr.containers(all=True)))]

class docker_netns(object):
    def __init__(self, name):
        pid = int(dckr.inspect_container(name)['State']['Pid'])
        if pid == 0:
            raise Exception('no container named {0}'.format(name))
        self.pid = pid

    def __enter__(self):
        pid = self.pid
        if not os.path.exists('/var/run/netns'):
            os.mkdir('/var/run/netns')
        os.symlink('/proc/{0}/ns/net'.format(pid), '/var/run/netns/{0}'.format(pid))
        return str(pid)

    def __exit__(self, type, value, traceback):
        pid = self.pid
        os.unlink('/var/run/netns/{0}'.format(pid))


class CmdBuffer(list):
    def __init__(self, delim='\n'):
        super(CmdBuffer, self).__init__()
        self.delim = delim

    def __lshift__(self, value):
        self.append(value)

    def __str__(self):
        return self.delim.join(self)


class Bridge(object):
    def __init__(self, name, subnet='', with_ip=True):
        ip = IPRoute()
        br = ip.link_lookup(ifname=name)
        if len(br) != 0:
            ip.link('del', index=br[0])
        ip.link_create(ifname=name, kind='bridge')
        br = ip.link_lookup(ifname=name)
        br = br[0]
        ip.link('set', index=br, state='up')

        if with_ip:
            self.subnet = netaddr.IPNetwork(subnet)

            def f():
                for host in self.subnet:
                    yield host
            self._ip_generator = f()
            # throw away first network address
            self.next_ip_address()
            self.ip_addr = self.next_ip_address()
            address, prefixlen = self.ip_addr.split('/')
            ip.addr('add', index=br, address=address, prefixlen=int(prefixlen))

        self.name = name
        self.with_ip = with_ip
        self.br = br
        self.ctns = []

    def next_ip_address(self):
        return "{0}/{1}".format(self._ip_generator.next(),
                                self.subnet.prefixlen)

    def addif(self, ctn, ifname='', mac=''):
        with docker_netns(ctn.name) as pid:
            host_ifname = '{0}_{1}'.format(self.name, ctn.name)
            guest_ifname = random_str(5)
            ip = IPRoute()
            ip.link_create(ifname=host_ifname, kind='veth', peer=guest_ifname)
            host = ip.link_lookup(ifname=host_ifname)[0]
            ip.link('set', index=host, master=self.br)
            ip.link('set', index=host, state='up')

            self.ctns.append(ctn)

            guest = ip.link_lookup(ifname=guest_ifname)[0]
            ip.link('set', index=guest, net_ns_fd=pid)
            with Namespace(pid, 'net'):
                ip = IPRoute()
                if ifname == '':
                    links = [x.get_attr('IFLA_IFNAME') for x in ip.get_links()]
                    n = [int(l[len('eth'):]) for l in links if l.startswith('eth')]
                    idx = 0
                    if len(n) > 0:
                        idx = max(n) + 1
                    ifname = 'eth{0}'.format(idx)
                ip.link('set', index=guest, ifname=ifname)
                ip.link('set', index=guest, state='up')

                if mac != '':
                    ip.link('set', index=guest, address=mac)

                if self.with_ip:
                    address, mask = self.next_ip_address().split('/')
                    ip.addr('add', index=guest, address=address, mask=int(mask))
                    ctn.ip_addrs.append((ifname, address, self.name))


class Container(object):
    def __init__(self, name, image):
        self.name = name
        self.image = image
        self.shared_volumes = []
        self.ip_addrs = []
        self.is_running = False

    def run(self):
        if self.name in get_containers():
            self.stop()
        binds = ['{0}:{1}'.format(os.path.abspath(sv[0]), sv[1]) for sv in self.shared_volumes]
        config = dckr.create_host_config(binds=binds, privileged=True)
        ctn = dckr.create_container(image=self.image, detach=True, name=self.name,
                                    stdin_open=True, volumes=[sv[1] for sv in self.shared_volumes],
                                    host_config=config, network_disabled=True)
        dckr.start(container=self.name)
        self.id = ctn['Id']
        self.is_running = True
        with docker_netns(self.name) as pid:
            with Namespace(pid, 'net'):
                ip = IPRoute()
                lo = ip.link_lookup(ifname='lo')[0]
                ip.link('set', index=lo, state='up')


    def stop(self):
        dckr.remove_container(container=self.name, force=True)
        self.is_running = False

    def local(self, cmd, stream=False, detach=False):
        i = dckr.exec_create(container=self.name, cmd=cmd)
        return dckr.exec_start(i['Id'], tty=True, stream=stream, detach=detach)


class BGPContainer(Container):

    WAIT_FOR_BOOT = 0
    RETRY_INTERVAL = 5

    def __init__(self, name, asn, router_id, ctn_image_name):
        self.config_dir = "{0}/{1}".format(TEST_BASE_DIR, name)
        if not os.path.exists(self.config_dir):
            os.makedirs(self.config_dir)
            os.chmod(self.config_dir, 0777)
        self.asn = asn
        self.router_id = router_id
        self.peers = {}
        self.routes = []
        self.policies = {}
        super(BGPContainer, self).__init__(name, ctn_image_name)

    def run(self):
        self.create_config()
        super(BGPContainer, self).run()

    def add_peer(self, peer, passwd='', evpn=False, is_rs_client=False,
                 policies=None, passive=False):
        neigh_addr = ''
        for me, you in itertools.product(self.ip_addrs, peer.ip_addrs):
            if me[2] == you[2]:
                neigh_addr = you[1]

        if neigh_addr == '':
            raise Exception('peer {0} seems not ip reachable'.format(peer))

        if not policies:
            policies = []

        self.peers[peer] = {'neigh_addr': neigh_addr,
                            'passwd': passwd,
                            'evpn': evpn,
                            'is_rs_client': is_rs_client,
                            'policies': policies,
                            'passive' : passive}
        self.create_config()

    def del_peer(self, peer):
        del self.peers[peer]
        self.create_config()
        if self.is_running:
            self.reload_config()

    def create_config(self):
        raise Exception('implement create_config() method')

    def reload_config(self):
        raise Exception('implement reload_config() method')


class GoPlaneContainer(BGPContainer):

    PEER_TYPE_INTERNAL = 'internal'
    PEER_TYPE_EXTERNAL = 'external'
    SHARED_VOLUME = '/root/shared_volume'

    def __init__(self, name, asn, router_id, ctn_image_name='goplane',
                 log_level='debug'):
        super(GoPlaneContainer, self).__init__(name, asn, router_id,
                                             ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))
        self.vns = []
        self.log_level = 'debug'

    def start_goplane(self):
        name = '{0}/start_gobgp.sh'.format(self.config_dir)
        with open(name, 'w') as f:
            f.write('''#!/bin/bash
gobgpd -f {0}/gobgpd.conf -l {1} -p > {0}/gobgpd.log 2>&1
'''.format(self.SHARED_VOLUME, self.log_level))
        os.chmod(name, 0755)
        self.local('{0}/start_gobgp.sh'.format(self.SHARED_VOLUME), detach=True)

        name = '{0}/start_goplane.sh'.format(self.config_dir)
        with open(name, 'w') as f:
            f.write('''#!/bin/bash
goplaned -f {0}/goplaned.conf -l {1} -p > {0}/goplaned.log 2>&1
'''.format(self.SHARED_VOLUME, self.log_level))
        os.chmod(name, 0755)
        self.local('{0}/start_goplane.sh'.format(self.SHARED_VOLUME), detach=True)


    def run(self):
        super(GoPlaneContainer, self).run()
        return self.WAIT_FOR_BOOT

    def create_goplane_config(self):
        dplane_config = {'type': 'netlink', 'virtual-network-list': []}
        for info in self.vns:
            dplane_config['virtual-network-list'].append({'rd': '{0}:{1}'.format(self.asn, info['vni']),
                                                          'vni': info['vni'],
                                                          'vxlan-port': info['vxlan_port'],
                                                          'vtep-interface': info['vtep'],
                                                          'etag': info['color'],
                                                          'sniff-interfaces': info['member'],
                                                          'member-interfaces': info['member']})

        config = {'dataplane': dplane_config}

        with open('{0}/goplaned.conf'.format(self.config_dir), 'w') as f:
            f.write(toml.dumps(config))

    def create_gobgp_config(self):
        config = {'global': {'config': {'as': self.asn, 'router-id': self.router_id}}}
        for peer, info in self.peers.iteritems():
            if self.asn == peer.asn:
                peer_type = self.PEER_TYPE_INTERNAL
            else:
                peer_type = self.PEER_TYPE_EXTERNAL

            afi_safi_list = []
            version = netaddr.IPNetwork(info['neigh_addr']).version
            if version == 4:
                afi_safi_list.append({'config': {'afi-safi-name': 'ipv4-unicast'}})
            elif version == 6:
                afi_safi_list.append({'config': {'afi-safi-name': 'ipv6-unicast'}})
            else:
                Exception('invalid ip address version. {0}'.format(version))

            if info['evpn']:
                afi_safi_list.append({'config': {'afi-safi-name': 'l2vpn-evpn'}})

            n = {'config': {
                    'neighbor-address': info['neigh_addr'],
                    'peer-as': peer.asn,
                    'local-as': self.asn,
                    'auth-password': info['passwd'],
                 },
                 'afi-safis': afi_safi_list,
                }

            if info['passive']:
                n['transport'] = {'config': {'passive-mode':True}}

            if info['is_rs_client']:
                n['route-server'] = {'config': {'route-server-client': True}}

            if 'neighbors' not in config:
                config['neighbors'] = []

            config['neighbors'].append(n)

        with open('{0}/gobgpd.conf'.format(self.config_dir), 'w') as f:
            f.write(toml.dumps(config))

    def create_config(self):
        self.create_gobgp_config()
        self.create_goplane_config()

    def reload_config(self):
        self.local('/usr/bin/pkill gobgpd -SIGHUP')
        self.local('/usr/bin/pkill goplaned -SIGHUP')

    def add_vn(self, vni, vtep, color, member, vxlan_port=8472):
        self.vns.append({'vni':vni, 'vtep':vtep, 'vxlan_port':vxlan_port,
                         'color':color, 'member':member})


if __name__ == '__main__':

    parser = OptionParser(usage="usage: %prog [clean]")
    options, args = parser.parse_args()

    os.chdir(os.path.abspath(os.path.dirname(__file__)))

    if os.getegid() != 0:
        print "execute as root"
        sys.exit(1)

    if len(args) > 0:
        if args[0] == 'clean':
            for ctn in get_containers():
                if ctn[0] == 'h' or ctn[0] == 'j' or ctn[0] == 'g':
                    print 'remove container {0}'.format(ctn)
                    dckr.remove_container(container=ctn, force=True)

            ip = IPRoute()
            for i in range(7):
                name = "br0" + str(i+1)
                brs = ip.link_lookup(ifname=name)
                for br in brs:
                    print 'delete link {0}'.format(name)
                    ip.link('del', index=br)
            sys.exit(0)
        else:
            print "usage: demo.py [clean]"
            sys.exit(1)

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
