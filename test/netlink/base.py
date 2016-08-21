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
import time

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


class Bridge(object):
    def __init__(self, name, subnet='', with_ip=True):
        ip = IPRoute()
        br = ip.link_lookup(ifname=name)
        if len(br) != 0:
            ip.link('del', index=br[0])
        ip.link('add', ifname=name, kind='bridge')
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
            ip.link('add', ifname=host_ifname, kind='veth', peer=guest_ifname)
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
            return ifname


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
        time.sleep(2)
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
                 policies=None, passive=False, interface=''):

        neigh_addr = ''
        if interface == '' :
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
                            'passive' : passive,
                            'interface' : interface}
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

    def __init__(self, name, asn, router_id, ctn_image_name='osrg/goplane',
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

        time.sleep(1)

        name = '{0}/start_goplane.sh'.format(self.config_dir)
        with open(name, 'w') as f:
            f.write('''#!/bin/bash
goplane -f {0}/goplane.conf -l {1} -p > {0}/goplane.log 2>&1
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

        with open('{0}/goplane.conf'.format(self.config_dir), 'w') as f:
            f.write(toml.dumps(config))

    def create_gobgp_config(self):
        config = {'global': {'config': {'as': self.asn, 'router-id': self.router_id},
                             'use-multiple-paths': {'config': {'enabled': True}}}}
        for peer, info in self.peers.iteritems():
            if info['interface'] == '':
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

                n = {'config': {
                        'neighbor-address': info['neigh_addr'],
                        'peer-as': peer.asn,
                        'local-as': self.asn,
                     },
                     'afi-safis': afi_safi_list,
                    }
            else:
                afi_safi_list = [
                        {'config': {'afi-safi-name': 'ipv4-unicast'}},
                        {'config': {'afi-safi-name': 'ipv6-unicast'}},
                ]
                n = {'config': {'neighbor-interface': info['interface']},
                     'afi-safis': afi_safi_list}

            if len(info['passwd']) > 0:
                n['config']['auth-password'] = info['passwd']

            if info['evpn']:
                afi_safi_list.append({'config': {'afi-safi-name': 'l2vpn-evpn'}})

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
        self.local('/usr/bin/pkill goplane -SIGHUP')

    def add_vn(self, vni, vtep, color, member, vxlan_port=8472):
        self.vns.append({'vni':vni, 'vtep':vtep, 'vxlan_port':vxlan_port,
                         'color':color, 'member':member})
