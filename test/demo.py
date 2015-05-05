#!/usr/bin/env python
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

from fabric.context_managers import shell_env
from fabric.api import local
from fabric import colors
from optparse import OptionParser
import netaddr
import toml
import itertools
import os
import sys

TEST_BASE_DIR = '/tmp/goplane'
DEFAULT_GOPATH = '$HOME/.go'
GOPATH = DEFAULT_GOPATH

def install_docker_and_tools():
    print "start install packages of test environment."
    local("apt-key adv --keyserver hkp://keyserver.ubuntu.com:80 --recv-keys "
          "36A1D7869245C8950F966E92D8576A8BA88D21E9", capture=True)
    local('sh -c "echo deb https://get.docker.io/ubuntu docker main > /etc/apt/sources.list.d/docker.list"',
          capture=True)
    local("apt-get update", capture=True)
    local("apt-get install -y --force-yes lxc-docker-1.3.2", capture=True)
    local("ln -sf /usr/bin/docker.io /usr/local/bin/docker", capture=True)
    local("gpasswd -a `whoami` docker", capture=True)
    local("wget https://raw.github.com/jpetazzo/pipework/master/pipework -O /usr/local/bin/pipework",
          capture=True)
    local("chmod 755 /usr/local/bin/pipework", capture=True)
    local("docker pull osrg/gobgp", capture=True)
    update_goplane()

def update_goplane():
    local("cp Dockerfile ../../")
    local("cd ../../ && docker build -t goplane . && rm Dockerfile")

def get_bridges():
    return local("brctl show | awk 'NR > 1{print $1}'",
                 capture=True).split('\n')


def get_containers():
    return local("docker ps -a | awk 'NR > 1 {print $NF}'",
                 capture=True).split('\n')


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
        self.name = name
        self.with_ip = with_ip
        if with_ip:
            self.subnet = netaddr.IPNetwork(subnet)

            def f():
                for host in self.subnet:
                    yield host
            self._ip_generator = f()
            # throw away first network address
            self.next_ip_address()

        if self.name in get_bridges():
            self.delete()

        local("ip link add {0} type bridge".format(self.name), capture=True)
        local("ip link set up dev {0}".format(self.name), capture=True)

        if with_ip:
            self.ip_addr = self.next_ip_address()
            local("ip addr add {0} dev {1}".format(self.ip_addr, self.name),
                  capture=True)

        self.ctns = []

    def next_ip_address(self):
        return "{0}/{1}".format(self._ip_generator.next(),
                                self.subnet.prefixlen)

    def addif(self, ctn, name=''):
        if name == '':
            name = self.name
        self.ctns.append(ctn)
        if self.with_ip:
            ctn.pipework(self, self.next_ip_address(), name)
        else:
            ctn.pipework(self, '0/0', name)

    def delete(self):
        local("ip link set down dev {0}".format(self.name), capture=True)
        local("ip link delete {0} type bridge".format(self.name), capture=True)


class Container(object):
    def __init__(self, name, image):
        self.name = name
        self.image = image
        self.shared_volumes = []
        self.ip_addrs = []
        self.is_running = False

        if self.name in get_containers():
            self.stop()

    def run(self):
        c = CmdBuffer(' ')
        c << "docker run --privileged=true --net=none"
        for sv in self.shared_volumes:
            c << "-v {0}:{1}".format(sv[0], sv[1])
        c << "--name {0} -id {1}".format(self.name, self.image)

        self.id = local(str(c), capture=True)
        self.is_running = True
        self.local("ip li set up dev lo")
        return 0

    def stop(self):
        ret = local("docker rm -f " + self.name, capture=True)
        self.is_running = False
        return ret

    def pipework(self, bridge, ip_addr, intf_name=""):
        if not self.is_running:
            print colors.yellow('call run() before pipeworking')
            return
        c = CmdBuffer(' ')
        c << "pipework {0}".format(bridge.name)

        if intf_name != "":
            c << "-i {0}".format(intf_name)
        else:
            intf_name = "eth1"
        c << "{0} {1}".format(self.name, ip_addr)
        self.ip_addrs.append((intf_name, ip_addr, bridge))
        return local(str(c), capture=True)

    def local(self, cmd):
        return local("docker exec -it {0} {1}".format(self.name, cmd))


class BGPContainer(Container):

    WAIT_FOR_BOOT = 0
    RETRY_INTERVAL = 5

    def __init__(self, name, asn, router_id, ctn_image_name):
        self.config_dir = "{0}/{1}".format(TEST_BASE_DIR, name)
        local('if [ -e {0} ]; then rm -r {0}; fi'.format(self.config_dir))
        local('mkdir -p {0}'.format(self.config_dir))
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
        if self.is_running:
            self.reload_config()

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

    PEER_TYPE_INTERNAL = 0
    PEER_TYPE_EXTERNAL = 1
    SHARED_VOLUME = '/root/shared_volume'

    def __init__(self, name, asn, router_id, ctn_image_name='goplane',
                 log_level='debug'):
        super(GoPlaneContainer, self).__init__(name, asn, router_id,
                                             ctn_image_name)
        self.shared_volumes.append((self.config_dir, self.SHARED_VOLUME))
        self.vns = []
        self.log_level = 'debug'

    def start_goplane(self):
        c = CmdBuffer()
        c << '#!/bin/bash'
        c << 'goplaned -f {0}/goplaned.conf -l {1} -p > ' \
             '{0}/goplaned.log 2>&1'.format(self.SHARED_VOLUME, self.log_level)

        cmd = 'echo "{0:s}" > {1}/start.sh'.format(c, self.config_dir)
        local(cmd, capture=True)
        cmd = "chmod 755 {0}/start.sh".format(self.config_dir)
        local(cmd, capture=True)
        cmd = 'docker exec -d {0} {1}/start.sh'.format(self.name,
                                                       self.SHARED_VOLUME)
        local(cmd, capture=True)

    def run(self):
        super(GoPlaneContainer, self).run()
        return self.WAIT_FOR_BOOT

    def create_config(self):
        bgp_config = {'Global': {'As': self.asn, 'RouterId': self.router_id}}
        for peer, info in self.peers.iteritems():
            if self.asn == peer.asn:
                peer_type = self.PEER_TYPE_INTERNAL
            else:
                peer_type = self.PEER_TYPE_EXTERNAL

            afi_safi_list = []
            version = netaddr.IPNetwork(info['neigh_addr']).version
            if version == 4:
                afi_safi_list.append({'AfiSafiName': 'ipv4-unicast'})
            elif version == 6:
                afi_safi_list.append({'AfiSafiName': 'ipv6-unicast'})
            else:
                Exception('invalid ip address version. {0}'.format(version))

            if info['evpn']:
                afi_safi_list.append({'AfiSafiName': 'l2vpn-evpn'})
                afi_safi_list.append({'AfiSafiName': 'encap'})
                afi_safi_list.append({'AfiSafiName': 'rtc'})

            n = {'NeighborAddress': info['neigh_addr'].split('/')[0],
                 'PeerAs': peer.asn,
                 'AuthPassword': info['passwd'],
                 'PeerType': peer_type,
                 'AfiSafiList': afi_safi_list}

            if info['passive']:
                n['TransportOptions'] = {'PassiveMode':True}

            if info['is_rs_client']:
                n['RouteServer'] = {'RouteServerClient': True}

            if 'NeighborList' not in bgp_config:
                bgp_config['NeighborList'] = []

            bgp_config['NeighborList'].append(n)

        dplane_config = {'Type': 'netlink', 'VirtualNetworkList': []}
        for info in self.vns:
            dplane_config['VirtualNetworkList'].append({'VNI': info['vni'],
                                                        'VxlanPort': info['vxlan_port'],
                                                        'VtepInterface': info['vtep'],
                                                        'Color': info['color'],
                                                        'MemberInterfaces': info['member']})

        config = {'Bgp': bgp_config, 'Dataplane': dplane_config}

        with open('{0}/goplaned.conf'.format(self.config_dir), 'w') as f:
            print colors.yellow(toml.dumps(config))
            f.write(toml.dumps(config))

    def reload_config(self):
        cmd = 'docker exec {0} /usr/bin/pkill gobgpd -SIGHUP'.format(self.name)
        local(cmd, capture=True)

    def add_vn(self, vni, vtep, color, member, vxlan_port=8472):
        self.vns.append({'vni':vni, 'vtep':vtep, 'vxlan_port':vxlan_port,
                         'color':color, 'member':member})


if __name__ == '__main__':

    parser = OptionParser(usage="usage: %prog [--go-path <gopath>] [prepare|update|clean]")
    parser.add_option("-g", "--go-path", type="string", dest="gopath",
                      help="set go path (DEFAULT: {0})".format(DEFAULT_GOPATH),
                      default=DEFAULT_GOPATH)
    options, args = parser.parse_args()

    # parse via shell
    gopath = local("echo {0}".format(options.gopath), capture=True)

    with shell_env(GOPATH=gopath):

        os.chdir(os.path.abspath(os.path.dirname(__file__)))

        if os.getegid() != 0:
            print "execute as root"
            sys.exit(1)

        if len(args) > 0 and args[0] == 'prepare':
            install_docker_and_tools()
            sys.exit(0)
        elif len(args) > 0 and args[0] == 'update':
            update_goplane()
            sys.exit(0)
        elif len(args) > 0 and args[0] == 'clean':
            for ctn in get_containers():
                if ctn[0] == 'h' or ctn[0] == 'g':
                    local("docker rm -f {0}".format(ctn), capture=True)
            sys.exit(0)

        h1 = Container(name='h1', image='osrg/gobgp')
        h2 = Container(name='h2', image='osrg/gobgp')
        h3 = Container(name='h3', image='osrg/gobgp')
        h4 = Container(name='h4', image='osrg/gobgp')
        h5 = Container(name='h5', image='osrg/gobgp')
        h6 = Container(name='h6', image='osrg/gobgp')
        hosts = [h1, h2, h3, h4, h5, h6]

        g1 = GoPlaneContainer(name='g1', asn=65001, router_id='192.168.0.1')
        g2 = GoPlaneContainer(name='g2', asn=65002, router_id='192.168.0.2')
        g3 = GoPlaneContainer(name='g3', asn=65003, router_id='192.168.0.3')
        bgps = [g1, g2, g3]

        for idx, ctn in enumerate(bgps):
            ctn.add_vn(10, 'vtep10', 10+idx, ['eth2', 'eth3'])

        ctns = bgps + hosts
        [ctn.run() for ctn in ctns]

        br01 = Bridge(name='br01', subnet='192.168.10.0/24')
        [br01.addif(ctn, 'eth1') for ctn in bgps]

        for lfs, rfs in itertools.permutations(bgps, 2):
            lfs.add_peer(rfs, evpn=True)

        br02 = Bridge(name='br02', with_ip=False)
        br02.addif(g1, 'eth2')
        br02.addif(h1, 'eth1')

        br03 = Bridge(name='br03', with_ip=False)
        br03.addif(g2, 'eth2')
        br03.addif(h2, 'eth1')

        br04 = Bridge(name='br04', with_ip=False)
        br04.addif(g3, 'eth2')
        br04.addif(h3, 'eth1')

        br02 = Bridge(name='br05', with_ip=False)
        br02.addif(g1, 'eth3')
        br02.addif(h4, 'eth1')

        br03 = Bridge(name='br06', with_ip=False)
        br03.addif(g2, 'eth3')
        br03.addif(h5, 'eth1')

        br04 = Bridge(name='br07', with_ip=False)
        br04.addif(g3, 'eth3')
        br04.addif(h6, 'eth1')

        [ctn.local("ip a add 10.10.10.{0}/24 dev eth1".format(i+1)) for i, ctn in enumerate(hosts)]

        [ctn.start_goplane() for ctn in bgps]
