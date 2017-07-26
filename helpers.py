#!/usr/bin/env python3

import csv
import re
from subprocess import Popen, PIPE
from colorama import Fore, Style
from colorama import init as coloramainit

from structures import Client, Target

__author__ = 'Youssef Seddik'
__version__ = '0.1'
__license__ = 'MIT License'


#Console colors
B = Fore.BLUE
R = Fore.RED
G = Fore.GREEN
BR = Style.BRIGHT
RA = Style.RESET_ALL

class Helpers():
    """
    A set of useful methods, that do not have a relation with
    pentesting at all, but help with the flow of the tool.
    """

    def __init__(self):
        coloramainit()

    def check_availability(self, prog):
        '''Check program availability on the system'''

        proc = Popen(['which', prog], stdout=PIPE, stderr=PIPE)
        txt = proc.communicate()
        if txt[0].strip() == b'':
            return False
        elif txt[0].strip() != b'':
            return True

    def check_mac(self, mac):
        '''
        Takes a MAC address in input, checks its length and returns a boolean
        value depending on that.
        '''
        
        if len(mac) == 17:
            return True
        else:
            return False

    def args_error(self, **kwargs):
        '''Prints warnings about missing options in the command line'''
        
        if kwargs:
            msg = ""
            for i, j in kwargs.items():
                if i == "bssid" and j == False:
                    return R + "[!]    Target BSSID not specified or"\
                            " invalid; specify it with " + B + "-b" + R + ""\
                            " option" + RA
                if i == "bssidc" and j == False:
                    return R + "[!]    Client BSSID not specified"\
                            " or invalid; specify it with " + B + "-bc" + R + ""\
                            + " option" + RA
                if i == "channel" and j == False:
                    return R + "[!]    Channel not specified"\
                            " or invalid; specify it with " + B + "-i" + R + ""\
                            + " option" + RA
                if i == "interface" and j == False:
                    return R + "[!]    Network Interface not specified"\
                            " or invalid; specify it with " + B + "-i" + R + ""\
                            + " option" + RA
                if i == "macaddr" and j == False:
                    return R + "[!]    MAC address not specified"\
                            " or invalid; specify it with " + B + "-m" + R + ""\
                            + " option" + RA
                if i == "essid" and j == False:
                    return R + "[!]    ESSID not specified or invalid; specify"\
                            " it with "+ B + "-ed" + R + " option" +RA

    def csv_parser1(self, filename):
        '''
        Gets a csv filename in input, and outputs a tuple 
        with two lists: a list of targets and a list of clients.
        This csv parser is used to parse the list of networks scanned.
        '''
        
        targets = []
        clients = []
        try:
            hit_clients = False
            with open(filename, newline='') as csvfile:
                targetreader = csv.reader(csvfile, delimiter=',')
                for row in targetreader:
                    if len(row) < 2:
                        continue
                    if not hit_clients:
                        if row[0].strip() == 'Station MAC':
                            hit_clients = True
                            continue
                        if len(row) < 14:
                            continue
                        if row[0].strip() == 'BSSID':
                            continue
                        enc = row[5].strip()
                        wps = False
                        if enc.find('WPA') == -1 and enc.find('WEP') == -1 and enc.find('OPN') == -1:
                            continue
                        if enc == "WPA2WPA" or enc == "WPA2 WPA":
                            enc = "WPA2"
                        if enc == "OPN" or enc.find('OPN') == 1:
                            enc = "OPEN"
                        if enc == "WEP" or enc.find('WEP') == 1:
                            enc == "WEP"
                        if len(enc) > 4:
                            enc = enc[4:].strip()
                        power = int(row[8].strip())
                        ssid = row[13].strip()
                        ssidlen = int(row[12].strip())
                        ssid = ssid[:ssidlen]
                        if power < 0: power += 100
                        t = Target(row[0].strip(), power, row[10].strip(),
                                   row[3].strip(), enc, ssid)
                        #t.wps = wps to add also in the class definition
                        targets.append(t)
                    else:
                        if len(row) < 6:
                            continue
                        bssid = re.sub(r'[^a-zA-Z0-9:]', '', row[0].strip())
                        station = re.sub(r'[^a-zA-Z0-9]', '', row[5].strip())
                        power = row[3].strip()
                        if station != 'notassociated':
                            c = Client(bssid, station, power)
                            clients.append(c)
        except IOError as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))
            return ([], [])
        return (targets, clients)

    def csv_parser2(self, filename):
        '''
        Takes a csv file in input and outputs a list of clients.
        This csv parser is used to return the list of clients connected to
        a network.
        '''

        clients = []
        try:
            with open(filename, newline='') as csvfile:
                targetreader = csv.reader(csvfile, delimiter=',')
                for row in targetreader:
                    if "BSSID" in row:
                        continue
                    if len(row) > 7:
                        continue
                    if len(row) == 0:
                        continue
                    if "Station MAC" in row:
                        continue
                    mac = row[0].strip()
                    power = int(row[3].strip())
                    station = row[5].strip()
                    c = Client(mac, station, power)
                    clients.append(c)
        except IOError as e:
            print("I/O error({0}): {1}".format(e.errno, e.strerror))
            return []
        return clients

