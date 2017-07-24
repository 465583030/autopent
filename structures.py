#!/usr/bin/env python3

class Target:
    '''
    Data structure for a target: an Access Point - AP
    '''

    def __init__(self, bssid, power, data, channel, encryption, ssid):
        self.bssid = bssid
        self.power = power
        self.data = data
        self.channel = channel
        self.encryption = encryption
        self.ssid = ssid
        self.key = ''

class Client:
    '''
    Data structure for an AP' client - connected to the AP
    '''

    def __init__(self, bssid, station, power):
        self.bssid = bssid
        self.station = station
        self.power = power

