#!/usr/bin/env python3

import os
from colorama import Fore, Style
from colorama import init as coloramainit

__author__ = 'Youssef Seddik'
__version__ = '0.1'
__license__ = 'MIT License'

#GLOBAL VARIABLES
##Console Colors
B = Fore.BLUE
R = Fore.RED
G = Fore.GREEN
BR = Style.BRIGHT
RA = Style.RESET_ALL

def menu():
    '''
    Displays a numbered menu and prompts the user for a choice in input
    Each choice's code is in the main function
    '''

    print(R + BR +"   -----------   Autopent Menu   ---------- " + RA)
    print(R + BR +"               -----------------            " + RA)
    print(R + BR +"  |       99)" + RA + G + " Exit Program           " + R + BR + "      |" + RA)
    print(R + BR +"  |       98)" + RA + G + " Network Interfaces     " + R + BR + "      |" + RA)
    print(R + BR +"  |       97)" + RA + G + " Change MAC address     " + R + BR + "      |" + RA)
    print(R + BR +"  |       0)" + RA + G + "  Display Help           " + R + BR + "      |" + RA)
    print(R + BR +"  |       1)" + RA + G + "  Enable Monitor Mode    " + R + BR + "      |" + RA)
    print(R + BR +"  |       2)" + RA + G + "  Disable Monitor Mode   " + R + BR + "      |" + RA)
    print(R + BR +"  |       3)" + RA + G + "  Scan for Networks      " + R + BR + "      |" + RA)
    print(R + BR +"  |       4)" + RA + G + "  Discover Clients       " + R + BR + "      |" + RA)
    print(R + BR +"  |       5)" + RA + G + "  Send Deauth Attack     " + R + BR + "      |" + RA)
    print(R + BR +"  |       6)" + RA + G + "  Evil Tween Attack      " + R + BR + "      |" + RA)
    print(R + BR +"  |       7)" + RA + G + "  Crack WEP Key          " + R + BR + "      |" + RA)
    print(R + BR +"  |       8)" + RA + G + "  Crack WPA-PSK Key      " + R + BR + "      |" + RA)
    print(R + BR +"  |       9)" + RA + G + "  MITM Attack            " + R + BR + "      |" + RA)
    print(R + BR +"  |       10)" + RA + G + " DNS Spoof Attack       " + R + BR + "      |" + RA)
    print(R + BR +"   ---------------------------------------- " + RA)
    inp = int(input(B + BR + "--> " + RA))
    return inp

def main():
    '''
    Contains actions depending on user selection of a choice as in the above
    menu
    '''
    coloramainit()
    while True:
        choice = menu()
        if choice == 99:
            print("Bye")
            break
        if choice == 98:
            print()
            print(B + "[+]    The following network interfaces are available on this machine" + RA)
            os.system('airmon-ng')
        if choice == 97:
            interface = str(input(B + "[(1/2)-->] Enter the networking interface name: " + RA))
            mac = str(input(B + "[(2/2)-->] Enter the desired MAC address: " + RA))
            os.system('./autopent.py -cm -i ' + interface + ' -m ' + mac)
        if choice == 0:
            os.system('clear')
            os.system('./autopent.py --help')
        if choice == 1:
            interface = str(input(B + "[(1/1)-->] Enter the networking interface name: " + RA))
            os.system('./autopent.py -e -i' + interface)
        if choice == 2:
            interface = str(input(B + "[(1/1)-->] Enter the networking interface name: " + RA))
            os.system('./autopent.py -d -i ' + interface)
        if choice == 3:
            channel = str(input(B + "[(1/2)-->] Enter the channel number(1 to 11 or 99 for all channels): " + RA))
            interface = str(input(B + "[(2/2)-->] Enter the networking interface name: " + RA))
            os.system('./autopent.py -s -c ' + channel + ' -i' + interface)
        if choice == 4:
            bssid = str(input(B + "[(1/3)-->] Enter the AP's BSSID: " + RA))
            channel = str(input(B + "[(2/3)-->] Enter the AP's channel number: " + RA))
            interface = str(input(B + "[(3/3)-->] Enter the networking interface name: " + RA))
            os.system('./autopent.py -dc -c ' + channel + ' -i ' + interface + ' -b ' + bssid)
        if choice == 5:
            bssid = str(input(B + "[(1/3)-->] Enter the AP's BSSID: " + RA))
            interface = str(input(B + "[(2/3)-->] Enter the networking interface name: " + RA))
            bssidc = str(input(B + "[(3/3)-->] Enter the Client BSSID(press Enter if none): " + RA))
            if bssidc == '':
                os.system('./autopent.py -sd ' + '-i ' + interface + ' -b ' + bssid)
            elif bssidc != '':
                os.system('./autopent.py -sd ' + '-i ' + interface + ' -b ' + bssid + ' -bc ' + bssidc)
        if choice == 6:
            bssid = str(input(B + "[(1/4)-->] Enter the AP's BSSID: " + RA))
            interface = str(input(B + "[(2/4)-->] Enter the networking interface name: " + RA))
            essid = str(input(B + "[(3/4)-->] Enter the desired ESSID: " + RA))
            channel = str(input(B + "[(4/4)-->] Enter the desired channel: " + RA))
            os.system('./autopent.py -ev ' + '-i ' + interface + ' -b ' + bssid + ' -ed ' + essid + ' -c ' + channel)
        if choice == 7:
            bssid = str(input(B + "[(1/4)-->] Enter the AP's BSSID: " + RA))
            interface = str(input(B + "[(2/4)-->] Enter the networking interface name: " + RA))
            channel = str(input(B + "[(3/4)-->] Enter the AP's channel number: " + RA))
            bssidc = bssidc = str(input(B + "[(4/4)-->] Enter a connected client's BSSID: " + RA))
            os.system('./autopent.py -ce ' + '-i ' + interface + ' -b ' + bssid + ' -c ' + channel + ' -bc ' + bssidc)
        if choice == 8:
            bssid = str(input(B + "[(1/3)-->] Enter the AP's BSSID: " + RA))
            interface = str(input(B + "[(2/3)-->] Enter the networking interface name: " + RA))
            channel = str(input(B + "[(3/3)-->] Enter the AP's channel number: " + RA))
            os.system('./autopent.py -ca ' + '-i ' + interface + ' -b ' + bssid + ' -c ' + channel)
        if choice == 9:
            bssid = str(input(B + "[(1/4)-->] Enter the AP's BSSID: " + RA))
            interface = str(input(B + "[(2/4)-->] Enter the networking interface name: " + RA))
            channel = str(input(B + "[(3/4)-->] Enter the AP's channel number: " + RA))
            essid = str(input(B + "[(4/4)-->] Enter the desired ESSID: " + RA))
            os.system('./autopent.py -it ' + '-i ' + interface + ' -b ' + bssid + ' -c ' + channel + ' -ed ' + essid)
        if choice == 10:
            bssid = str(input(B + "[(1/4)-->] Enter the AP's BSSID: " + RA))
            interface = str(input(B + "[(2/4)-->] Enter the networking interface name: " + RA))
            channel = str(input(B + "[(3/4)-->] Enter the AP's channel number: " + RA))
            essid = str(input(B + "[(4/4)-->] Enter the desired ESSID: " + RA))
            os.system('./autopent.py -ds ' + '-i ' + interface + ' -b ' + bssid + ' -c ' + channel + ' -ed ' + essid)

if __name__ == "__main__":
    main()

