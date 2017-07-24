Tutorial
========

If you want to use the command line directly, this is a simple tutorial about how to use Autopent to conduct a set of attacks on targeted wireless networks.

Alternatively, you can use the command line menu interface by invoking g the command:

    ``./main.py``

During any step of this tutorial, help can be displayed using the following command:

    ``./autopent.py -h``

Activate/Deactivate Monitor Mode
--------------------------------

    Let's assume that our wireless networking card's name(displayed by the *ifconfig* tool) is *wlan0*, we issue the following command to activate monitor mode:

    ``./autopent.py -e -i wlan0``

    This will actually kill all annoying processes that would interrupt the process of capturing packets. It will cut any established connection to a network using other interfaces(You have been warned! ;-)).

    In order to deactivate monitor mode(which must be done in the end of the pentest), we issue the following command(assuming that monitor interface is *mon0*):

    ``./autopent.py -d -i mon0``

Scan for Networks
-----------------
    
    Monitor mode must be enabled.

    In order to scan for nearby networks, we issue the following command: 

    ``./autopent.py -s -i mon0 -c 99``

    We specify the channel number using the *-c* option, which must be a number from 1 to 11 for a specific channel scan; or 99 to scan for all channels.

    After completion of the scan, a list of respective networks, with their SSIDs, BSSIDs, power level, channel and encryption will be displayed.

Discover connected Clients
--------------------------

    This is an crucial step in the pentesting process, as it helps target precise clients connected to the target network.

    In order to launch this type of attack, you need to note the targetted wireless network's BSSID as well as its operating channel.

    Then you can use the following command, replacing the channel number and BSSID address by the wanted ones:

    ``./autopent.py -dc -c 1 -b 12:34:56:78:AB:CD``

Attack a Network
----------------

    Before launching an attack, you should have made a choice regarding the wireless network to attack, and note its BSSID, its channel and in the best case the physical address of a connected client to it.

    There's a large set of attacks to launch, we demonstrate two attacks as an example:
        * WEP key recovery attack:
            The wireless network must operate in WEP security mode, and at least one connected clients to it.

            We issue the following command as an example:

            ``./autopent.py -ce -b 12:34:56:78:AB:CD -c 1 -bc AB:CD:12:34:56:78 -i mon0``

            Where *-b* specifies the network MAC address; *-bc* the conected client's MAC address.

            After the tool finishes, which may take some time, the recovered key is then displayed.
        * Evil Tween attack:
            To launch this attack, we need: the ESSID which is the displayed name of the network we want to target, specified using the *-ed* option; the BSSID of the target network, specified using the *-b* option; the network's channel, specified using the *-c* option; and of course the networking interface we want to use, specified using the *-i* option.

            Then, as an example, we type in the following command:

            ``./autopent.py -ev -i mon0 -b 12:34:56:78:AB:CD -e TargetWifi -c 1 -bc AB:CD:12:34:56:78``

            After typing this command, *Wireshark* will open and display captured packets.

Other possible Attacks
----------------------

        * MITM(Man In The Middle) attack
        * DNS spoofing attack
        * Deauthentication DoS
        * Client deauthentication
        * Change wireless card physical(MAC) address, to join a MAC filtered wireless network.

