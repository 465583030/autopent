# Autopent

|docs|

Autopent is an automated command line pentesting tool for wireless networks. Written entirely in Python, it tests the presence of some common vulnerabilities in networks' security, and therefore may be used in a penetration test to assess security level.

It contains some basic attacks(WEP and WPA-PSK key cracking,...) and some advanced attacks(MITM attack and DNS spoofing attack).

Autopent's ethical goal is to urge and prompt people to think about the security they use in their daily Wi-FI usage.  
  
## Usage

Download the source code into your Linux machine by running the following command:
```
git clone https://github.com/the11/autopent.git 
```

Because of commands on networking interfaces, Autopent requires to be run as **root**. No problem if you forget it, as Autopent will return an error message stating the need of super user privilege. 

* When launching the tool, there are two options:

1. Using a command line based menu, by running the following line in a command prompt:
```
python3 main.py
```

2. Using the autopent command line tool directly by specifying command options and flags,
For example in order to activate monitor mode using short options, this is the command syntax(if autopent.py file permission for execution is set and assuming **wlan0** is your wireless networking interface name):
```
./autopent.py -e wlan0
```
Alternatively, if you want to use long options(assuming the same assumptions as before):
```
./autopent.py --enable-mon wlan0
```

* Help can be displayed anytime, containing the tool's help message and options' descriptions, by running the following line in a command prompt:
```
./autopent.py -h
```

## Dependencies

A set of tools and programs(100% open source and free) are required to run Autopent. 

The tool is coded to run a check for required tools in the moment of execution, and so it will display error messages about missing requirements and exit.

A list of requirements is available in the *Requirements* documentation section.

.. |docs| image:: https://readthedocs.org/projects/autopent/badge/?version=latest
    :alt: Documentation Status
    :scale: 100%
    :target: http://autopent.readthedocs.io/en/latest/?badge=latest
