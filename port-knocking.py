#!/usr/bin/python3

# https://gist.github.com/snj/9382c63ad49050e1b9ba

from scapy.all import *
import time


def knock(ports):
    """[summary]
    
    Arguments:
        ports {[type]} -- [description]
    """

    print("[*] Knocking on ports")
    for dport in range(0, len(ports)):
        ip = IP(dst="192.168.0.11")
        SYN = ip/UDP(dport=ports[dport], flags="S",
                     window=14600, options=[('MSS', 1460)])
        send(SYN)


def knockOpen():
    """[summary]
    """

    cports = [4444, 5555, 6666]
    knock(cports)
    print("[*] Port closed")


def knockClose():
    """[summary]
    """

    oports = [1111, 2222, 3333]
    knock(oports)
    print("[*] Port opened")
