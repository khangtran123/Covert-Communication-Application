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
    SYN = IP(dst="192.168.0.45")/UDP(dport=ports)
    send(SYN, verbose=False)


def knockOpen():
    """[summary]
    """

    ports = [8500, 8501, 8502]
    knock(ports)
    print("[*] Port closed")


def knockClose():
    """[summary]
    """

    ports = [8503, 8504, 8505]
    knock(ports)
    print("[*] Port opened")
