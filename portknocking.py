#!/usr/bin/python3

# https://gist.github.com/snj/9382c63ad49050e1b9ba

from scapy.all import *
import time


def knock(mode:int,ip:str):
    """[summary]
    
    Arguments:
        mode {int} -- [description]
        ip {str} -- [description]
    """

    if(mode==0):
        cports = [8503, 8504, 8505]
        SYN = IP(dst="192.168.0.45")/UDP(dport=cports)
    elif(mode==1):
        oports = [8500, 8501, 8502]
        SYN = IP(dst="192.168.0.45")/UDP(dport=oports)
     
    send(SYN, verbose=False)