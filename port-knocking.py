#!/usr/bin/python

# https://gist.github.com/snj/9382c63ad49050e1b9ba

from scapy.all import *
import time

def knock(ports):
    print "[*] Knocking on ports "+str(ports)
    for dport in range(0, len(ports)):
        ip = IP(dst = "192.168.0.11")
        SYN = ip/TCP(dport=ports[dport], flags="S", window=14600, options=[('MSS',1460)])
        send(SYN)

def execKnock(ports):
    knock(ports)
    print "Port opened"
    time.sleep(10)
    print "Port closed"

oports = [7303,40303,33528]
cports = [33528,40303,7303]
execKnock(oports)
