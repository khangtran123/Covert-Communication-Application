#!/usr/bin/python3

from scapy.all import *

def packatizer(msg ,TTL:int,addr:tuple):
    """[summary]

    Arguments:
        msg {[type]} -- [description]

    Returns:
        [type] -- [description]
    """

    # Create the packets array as a placeholder.
    packets = []
    # If the length of the number is larger than what is allowed in one packet, split it
    counter = 0

    # If not an array (if there is only one packet.)
    if(type(msg) is str):
        packets.append(craft(msg,TTL,addr))
    # If an array (if there is more than one packet)
    elif(type(msg) is list):
        while (counter < len(msg)):
            packets.append(craft(msg[counter],TTL,addr))
            counter = counter + 1
    return packets


def craft(data: str,TTL:int,addr:tuple) -> IP:
    """[summary]

    Arguments:
        data {str} -- [description]

    Returns:
        IP -- [description]
    """

    # The payload contains the unique password, UID, position number and total.
    packet = IP(dst=addr[0], ttl=TTL)/TCP( dport=addr[1],seq=int(str(data), 2), flags="E")
    return packet
