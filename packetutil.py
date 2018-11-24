#!/usr/bin/python3

from scapy.all import *

def packatizer(msg ,TTL:int,addr:tuple):
    """Crafts a packets using scapy and returns a list of TCP packet
    
    Arguments:
        msg {list || str} -- list of characters that will be stored inside the sequence
        number of a TCP packet
        TTL {int} -- used for packet identification durring packet sniffing
        addr {tuple} -- the IP([0]) and PORT([1]) packet is being sent to
    
    Returns:
        [list] -- list of TCP scapy.packets
    """

    packets = []
    # If the length of the number is larger than what is allowed in one packet, split it
    counter = 0

    if(type(msg) is str):       # If not an array (if there is only one packet.)
        packets.append(craft(msg,TTL,addr))
    elif(type(msg) is list):    # If an array (if there is more than one packet)
        while (counter < len(msg)):
            packets.append(craft(msg[counter],TTL,addr))
            counter = counter + 1
    return packets


def craft(data: str,TTL:int,addr:tuple) -> IP:
    """Crafts a packet using scapy and returns a TCP packet
    
    Arguments:
        data {str} -- characters that will be stored inside the sequence number of a TCP packet
        TTL {int} -- used for packet identification durring packet sniffing
        addr {tuple} -- the IP([0]) and PORT([1]) packet is being sent to
    
    Returns:
        IP -- TCP scapy.packet
    """

    packet = IP(dst=addr[0], ttl=TTL)/TCP( dport=addr[1],seq=int(str(data), 2), flags="E")
    return packet
