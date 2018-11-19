#!/usr/bin/python3
#import bkcrypt

def message_to_bits(message) -> str:
    #Create the string that will hold all the bits.
    messageData =""
    #For each character in the string
    for c in message:
        #Get the ASCII value of each character, and convert that value to binary
        #Also zfill it to have a total length of 8 characters (needed for
        # packetizing later)
        var = bin(ord(c))[2:].zfill(8)
        #Concatenate with the placeholder
        messageData += str(var)
    return messageData
'''
def file_to_bits(filePath) -> str:
    #Open the file for modifications
    file = open(filePath, "rb")
    #Create a placeholder
    binaryString = ""
    #Convert whatever is in the file to bytes
    readFile = bytearray(file.read())
    fileName = filePath.split("/")
    fileName = encrypt(fileName[len(fileName) - 1])
    #Craft a header
    header = message_to_bits(fileName+"00000000");#0s are so we can tell its the file name
    #Add the header to the string
    binaryString += header
    #convert bytes into bits
    for bit in readFile:
        binaryString += bin(bit)[2:].zfill(8)
    return binaryString
'''