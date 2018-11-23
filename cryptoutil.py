#!/usr/bin/python3

from Crypto.Cipher import AES

encryptionKey = "passyourwordssss"
IV = "whatsthedealwith"


def encrypt(message:str) -> str:
    """[summary]
    
    Arguments:
        message {str} -- [description]
    
    Returns:
        str -- [description]
    """

    global encryptionKey
    global IV
    
    encryptor = AES.new(encryptionKey.encode('utf-8'), AES.MODE_CFB, IV=IV.encode('utf-8'))
    enc = encryptor.encrypt(bytearray(message.encode('utf-8')))
    return enc


def decrypt(command: str) -> str:
    """[summary]
    
    Arguments:
        command {str} -- [description]
    
    Returns:
        str -- [description]
    """

    global encryptionKey
    global IV
    decryptor = AES.new(encryptionKey.encode('utf-8'), AES.MODE_CFB, IV=IV.encode('utf-8'))
    plain = decryptor.decrypt(bytearray(command)).decode('utf-8')
    return plain
