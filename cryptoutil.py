#!/usr/bin/python3

from Crypto.Cipher import AES

encryptionKey = "passyourwordssss"
IV = "whatsthedealwith"


def encrypt(message: str) -> str:
    """[summary]
    
    Arguments:
        message {str} -- [description]
    
    Returns:
        str -- [description]
    """

    global encryptionKey
    global IV
    encryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    return encryptor.encrypt(message)


def decrypt(command: str) -> str:
    """[summary]
    
    Arguments:
        command {str} -- [description]
    
    Returns:
        str -- [description]
    """

    global encryptionKey
    global IV
    decryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(command)
    return plain
