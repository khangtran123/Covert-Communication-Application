#!/usr/bin/python3

from Crypto.Cipher import AES

encryptionKey = b'passyourwordssss'
IV = b'whatsthedealwith'


def encrypt(plaintext:str) -> str:
    """ Encrypt data with the key and the parameters set at initialization.
    
    Arguments:
        plaintext {str} -- The piece of data to encrypt.
    
    Returns:
        str -- the encrypted data, as a byte string
    """

    global encryptionKey
    global IV
    
    encryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    enc = encryptor.encrypt(bytearray(plaintext.encode('utf-8')))
    return enc


def decrypt(ciphertext: str) -> str:
    """Decrypt data with the key and the parameters set at initialization.
    
    Arguments:
        ciphertext {str} -- The piece of data to decrypt.
    
    Returns:
        str -- the decrypted data (byte string, as long as *ciphertext*)
    """

    global encryptionKey
    global IV

    decryptor = AES.new(encryptionKey, AES.MODE_CFB, IV=IV)
    plain = decryptor.decrypt(bytearray(ciphertext)).decode('utf-8')
    return plain
