#!/usr/bin/env python

import base64

import hashlib
from Crypto import Random
from Crypto.Util.Padding import pad
#from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES

BS = 16
#pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)
#pad = lambda s : s[:-ord(s[len(s)-1:])]
unpad = lambda s : s[0:-s[-1]]


class AESCipher:

    def __init__(self, key):
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt( self, raw ):
        raw = pad(raw,16,style='pkcs7')
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))
        #return base64.b64encode( iv + cipher.encrypt(raw) )

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC,iv)
        return unpad(cipher.decrypt(enc[16:]))

'''
cipher = AESCipher('mysecretpassword')
encrypted = cipher.encrypt('Secret Message A')
decrypted = cipher.decrypt(encrypted)
print(encrypted)
print(decrypted)
'''
