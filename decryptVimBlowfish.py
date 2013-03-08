#!/usr/bin/env python
# -*- coding: UTF-8 -*-

import hashlib
from Crypto.Cipher import Blowfish
import struct


filename = 'file'
password = 'test'


fd = open(filename, 'rb')
myBuffer = fd.read()
fd.close()

header = myBuffer[:12] # should be "VimCrypt~02!"
assert header == 'VimCrypt~02!', 'This is not a Vim-blowfish-encrypted file.'

salt = myBuffer[12:20]
iv = myBuffer[20:28]
contents = myBuffer[28:]


def getKey(password, salt):
    # Process the key 1000 times.  (called "Key stretching")
    key = hashlib.sha256(password + salt).hexdigest()

    for i in xrange(1000):
        if i < 5:
            print " key:", key
        key = hashlib.sha256(key + salt).hexdigest()

    print " key:", key
    return key;


def flipEndian(inData):
    outData = ''
    for i in xrange(0, len(inData), 4):
        outData += inData[i+3] + inData[i+2] + inData[i+1] + inData[i]
    return outData


key = getKey(password, salt)
binKey = key.decode('hex')

#Blowfish.block_size = 64
#bf = Blowfish.new(binKey, mode=Blowfish.MODE_CFB, IV=iv_be*8, segment_size=8)
#bf = Blowfish.new(binKey, mode=Blowfish.MODE_OFB, IV=iv_be)
#bf = Blowfish.new(binKey, mode=Blowfish.MODE_OFB, IV=iv_be)

bf = Blowfish.new(binKey)

# Initialize the keystream:
iv_be = flipEndian(iv)
keystream_be = bf.encrypt( iv_be*8 )
keystream = flipEndian(keystream_be)

## TODO: FIXME:  This only works for the first block:
cLen = min(len(contents), len(keystream))
results = []
for i in xrange(cLen):
    results.append( ord(contents[i]) ^ ord(keystream[i]))

print ''.join(map(lambda x: chr(x), results))


