#MIT License

#Copyright (c) 2017 Manoj Pandey

#Permission is hereby granted, free of charge, to any person obtaining a copy
#of this software and associated documentation files (the "Software"), to deal
#in the Software without restriction, including without limitation the rights
#to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
#copies of the Software, and to permit persons to whom the Software is
#furnished to do so, subject to the following conditions:

#The above copyright notice and this permission notice shall be included in all
#copies or substantial portions of the Software.

#THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
#IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
#FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
#AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
#LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
#OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
#SOFTWARE.

#!/usr/bin/env python
# -*- coding: utf-8 -*-
# original author: @manojpandey
# rework author: @tartokanian

import codecs
import psutil
import os
import random
import time
import math
import re
from collections import Counter
from textwrap import wrap

MOD = 16 # bit size
ivList = [] # stores all IV bytes
ivPosList = random.SystemRandom().sample(range(16), 16) # creates a list of random, unique numbers for byte positions.
start_time = time.time()

encryptionSample = open("C:\\Users\\Max Allan\\Documents\\encryptionSamples\\16\\encryptionSample16-10.txt", "r") # reading the packet sample

def KSA(key):
    key_length = len(key)
    # create the array "S"
    S = list(range(MOD))  # [0 - MOD]
    j = 0
    for i in range(MOD):
        j = (j + S[i] + key[i % key_length]) % MOD
        S[i], S[j] = S[j], S[i]  # swap values

    return S

def PRGA(S):
    i = 0
    j = 0
    while True:
        i = (i + 1) % MOD
        j = (j + S[i]) % MOD

        S[i], S[j] = S[j], S[i]  # swap values
        k = S[(S[i] + S[j]) % MOD] + S[(S[i] + S[i]) % MOD] # new formula adds the original S value with another i iteration of S.
        yield k

def get_keystream(key):
    ''' Takes the encryption key to get the keystream using PRGA
        return object is a generator
    '''
    S = KSA(key)
    return PRGA(S)

def encrypt_logic(key, plaintext):
    ''' :key -> encryption key used for encrypting, as hex string
        :text -> array of unicode values/ byte string to encrpyt/decrypt
    '''
    # For plaintext key, use this
    key = [ord(c) for c in key]
    # If key is in hex:
    # key = codecs.decode(key, 'hex_codec')
    # key = [c for c in key]
    keystream = get_keystream(key)

    res = []
    for c in plaintext:
        val = ("%02X" % (c ^ next(keystream)))  # XOR and taking hex
        res.append(val)

    increment = 0
    for i in range(16): # loops for packet size
        ivPos = ivPosList[increment] # goes to the next item in the position list
        IV = ("%02X" % (next(keystream))) # continues the keystream and generates a byte
        ivList.append(IV) # appends the byte to a list for removal later
        res.insert(ivPos, IV) # inserts the byte with a corresponding position from ivPosList
        increment = increment + 1
    return ''.join(res)

def entropy(ciphertext):
    p, lns = Counter(ciphertext), float(len(ciphertext))
    return -sum( count/lns * math.log(count/lns, 2) for count in p.values())

def encrypt(key, plaintext):
    ''' :key -> encryption key used for encrypting, as hex string
        :plaintext -> plaintext string to encrypt
    '''
    plaintext = [ord(c) for c in plaintext]
    return encrypt_logic(key, plaintext)

def decrypt(key, ciphertext):
    ''' :key -> encryption key used for encrypting, as hex string
        :ciphertext -> hex encoded ciphered text using RC4
    '''
    wrapciph = wrap(ciphertext, 2) # splits the ciphertext back into bytes
    for element in ivList: # loop through ivList and remove each one from ciphertext
      if element in wrapciph:
         wrapciph.remove(element)
    wrapciph = ''.join(wrapciph) # join remaining bytes together
    ciphertext = codecs.decode(wrapciph, 'hex_codec') # used to be ciphertext
    res = encrypt_logic(key, ciphertext)
    return codecs.decode(res, 'hex_codec').decode('utf-8')

def main():
    key = 'Aenean eleifend.'
    plaintext = encryptionSample.read()
    # encrypt the plaintext, using key and RC4 algorithm
    ciphertext = encrypt(key, plaintext)
    print('plaintext:', plaintext)
    print('ciphertext:', ciphertext)
    print("Encryption time: ", time.time() - start_time)

    print("Entropy: ", entropy(ciphertext))

    # change ciphertext to string again
    decrypted = re.sub(r'\W+', ' ', decrypt(key, ciphertext)) # removes null spaces left by IV removal
    print('decrypted:', decrypted)
    print("Decryption time: ", time.time() - start_time)

if __name__ == '__main__':
    main()
    process = psutil.Process(os.getpid()) # grabs process details
    print("\nMemory used: ", process.memory_percent()) # CPU memory usage
    print("\nCPU Time: ", process.cpu_times()) # CPU clock times