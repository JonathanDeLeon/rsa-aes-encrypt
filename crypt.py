#!/usr/bin/env python3
# Jonathan De Leon
# CSCI 531 Applied Cryptography
# April, 2021

import sys
import random
import math
import json
import hashlib
from Crypto.Cipher import AES
from Crypto.Util import Counter


#########################
### Encryption Tools ####
#########################

# Encrypt message using AES CTR Mode and 256-bit key
def aes_encrypt(message, key):
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message


# Reads files and encrypts contents with AES
def encrypt_file(file_name, key):
    with open(file_name, 'r') as f:
        plaintext = f.read()
    encrypted_message = aes_encrypt(plaintext, key)
    return encrypted_message

# Util method to read from a json file - used for RSA pub/prv keys
def read_json_file(file_name):
    with open(file_name, 'r') as f:
        return json.loads(f.read())


# Encrypt a message using RSA
# message must be a byte string and not a normal string, encode utf-8 if regular string
def rsa_encrypt(message, key_file_name):
    public_key = read_json_file(key_file_name)
    payload = int.from_bytes(message, 'big', signed=False)
    encrypted_message = pow(payload, int(public_key['e']), int(public_key['n']))
    return encrypted_message.to_bytes(max(1, math.ceil(encrypted_message.bit_length() / 8)), 'big')

#########################
### Decryption Tools ####
#########################

def decrypt_file(file_name):
    with open(file_name, 'rb') as f:
        ciphertext = f.read()
    
    if len(ciphertext) < 256:
        raise Exception('Something went wrong, file has unexpected length')
    
    key_index = len(ciphertext) - 256
    return (ciphertext[:key_index], ciphertext[key_index:])

def rsa_decrypt(message, key_file_name):
    private_key = read_json_file(key_file_name)
    payload = int.from_bytes(message, 'big', signed=False)
    decrypted_message = pow(payload, int(private_key['d']), int(private_key['n']))
    return decrypted_message.to_bytes(max(1, math.ceil(decrypted_message.bit_length() / 8)), 'big')

def aes_decrypt(message, key):
    ctr = Counter.new(128)
    cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
    decrypted_message = cipher.decrypt(message)
    return decrypted_message.decode('utf-8') 


sys_random = random.SystemRandom()
if __name__ == "__main__":

    if len(sys.argv) > 4:
        encryption = False
        if sys.argv[1] == '-e':
            encryption = True

        key_file, input_file, out_file = sys.argv[2], sys.argv[3], sys.argv[4]

        if encryption is True:
            print ('-'*20+' Encrypting message '+'-'*20)
            # hash random key using sha-256 to get 32-byte key 
            rand_key = sys_random.getrandbits(256)
            aes_key = hashlib.sha256(str(rand_key).encode('utf-8')).digest()
            encrypted_file_contents = encrypt_file(input_file, aes_key)
            encrypted_aes_key = rsa_encrypt(aes_key, key_file)
            print ('*'*20+' Encrypted ciphertext '+'*'*20)
            ciphertext = encrypted_file_contents+encrypted_aes_key
            print (ciphertext)
            with open(out_file, 'wb') as f:
                f.write(ciphertext)
        else:
            # decryption
            print ('-'*20+' Decrypting message '+'-'*20)
            encrypted_message, encrypted_key = decrypt_file(input_file)
            key = rsa_decrypt(encrypted_key, key_file)
            message = aes_decrypt(encrypted_message, key)
            print(message)
            with open(out_file, 'w') as f:
                f.write(message)
    else:
        raise NotImplementedError('Program requires four command line arguments: -[e,d] keyFileName inputFileName outputFileName')