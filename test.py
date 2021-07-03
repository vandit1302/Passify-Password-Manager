import json
from base64 import b64encode, b64decode
from Crypto.Cipher import AES
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Hash import SHA256
from Crypto.Hash import SHAKE256
from enyo.enyoencryption import EnyoEncryption
from enyo.enyodecryption import EnyoDecryption



## Global password is the key for all encryption and decryption
print('Enter your global password: ', end = ' ')
key1 = input()


## This data is the password
print('Enter your password for the website: ')
data = input()
data = bytes(data, 'utf-8')

## Choice of algo
print("\n\n")
print("Enter your choice of algorithm: ")
print("1. AES")
print("2. DES")
print("3. Enyo")
choice = int(input())
print("\n\n")


## For AES encryption
## Generate 32 bit key using hashing and use that as the key
## Pass on iv, ciphertext
if(choice == 1):
    h = SHAKE256.new( )
    h.update(bytes(key1, 'utf-8'))
    hash = h.read(32)
    key = hash
    print("Hashed key = ", end = ' ')
    print(key)
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, AES.block_size))
    iv = cipher.iv
    print('Cipher text = ', end = ' ')
    print(ciphertext)
    print('Initialization vector = ', end = ' ')
    print(iv)

## For DES encryption
## Generate 8 bit key using hashing and use that as the key
## Pass on iv, ciphertext
elif(choice == 2):
    h = SHAKE256.new()
    h.update(bytes(key1, 'utf-8'))
    hash = h.read(8)
    key = hash
    print("Hashed key = ", end = ' ')
    print(key)
    cipher = DES.new(key, DES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(data, DES.block_size))
    iv = cipher.iv
    print('Cipher text = ', end = ' ')
    print(ciphertext)
    print('Initialization vector = ', end = ' ')
    print(iv)

elif(choice == 3):
    key = key1
    ciphertext = EnyoEncryption(data.decode('utf-8'),key,partition=2,transposition=True)
    print(ciphertext.encrypted)

else:
    print("Default choice selected") 


## Things required for decryption - iv, ciphertext, key
## ciphertext made new for each time
## store iv and key in sql table
print("\n\n Starting decryption...")

if(choice == 1):
    cipher2 = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher2.decrypt(ciphertext), AES.block_size)
    print('Cipher text = ', end = ' ')
    print(ciphertext)
    print('Initialization vector = ', end = ' ')
    print(iv)
    print('Plaintext = ', end = ' ')
    print(plaintext)

elif(choice == 2):
    cipher2 = DES.new(key, DES.MODE_CBC, iv)
    plaintext = unpad(cipher2.decrypt(ciphertext), DES.block_size)
    print('Cipher text = ', end = ' ')
    print(ciphertext)
    print('Initialization vector = ', end = ' ')
    print(iv)
    print('Plaintext = ', end = ' ')
    print(plaintext)


elif(choice == 3):
    plaintext = EnyoDecryption(ciphertext.encrypted,key,partition=2,transposition=True)
    print(plaintext.decrypted)


