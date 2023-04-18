import threading
from Crypto.Cipher import DES

def sxor(s1,s2):    
    return ''.join(chr(ord(a) ^ ord(b)) for a,b in zip(s1,s2))

def encrypt_file(plaintext, key):
    key = bytes.fromhex(key)
    plaintext = plaintext.encode()
    if len(plaintext) % 8 != 0:
        plaintext = plaintext + b'\x00' * (8 - len(plaintext) % 8)
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(plaintext)

def decrypt_file(ciphertext, key):
    key = bytes.fromhex(key)
    cipher = DES.new(key, DES.MODE_ECB)
    plaintext = cipher.decrypt(ciphertext)
    return plaintext.rstrip(b'\x00')

def set_interval(func, sec):
    def func_wrapper():
        set_interval(func, sec)
        func()
    t = threading.Timer(sec, func_wrapper)
    t.start()
    return t