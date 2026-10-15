#!/usr/bin/env python3
import hashlib
import os

def str_xor(secret, key):
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

flag_enc = open('level5.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level5.hash.bin', 'rb').read()
dict_file = 'dictionary.txt' if os.path.exists('dictionary.txt') else 'dictionary'

with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        password = line.strip() # Purge dynamic whitespaces (\n)
        if hash_pw(password) == correct_pw_hash:
            print(f"[+] Success! Mapped core authentication pass: '{password}'")
            print(f"[+] Recovered Plaintext Flag: {str_xor(flag_enc.decode(), password)}")
            break