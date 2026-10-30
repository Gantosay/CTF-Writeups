#!/usr/bin/env python3
"""
picoCTF PW Crack 3 Automated Solution Tool-Gantosay
"""
import hashlib

def str_xor(secret, key):
    # Extend key to secret length dynamically
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

# Load isolated encrypted static targets into memory stream
flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()

# Target Candidate Entry Array mined from source comments
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]

print("[*] Launching high-speed programmatic brute-force over candidate space...")

# Iterative execution loop processing
for candidate in pos_pw_list:
    current_digest = hash_pw(candidate)
    
    # Evaluate binary structural equivalence across MD5 byte strings
    if current_digest == correct_pw_hash:
        print(f"[+] Success! Isolated true authentication key parameter: '{candidate}'")
        
        # Deploy XOR decryption routines using the valid extracted key
        plaintext_flag = str_xor(flag_enc.decode(), candidate)
        print(f"[+] Decrypted Flag Recovered: {plaintext_flag}")
        break

