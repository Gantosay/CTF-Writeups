#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Statically extracted ciphertext validation array from Reverse.class
target_key_array = [
    180, 136, 137, 147, 191, 137, 147, 191, 
    148, 136, 133, 191, 134, 140, 129, 135, 
    191, 65
]

extracted_plaintext = ""

# Execute the exact inverse mathematical transformation loop
for cipher_val in target_key_array:
    # 1. Reverse XOR shift layer with mask 32
    # 2. Reverse arithmetic scaling layer by subtracting 64
    plain_char_code = (cipher_val ^ 32) - 64
    
    # Cast byte integers back to human-readable characters
    extracted_plaintext += chr(plain_char_code)

# Enforce target contest flag wrapping requirements
final_flag = f"flag{{{extracted_plaintext}}}"

print("\n[+] Cryptographic Inversion Complete!")
print(f"🥇 Flag: {final_flag}\n")