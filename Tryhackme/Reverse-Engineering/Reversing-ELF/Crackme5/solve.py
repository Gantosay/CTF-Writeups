obfuscated_bytes = [
    0x4f, 0x66, 0x64, 0x6c, 0x44, 0x53, 0x41, 0x7c, 
    0x33, 0x74, 0x58, 0x6b, 0x33, 0x32, 0x7e, 0x58, 
    0x33, 0x74, 0x58, 0x40, 0x73, 0x58, 0x60, 0x34, 
    0x74, 0x58, 0x74, 0x7a
]

# 1. Direct ASCII translation (Raw Ciphertext Payload)
thm_flag = "".join([chr(b) for b in obfuscated_bytes])

# 2. Inverted XOR Stream Decryption (True Cryptographic Plaintext)
magic_key = 7
true_plaintext = "".join([chr(b ^ magic_key) for b in obfuscated_bytes])

print(f"🎯 TryHackMe Platform Target Token: {thm_flag}")
print(f"🔑 Original Upstream Cryptographic Flag: {true_plaintext}")