#!/usr/bin/env python3
"""
Automated Cascading XOR Decoder Matrix for macOS Mach-O Challenge
"""

def inverse_rolling_cipher():
    # Extracted raw hexadecimal validation block harvested from offset 0x100000f6e
    ciphertext_stream = [
        0x66, 0x0a, 0x6b, 0x0c, 0x77, 0x26, 0x4f, 0x2e, 0x40, 0x11, 
        0x78, 0x0d, 0x5a, 0x3b, 0x55, 0x11, 0x70, 0x19, 0x46, 0x1f, 
        0x76, 0x22, 0x4d, 0x23, 0x44, 0x0e, 0x67, 0x06, 0x68, 0x0f, 
        0x47, 0x32, 0x4f
    ]
    
    plaintext_out = []
    
    # Position index 0 remains fundamentally identical (no preceding dependency character)
    plaintext_out.append(chr(ciphertext_stream[0]))
    
    # Systematically loop forward, XORing each cipher slot with its preceding sibling cipher bock
    for i in range(1, len(ciphertext_stream)):
        recovered_char_code = ciphertext_stream[i] ^ ciphertext_stream[i - 1]
        plaintext_out.append(chr(recovered_char_code))
        
    final_flag = "".join(plaintext_out)
    
    print("═" * 60)
    print(f"Programmatic Rolling Decode Initiated...")
    print(f"RECOVERED CTF FLAG ASSET: {final_flag}")
    print("═" * 60)

if __name__ == "__main__":
    inverse_rolling_cipher()