#!/usr/bin/env python3
import os

def ultimate_crack_happy():
    target_file = "Happy.exe"
    cracked_file = "Happy_cracked.exe"
    
    if not os.path.exists(target_file):
        print(f"[-] Error: {target_file} not found in current directory!")
        return

    with open(target_file, "rb") as f:
        binary_data = bytearray(f.read())
        
    print("[*] Scanning binary for validation gates...")
    
    target_pattern = b'\x85\xc0\x74\x14'
    
    count = 0
    offset = binary_data.find(target_pattern)
    
    while offset != -1:
        
        binary_data[offset + 2] = 0xeb
        print(f"[+] Successfully cracked validation gate at raw file offset: {hex(offset + 2)}")
        count += 1
        offset = binary_data.find(target_pattern, offset + 1)
        
    if count > 0:
        with open(cracked_file, "wb") as f:
            f.write(binary_data)
        print(f"[+] Total patches applied: {count}")
        print(f"[+] Cracked file successfully saved as: ./{cracked_file}")
        print("[+] IMPORTANT: Delete the old file on FLARE-VM, transfer this new file, and try again!")
    else:
        print("[-] Error: Target instruction pattern not found. Let's do a full scan.")
        print(f"[*] Raw bytes at 0x108c currently: {binary_data[0x108c:0x108c+4].hex()}")

if __name__ == "__main__":
    ultimate_crack_happy()
