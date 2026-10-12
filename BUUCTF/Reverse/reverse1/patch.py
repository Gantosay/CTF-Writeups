#!/usr/bin/env python3
"""
Automated Structural PE Binary Patcher for reverse1 Challenge
Author: Gantosay
"""
import os

def apply_control_flow_hijack():
    original_exe = "reverse1.exe"
    cracked_exe = "reverse1_cracked.exe"
    
    # Accurate physical disk target offset calculated via PE section structures
    target_disk_offset = 0xD86
    
    # Patch array conversion blueprint: Swap 74 (jz) -> eb (jmp)
    patch_payload = b'\xeb\x0e'
    
    if not os.path.exists(original_exe):
        print(f"[-] Critical Error: File '{original_exe}' not found inside workspace!")
        return

    # Ingest the target application stream
    with open(original_exe, "rb") as target_file:
        file_bytes = bytearray(target_file.read())
        
    print(f"[+] Loaded raw PE binary footprint into dynamic memory.")
    print(f"[*] Original opcodes tracked at target checkpoint: {file_bytes[target_disk_offset:target_disk_offset+2].hex()}")
    
    # Force patch mutation injection
    file_bytes[target_disk_offset:target_disk_offset+2] = patch_payload
    print(f"[+] Successfully injected unconditional jump modification at offset: {hex(target_disk_offset)}")
    
    # Save the modified cracked clone executable
    with open(cracked_exe, "wb") as output_file:
        output_file.write(file_bytes)
        
    print(f"[+] Executable cracked successfully! Output file built as: ./{cracked_exe}")
    print("[+] Launch the cracked asset inside Windows or Wine and submit any input text to bypass authentication rules!")

if __name__ == "__main__":
    apply_control_flow_hijack()