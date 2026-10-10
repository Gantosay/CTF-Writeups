#!/usr/bin/env python3
"""
Automated Software Cracker - Bypassing Native String Validation Gates - Gantosay
"""
import os

def apply_binary_crack():
    original_binary = "reverse_2"
    cracked_binary = "reverse_2_cracked"
    
    # Target raw file offset mapping inside the ELF structure
    file_offset = 0x846 
    
    # Overwrite payload: Change \x74\x0c (je) into \xeb\x0c (jmp)
    crack_payload = b'\xeb\x0c'
    
    if not os.path.exists(original_binary):
        print(f"[-] Error: Native file '{original_binary}' missing from directory!")
        return

    # Ingest raw bytes stream from disk
    with open(original_binary, "rb") as target_file:
        binary_stream = bytearray(target_file.read())
        
    print("[+] Ingested raw binary bytes stream into mutable memory buffer.")
    
    # Splice and corrupt the validation checkpoint 
    binary_stream[file_offset:file_offset+2] = crack_payload
    print(f"[+] Overwrote conditional opcode at file offset: {hex(file_offset)}")
    
    # Output the modified executable package
    with open(cracked_binary, "wb") as cracked_file:
        cracked_file.write(binary_stream)
        
    # Programmatically assign execution permissions (Linux chmod +x)
    os.chmod(cracked_binary, 0o755)
    print(f"[+] Success! Fully cracked executable compiled: ./{cracked_binary}")
    print("[+] Run the cracked binary and input ANY text to trigger the victory branch!")

if __name__ == "__main__":
    apply_binary_crack()