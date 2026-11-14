#!/usr/bin/env python3
import os
from pwn import *

context.arch = 'amd64'

elf = ELF('./xxor')

# Overwrite the first instruction(s) of fcn.00400770 with an unconditional
# jump straight to the success block, skipping all 6 comparisons entirely.
elf.asm(0x400770, 'jmp 0x400823')

output_file = './xxor_pwn_patched'
elf.save(output_file)
os.chmod(output_file, 0o755)

print(f"[+] Patched binary saved to {output_file}")