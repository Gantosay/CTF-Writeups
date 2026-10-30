#!/usr/bin/env python3
"""
Automated Assembly Pipeline Solver for Bit-O-Asm-3
"""

def solve_assembly_matrix():
    # Extract immediate hexadecimal bounds natively from the instruction dump
    initial_eax = 0x9fe1a   # Offset <+15>
    multiplier  = 0x4       # Offset <+22>
    addend      = 0x1f5     # Offset <+36>
    
    # Simulate CPU Register pipeline modifications
    eax = initial_eax
    eax *= multiplier       # Replicating the 'imul' block execution
    eax += addend           # Replicating the 'add' block execution
    
    # Generate the strict platform flag format envelope
    flag_payload = f"academy{{{eax}}}"
    
    print("═" * 50)
    print(f"[+] Programmatic Decimal EAX: {eax}")
    print(f"[+] Reconstructed Flag Token : {flag_payload}")
    print("═" * 50)

if __name__ == "__main__":
    solve_assembly_matrix()
