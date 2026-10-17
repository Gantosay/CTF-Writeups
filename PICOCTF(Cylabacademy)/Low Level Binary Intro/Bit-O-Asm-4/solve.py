#!/usr/bin/env python3
"""
Automated Control Flow Pipeline Solver for Bit-O-Asm-4
"""

def solve_assembly_flow():
    # Ingest baseline hexadecimal primitives from instructions
    local_var = 0x9fe1a    # Offset <+15>
    compare_gate = 0x2710 # Offset <+22>
    modifier = 0x65       # Offset <+31> / <+37>
    
    # Simulate the CMP + JLE Evaluation Gate
    if local_var <= compare_gate:
        # Branch Taken (main+37)
        local_var += modifier
    else:
        # Branch Not Taken -> Fall-through (main+31)
        local_var -= modifier
        
    eax = local_var
    flag_payload = f"academy{{{eax}}}"
    
    print("═" * 50)
    print(f"[+] Reconstructed Decimal EAX: {eax}")
    print(f"[+] Automated Flag Generated : {flag_payload}")
    print("═" * 50)

if __name__ == "__main__":
    solve_assembly_flow()


### Script Execution Trace:
#$ python3 solve.py
#══════════════════════════════════════════════════
#[+] Reconstructed Decimal EAX: 654773
#[+] Automated Flag Generated : academy{654773}
#══════════════════════════════════════════════════

