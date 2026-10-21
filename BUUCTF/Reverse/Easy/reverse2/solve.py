#!/usr/bin/env python3
"""
Automated Memory-Mutation Solver for Forking-RE Challenge-Gantosay
"""

def extract_mutated_flag():
    # Carved string extracted via 'ps @ 0x601080' in Rizin
    initial_flag_state = "{hacking_for_fun}"
    
    # Cast to a lists structure for linear mutation tasks
    flag_characters = list(initial_flag_state)
    
    # Mirror the child process instruction behavior 
    for index in range(len(flag_characters)):
        if flag_characters[index] in ['i', 'r']:
            flag_characters[index] = '1'
            
    final_solution = "".join(flag_characters)
    
    print("[+] Emulation Matrix Complete.")
    print(f"[+] Extracted Flag: flag{{{final_solution}}}")

if __name__ == "__main__":
    extract_mutated_flag()
