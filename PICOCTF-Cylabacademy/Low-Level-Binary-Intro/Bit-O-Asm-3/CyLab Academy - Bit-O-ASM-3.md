# CTF Technical Write-up: cyLab Academy - Bit-O-Asm-3 (Medium)
## Deep-Dive on Arithmetic Instructions (IMUL & ADD) & Programmatic Automation

## 📝 Challenge Description
* **Category:** Reverse Engineering / Assembly Reading
* **Difficulty:** Medium (Arithmetic Tracking)
* **Target Artifact:** `disassembler-dump.txt`
* **Objective:** Trace dynamic memory pointer loading, calculate intermediate register math involving signed multiplication (`imul`) and addition (`add`), and determine the final base-10 decimal value of the `eax` register.

---

## 🔍 Phase 1: Control Flow & Arithmetic Instruction Mapping
We conduct a linear static execution analysis over the unoptimized assembly dump to map how immediate values are processed between memory pointers and registers:

```assembly
<+0>:     endbr64                       ; Intel CET Security preamble (No op)
<+4>:     push   rbp                    ; Prologue: Allocating stack
<+5>:     mov    rbp,rsp                ; Prologue: Aligning stack base pointer
<+8>:     mov    DWORD PTR [rbp-0x14],edi; Argument register backup (Noise)
<+11>:    mov    QWORD PTR [rbp-0x20],rsi; Argument register backup (Noise)
<+15>:    mov    DWORD PTR [rbp-0xc],0x9fe1a; POINTER 1: Store 0x9fe1a at [rbp-0xc]
<+22>:    mov    DWORD PTR [rbp-0x8],0x4; POINTER 2: Store 0x4 at [rbp-0x8]
<+29>:    mov    eax,DWORD PTR [rbp-0xc]; LOAD: EAX = 0x9fe1a
<+32>:    imul   eax,DWORD PTR [rbp-0x8]; MULTIPLY: EAX = EAX * [rbp-0x8] (4)
<+36>:    add    eax,0x1f5              ; ADDITION: EAX = EAX + 0x1f5
<+41>:    mov    DWORD PTR [rbp-0x4],eax; Sync state variables (Noise)
<+44>:    mov    eax,DWORD PTR [rbp-0x4]; Hydrate output return register
<+47>:    pop    rbp                    ; Epilogue: Clear local frames
<+48>:    ret                           ; Exit: Terminating with final EAX state
```

### Mathematical Pipeline Reconstruction:
1. **Memory Allocation:** The stack address `[rbp-0xc]` holds the hex constant `0x9fe1a`. The stack address `[rbp-0x8]` holds the value `0x4`.
2. **Register Loading:** The variable `eax` is initialized with the content of `[rbp-0xc]` → `0x9fe1a`.
3. **Execution of `imul`:** The signed integer multiplication instruction computes: `eax = 0x9fe1a * 0x4`.
4. **Execution of `add`:** The immediate hex value `0x1f5` is added to the previous state: `eax = (0x9fe1a * 0x4) + 0x1f5`.

---

## 🧮 Phase 2: Base-16 Cryptographic Decoupling & Math Execution
Translating the hexadecimal operational parameters into a verified base-10 decimal integer sequence manually:

* **Initial Key (Hex):** `0x9fe1a` → `654874` (Decimal)
* **Multiplier Factor:** `0x4` → `4` (Decimal)
* **Addend Value (Hex):** `0x1f5` → `(1 × 16²) + (15 \times 16¹) + (5 \times 16⁰) = 256 + 240 + 5 = 501` (Decimal)

### Running the Computational Pipeline:
\[{Step 1 (IMUL): } 654874 \times 4 = 2619496\]
\[{Step 2 (ADD): } 2619496 + 501 = \mathbf{2619997}\]

---

## 🤖 Phase 3: High-Fidelity Python Solver Automation
To eliminate potential human errors in manual base-16 arithmetic calculations, I engineered a programmatic python simulation matrix (`solve.py`). Python natively handles hexadecimal literals prefixed with `0x`, allowing a clean execution sync to reproduce the CPU's register transformations instantly:

```python
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
```

### Automation Execution Trace Output:
```text
$ python3 calc.py
══════════════════════════════════════════════════
[+] Programmatic Decimal EAX: 2619997
[+] Reconstructed Flag Token : academy{2619997}
══════════════════════════════════════════════════
```

---

## 🏁 Final Flag
**`academy{2619997}`**
