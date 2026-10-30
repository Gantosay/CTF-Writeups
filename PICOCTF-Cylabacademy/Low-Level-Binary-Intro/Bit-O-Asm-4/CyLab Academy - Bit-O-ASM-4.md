# CTF Technical Write-up: cyLab Academy - Bit-O-Asm-4 (Medium)
## Advanced Control Flow Tracking & Conditional Jump (JLE) Analysis

## 📝 Challenge Description
* **Category:** Reverse Engineering / Assembly Reading
* **Difficulty:** Medium (Control Flow Hijacking)
* **Target Artifact:** `disassembler-dump.txt`
* **Objective:** Track a standard x86_64 conditional jump branch (`jle`), analyze operand evaluations via `cmp`, execute dynamic registry mutations, and determine the final decimal value of the `eax` register.

---

## 🔍 Phase 1: Branch Analysis & Instruction Mapping
We conduct a linear static execution simulation over the unoptimized assembly dump to trace the CPU's branch decision path:

```assembly
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a; ALLOCATION: [rbp-0x4] = 0x9fe1a (654874)
<+22>:    cmp    DWORD PTR [rbp-0x4],0x2710 ; EVALUATION: Compare 654874 against 0x2710 (10000)
<+29>:    jle    0x55555555514e <main+37>   ; CONDITIONAL GATE: Jump if <= 10000 (False!)
<+31>:    sub    DWORD PTR [rbp-0x4],0x65   ; TRUE BRANCH: Execute subtraction of 0x65 (101)
<+35>:    jmp    0x555555555152 <main+41>   ; UNCONDITIONAL JUMP: Bypass alternative block
<+37>:    add    DWORD PTR [rbp-0x4],0x65   ; FALSE BRANCH: (Dead Code - Never Triggered)
<+41>:    mov    eax,DWORD PTR [rbp-0x4]    ; TERMINATION: Hydrate output register EAX
```

### Architectural Branch Breakdown:
1. At offset `<+22>`, the `cmp` instruction evaluates the local stack pointer variable against the immediate hex boundary `0x2710` (decimal `10,000`).
2. At offset `<+29>`, the `jle` (Jump if Less or Equal) condition reads the evaluation flags. Since the initialized state value (`654,874`) is significantly **greater** than `10,000`, the branch is **not taken**.
3. The CPU falls through directly into the execution block at offset `<+31>`, executing a subtraction pass: `[rbp-0x4] = [rbp-0x4] - 0x65`.
4. It hits the unconditional `jmp` at offset `<+35>`, clean-leaping over the alternative addition path to load the final register value.

---

## 🤖 Phase 2: Programmatic Solver Automation
To eliminate manual base-16 calculation errors, I engineered a programmatic Python solver (`solve.py`) replicating the CPU register transformations:

```python
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
```

### Script Execution Trace:
```text
$ python3 solve.py
══════════════════════════════════════════════════
[+] Reconstructed Decimal EAX: 654773
[+] Automated Flag Generated : academy{654773}
══════════════════════════════════════════════════
```

---

## 🏁 Final Flag
**`academy{654773}`**
