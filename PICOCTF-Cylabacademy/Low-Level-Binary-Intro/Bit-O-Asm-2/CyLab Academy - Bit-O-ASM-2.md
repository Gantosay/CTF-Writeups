# CTF Technical Write-up: cyLab Academy - Bit-O-Asm-2 (Medium)
## Master Class on Assembly Pointers (PTR) & Stack Offsets

## 📝 Challenge Description
* **Category:** Reverse Engineering / Assembly Reading
* **Difficulty:** Medium (Pointer Evaluation)
* **Target Artifact:** `disassembler-dump.txt`
* **Objective:** Trace dynamic stack storage operations via Data Pointers (PTR), track volatile register changes, and calculate the final decimal content of the `eax` register.

---

## 🔍 Phase 1: Tracking Pointer Architecture & Memory Offsets
When compiling a high-level function, local variables are assigned to specific offsets relative to the Base Pointer register (`rbp`). We conduct a linear execution trace to see how data shifts between memory segments:

```assembly
<+0>:     endbr64                       ; Security preamble (No operational effect)
<+4>:     push   rbp                    ; Prologue: Allocating stack frame
<+5>:     mov    rbp,rsp                ; Prologue: Aligning stack frame boundary
<+8>:     mov    DWORD PTR [rbp-0x14],edi; Argument storage pad (Noise)
<+11>:    mov    QWORD PTR [rbp-0x20],rsi; Argument storage pad (Noise)
<+15>:    mov    DWORD PTR [rbp-0x4],0x9fe1a; POINTER ASSIGNMENT: Writing immediate value to stack
<+22>:    mov    eax,DWORD PTR [rbp-0x4]; REGISTER HYDRATION: Fetching value from stack into EAX
<+25>:    pop    rbp                    ; Epilogue: Cleaning local frame stack
<+26>:    ret                           ; Exit: Terminating routine with active EAX state
```

### Technical Execution Analysis:
* At offset `<+15>`, the CPU encounters an execution block mapping a 4-byte Double Word pointer (`DWORD PTR`). It writes the hexadecimal immediate constant **`0x9fe1a`** directly into the stack memory address space pointed to by `[rbp-0x4]`.
* At offset `<+22>`, the program retrieves the data block by dereferencing the exact same pointer address `[rbp-0x4]` and hydrates the evaluation register `eax` with that stored value.

Since no other instruction transforms or manipulates the `eax` state before the final `ret` checkpoint, the final execution state of `eax` is locked at hex value **`0x9fe1a`**.

---

## 🧮 Phase 2: Base-16 Hexadecimal to Decimal Conversion
Converting the harvested hexadecimal state into a standard base-10 decimal integer requires calculating each digit's place value in base-16:

* **Captured Hex Value:** `0x9fe1a`
* **Mathematical Matrix:**
  - \(9 \times 16^4 = 9 \times 65536 = 589824\)
  - \(15 \times 16^3 = 15 \times 4096 = 61440\)
  - \(14 \times 16^2 = 14 \times 256 = 3584\)
  - \(1 \times 16^1 = 1 \times 16 = 16\)
  - \(10 \times 16^0 = 10 \times 1 = 10\)

  \[{Total Sum} = 589824 + 61440 + 3584 + 16 + 10 = \mathbf{654874}\]

---

## 🏁 Final Flag
**`academy{654874}`**
