# CTF Technical Write-up: cyLab Academy - x86_64 Assembly Triage (Easy)

## 📝 Challenge Description
* **Category:** Reverse Engineering / Assembly Reading
* **Difficulty:** Easy (Triage Optimization)
* **Objective:** Analyze a flat x86_64 assembly function dump, track volatile register state changes, and extract the final decimal content of the `eax` register.

---

## 🔍 Phase 1: Assembly Signal-to-Noise Mapping
When auditing compiled native assembly functions, the compiler embeds architectural padding and stack allocation frames that act as noise. We execute a linear line-by-line mapping to isolate the active instruction payload:

```assembly
<+0>:     endbr64                       ; Intel CET Mitigation (No-op for execution logic)
<+4>:     push   rbp                    ; Function Prologue: Stack frame alignment
<+5>:     mov    rbp,rsp                ; Function Prologue: Setting local base pointer
<+8>:     mov    DWORD PTR [rbp-0x4],edi; Static Storage: Saving argument 1 (Noise)
<+11>:    mov    QWORD PTR [rbp-0x10],rsi; Static Storage: Saving argument 2 (Noise)
<+15>:    mov    eax,0x30               ; CORE PAYLOAD: Hardcoding return register value
<+20>:    pop    rbp                    ; Function Epilogue: Standard stack clearance
<+21>:    ret                           ; Exit: Returning control flow with RAX state
```

### Operational Evaluation:
The parameters tracking input variables inside `edi` and `rsi` are pushed into stack offsets but never processed or mutated. At memory offset `<+15>`, the CPU encounters an absolute immediate assignment instruction: `mov eax, 0x30`. 

Because no subsequent arithmetic arithmetic blocks or register transformations occur prior to the `ret` epilogue checkpoint, the termination state of the `eax` register is definitively fixed at hex value **`0x30`**.

---

## 🧮 Phase 2: Hexadecimal to Decimal Matrix Conversion
The challenge specifications require the flag output to represent the final `eax` context transformed into a standard base-10 decimal number:

* **Extracted Register State (Hex):** `0x30`
* **Mathematical Translation:** (3 × 16¹) + (0 × 16⁰) = 48 + 0 = 48

---

## 🏁 Final Flag
**`academy{48}`**
