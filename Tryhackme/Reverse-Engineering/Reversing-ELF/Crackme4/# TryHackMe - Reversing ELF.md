# TryHackMe - Reversing ELF: Advanced Analysis of Crackme4

This write-up delivers a comprehensive, instruction-level reverse engineering analysis of **Crackme4** from the *Reversing ELF* room on TryHackMe. This challenge introduces advanced architectural layers, including custom stack frames, **Stack Canaries**, and a dedicated **XOR stream cipher** routine designed to mask authentication credentials.

---

## 🛠️ Binary Triage & Discovery
Running a baseline diagnostic via `file crackme4` reveals the following properties:
* **Architecture:** ELF 64-bit LSB executable, x86-64.
* **Symbols:** **Not Stripped**. This keeps crucial internal function labels like `<compare_pwd>` and `<get_pwd>` completely visible in our disassembly table, providing a flawless roadmap for analysis.

---

## 🛡️ Phase 1: Binary Security Mitigations (checksec)

Before inspecting the instructions, we audit the binary's built-in security properties using `pwn checksec`. This determines which exploitation mitigation features are enforced by the compiler:

```text
pwn checksec --file=crackme4

    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```

### 🧠 Security Property Breakdown:
* **Arch (amd64-64-little):** Confirms a standard 64-bit Intel/AMD architecture utilizing Little-Endian byte storage layout.
* **RELRO (Partial RELRO):** The Global Offset Table (GOT) is placed before local variables to prevent simple buffer overflows from destroying it, but it remains writeable at runtime.
* **Stack (Canary found):** [CRITICAL] The compiler has injected a protective random cookie onto the stack frame. Any stack-based buffer overflow attempt that overwrites the instruction pointer will corrupt this cookie, causing the program to abort immediately.
* **NX (NX enabled):** No-eXecute is active. The stack memory region is marked as non-executable, meaning injected shellcode cannot be fired directly from the stack.
* **PIE (No PIE):** Position Independent Executable is disabled. The application loads at a static, predictable base address in memory (`0x400000`), allowing us to rely heavily on static disassembly addresses.

---

## 🔐 Phase 2: Dissecting `main` & Functional Routing
To extract the primary programmatic orchestration sequence without loading a visual decompiler, I dump the assembly instructions under the `<main>` sector using `objdump` with Intel syntax and filter the immediate code block:
```bash
objdump -d crackme4 -M intel | grep -A 35 "<main>:"
```

**Output Terminal View:**
```assembly
0000000000400716 <main>:
  400716:   55                      push   rbp
  400717:   48 89 e5                mov    rbp,rsp
  40071a:   48 83 ec 10             sub    rsp,0x10
  40071e:   89 7d fc                mov    DWORD PTR [rbp-0x4],edi
  400721:   48 89 75 f0             mov    QWORD PTR [rbp-0x10],rsi
  400725:   83 7d fc 02             cmp    DWORD PTR [rbp-0x4],0x2   ; Check if argc == 2
  400729:   74 1b                   je     400746 <main+0x30>        ; Jump if user provided an argument
  40072b:   48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
  40072f:   48 8b 00                mov    rax,QWORD PTR [rax]
  400732:   48 89 c6                mov    rsi,rax
  400735:   bf 10 08 40 00          mov    edi,0x400810
  40073a:   b8 00 00 00 00          mov    eax,0x0
  40073f:   e8 bc fd ff ff          call   400500 <printf@plt>
  400744:   eb 13                   jmp    400759 <main+0x43>
  400746:   48 8b 45 f0             mov    rax,QWORD PTR [rbp-0x10]
  40074a:   48 83 c0 08             add    rax,0x8
  40074e:   48 8b 00                mov    rax,QWORD PTR [rax]
  400751:   48 89 c7                mov    rdi,rax
  400754:   e8 21 ff ff ff          call   40067a <compare_pwd>      ; Route control flow to authentication
  400759:   b8 00 00 00 00          mov    eax,0x0
  40075e:   c9                      leave  
  40075f:   c3                      ret    
```

Inspecting the structural mapping of the `main` loop reveals traditional sanitization of execution parameters:
```assembly
  400725:   83 7d fc 02             cmp    DWORD PTR [rbp-0x4],0x2   ; Check if argc == 2
  400729:   74 1b                   je     400746 <main+0x30>        ; Jump if user provided an argument
```
If an interactive input parameter is attached, `main` grabs the `argv` reference pointer and passes execution control over to the validation block located at address `0x40067a`:
```assembly
  400754:   e8 21 ff ff ff          call   40067a <compare_pwd>      ; Route control flow to authentication
```

---

## 🦅 Phase 3: Analyzing `<compare_pwd>` & Stack Canaries

To see how the password validation framework behaves, we execute a targeted assembly pull specifically targeting the `<compare_pwd>` function label:

```bash
objdump -d crackme4 -M intel | grep -A 45 "<compare_pwd>:"
```

**Output Terminal View:**
```assembly
000000000040067a <compare_pwd>:
  40067a:   55                      push   rbp
  40067b:   48 89 e5                mov    rbp,rsp
  40067e:   48 83 ec 30             sub    rsp,0x30
  400682:   48 89 7d d8             mov    QWORD PTR [rbp-0x28],rdi
  400686:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28     ; Pull random cookie from OS kernel storage
  40068d:   00 00 
  40068f:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax   ; Store it securely at rbp-0x8
  400693:   31 c0                   xor    eax,eax
  400695:   48 b8 49 5d 7b 49 14    movabs rax,0x7b175614497b5d49    ; Pack encrypted segment 1 onto stack
  40069c:   56 17 7b 
  40069f:   48 89 45 e0             mov    QWORD PTR [rbp-0x20],rax
  4006a3:   48 b8 57 41 47 51 56    movabs rax,0x547b175651474157    ; Pack encrypted segment 2 onto stack
  4006aa:   17 7b 54 
  4006ad:   48 89 45 e8             mov    QWORD PTR [rbp-0x18],rax
  4006b1:   66 c7 45 f0 53 40       mov    WORD PTR [rbp-0x10],0x4053       ; Pack tail segment
  4006b7:   c6 45 f2 00             mov    BYTE PTR [rbp-0xe],0x0           ; Append Null Terminator
  4006bb:   48 8d 45 e0             lea    rax,[rbp-0x20]
  4006bf:   48 89 c7                mov    rdi,rax
  400622:   e8 66 ff ff ff          call   40062d <get_pwd>          ; Invoke XOR Cipher Engine
  4006c7:   48 8b 55 d8             mov    rdx,QWORD PTR [rbp-0x28]
  4006cb:   48 8d 45 e0             lea    rax,[rbp-0x20]
  4006cf:   48 89 d6                mov    rsi,rdx
  4006d2:   48 89 c7                mov    rdi,rax
  4006d5:   e8 46 fe ff ff          call   400520 <strcmp@plt>
  4006da:   85 c0                   test   eax,eax
  4006dc:   75 0c                   jne    4006ea <compare_pwd+0x70>
  4006de:   bf e8 07 40 00          mov    edi,0x4007e8
  4006e3:   e8 f8 fd ff ff          call   4004e0 <puts@plt>
```

Looking inside the `<compare_pwd>` block, I noticed the live implementation of the **Stack Canary** verified earlier by `checksec`:
```assembly
  400686:   64 48 8b 04 25 28 00    mov    rax,QWORD PTR fs:0x28     ; Pull random cookie from OS kernel storage
  40068f:   48 89 45 f8             mov    QWORD PTR [rbp-0x8],rax   ; Store it securely at rbp-0x8
```
Before exiting, the function XORs this value back against `fs:0x28`. If a buffer overflow corrupts this layout, it immediately triggers `__stack_chk_fail@plt` to abort execution.

Right after the canary setup, a hardcoded block of raw quad-word values is stacked into adjacent memory allocations using `movabs`:
```assembly
  400695:   48 b8 49 5d 7b 49 14    movabs rax,0x7b175614497b5d49
  40069f:   48 89 45 e0             mov    QWORD PTR [rbp-0x20],rax
```
The application then feeds the base pointer of this encrypted chunk directly into a specialized decryption subroutine:
```assembly
  4006bb:   48 8d 45 e0             lea    rax,[rbp-0x20]
  400622:   e8 66 ff ff ff          call   40062d <get_pwd>          ; Invoke XOR Cipher Engine
```

---

## ⚡ Phase 4: Breaking the Obfuscation Inside `<get_pwd>`

To isolate the dynamic transformation logic applied to the array, we extract the loop body mechanics using `objdump`:

```bash
objdump -d crackme4 -M intel | grep -A 35 "<get_pwd>:"
```

**Output Terminal View:**
```assembly
000000000040062d <get_pwd>:
  40062d:   55                      push   rbp
  40062e:   48 89 e5                mov    rbp,rsp
  400631:   48 89 7d e8             mov    QWORD PTR [rbp-0x18],rdi
  400635:   c7 45 fc ff ff ff ff    mov    DWORD PTR [rbp-0x4],0xffffffff
  40063c:   eb 22                   jmp    400660 <get_pwd+0x33>
  40063e:   8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
  400641:   48 63 d0                movsxd rdx,eax
  400644:   48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]
  400648:   48 01 c2                add    rdx,rax
  40064b:   8b 45 fc                mov    eax,DWORD PTR [rbp-0x4]
  40064e:   48 63 c8                movsxd rcx,eax
  400651:   48 8b 45 e8             mov    rax,QWORD PTR [rbp-0x18]
  400655:   48 01 c8                add    rax,rcx
  400658:   0f b6 00                movzx  eax,BYTE PTR [rax]        ; Fetch one byte of encrypted data
  40065b:   83 f0 24                xor    eax,0x24                  ; [CRITICAL] XOR the byte with key 0x24
  40065e:   88 02                   mov    BYTE PTR [rdx],al         ; Write plaintext byte back to memory
```

Zooming into the `<get_pwd>` subroutine reveals a tight string processing loop that decrypts the real credentials dynamically at runtime. The core operations occur right here:

```assembly
  400658:   0f b6 00                movzx  eax,BYTE PTR [rax]        ; Fetch one byte of encrypted data
  40065b:   83 f0 24                xor    eax,0x24                  ; [CRITICAL] XOR the byte with key 0x24
  40065e:   88 02                   mov    BYTE PTR [rdx],al         ; Write plaintext byte back to memory
```

### 🧠 Cryptographic Breakdown:
The algorithm steps through the hardcoded byte matrix sequentially until it encounters a string termination character (`0x00`). Every individual byte is dynamically XORed with the static mask **`0x24`** (the ASCII character `$`). 

Because the XOR operation is reflexive (\(A \oplus B \oplus B = A\)), we can trivially reverse engineer this process statically without running the application binary.

---

## 👨‍💻 Source Code Reconstruction (C Source Code)
Based on the instruction architecture, the compiler data alignment, and structural logic flow analyzed above, we can cleanly reconstruct the author's original **C source code**:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Stream cipher engine pulling raw obfuscated data arrays
void get_pwd(char *encrypted_str) {
    int i = 0;
    // Iterate through stack variables sequentially until Null Terminator is reached
    while (encrypted_str[i] != '\0') {
        // Dynamic reverse engineering transformation utilizing static mask 0x24
        encrypted_str[i] = encrypted_str[i] ^ 0x24;
        i++;
    }
}

// Authentication handling module
void compare_pwd(char *user_input) {
    // Encrypted byte sequence extracted straight from the raw assembly 'movabs' allocations
    char encrypted_password = {
        0x49, 0x5d, 0x7b, 0x49, 0x14, 0x56, 0x17, 0x7b,
        0x57, 0x41, 0x47, 0x51, 0x56, 0x17, 0x7b, 0x54,
        0x53, 0x40, 0x00 // String Termination Indicator
    };

    // Run decrypt layer over static variables on stack
    get_pwd(encrypted_password);

    // Verify user input credentials against runtime-unmasked plaintext array
    if (strcmp(encrypted_password, user_input) == 0) {
        puts("Access granted! Capturing structural target flag sequence...");
    } else {
        printf("Access denied! Your input '%s' is incorrect.\n", user_input);
    }
}

// Global programmatic runtime entry point
int main(int argc, char *argv) {
    // Sanitization gateway checking execution parameters 
    if (argc != 2) {
        printf("Usage : %s password\n", argv);
        return 0;
    }

    // Forward argument vector parameters downstream
    compare_pwd(argv);

    return 0;
}
```

---

## 🐍 Automated Static Decoder (Python Solver)

By accounting for x86-64 **Little-Endian** byte ordering, we extract the scrambled stack chunks, map them linearly, and use Python to reconstruct the plain-text credentials:

```python
# Raw hex arrays re-aligned linearly from Little-Endian layout
encrypted_bytes = [
    0x49, 0x5d, 0x7b, 0x49, 0x14, 0x56, 0x17, 0x7b,
    0x57, 0x41, 0x47, 0x51, 0x56, 0x17, 0x7b, 0x54,
    0x53, 0x40
]

xor_key = 0x24
plaintext_password = "".join([chr(b ^ xor_key) for b in encrypted_bytes])

print(f"Target Password Decrypted: {plaintext_password}")
```

### Final Exploitation Flow:
1. Execute the standalone Python solver to extract the plain-text authentication password.
2. Inject the resulting string back into the live pipeline: `./crackme4 <decrypted_password>`.
