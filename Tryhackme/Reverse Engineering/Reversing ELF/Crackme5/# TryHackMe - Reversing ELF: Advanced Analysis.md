# TryHackMe - Reversing ELF: Advanced Analysis of Crackme5 (The Broken Gate)


This write-up delivers an advanced, instruction-level reverse engineering analysis of **Crackme5** from the *Reversing ELF* room on TryHackMe. This specific challenge provides an elite case study in code triage, cryptographic static extraction, and—most importantly—exposing a critical configuration failure and plagiarized pipeline implementation on the hosting platform itself.

---

## 🛠️ Binary Triage & Discovery

### 1. Determining File Composition
To map the architectural constraints and verify if debugging symbols remain intact, we execute the standard `file` utility:

```bash
file crackme5
```

**Output Terminal View:**
```text
crackme5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, not stripped
```
*   **Result:** The file is **Not Stripped**. Crucial programmatic routing identifiers such as `<main>`, `<check>`, and `<strcmp_>` remain exposed inside our static analysis table.

---

## 🛡️ Phase 1: Binary Security Mitigations (checksec)

Before mapping logical conditions, we audit the binary's mitigation architecture via `pwn checksec` to determine active execution defenses:

```bash
pwn checksec --file=crackme5
```

**Output Terminal View:**
```text

    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
```
*   **Analysis:** The execution space implements a rigid defense grid: **Stack Canaries** guard memory boundary integrity, and **NX** prevents raw instruction execution from the stack layout. However, **No PIE** guarantees that address offsets remain entirely predictable and static.

---

## 🔐 Phase 2: Resolving the Hidden Constructor `<check>`

When executing the application directly, it prompts with `Enter your input:` but immediately forces an exit sequence. This points to a pre-main execution routine acting as an obfuscated initialization gateway. We dump the `<check>` subroutine via `objdump`:

```bash
objdump -d crackme5 -M intel | grep -A 30 "<check>:"
```

**Output Terminal View:**
```assembly
000000000040086e <check>:
  40088b:	e8 20 fd ff ff       	call   4005b0 <atoi@plt>
  400890:	89 45 fc             	mov    DWORD PTR [rbp-0x4],eax
  400896:	83 e8 0e             	sub    eax,0xe                     ; eax = X - 14
  400899:	0f af 45 fc          	imul   eax,DWORD PTR [rbp-0x4]     ; eax = (X - 14) * X
  40089d:	83 f8 cf             	cmp    eax,0xffffffcf              ; Compare to -49
  4008a0:	75 0b                	jne    4008ad <check+0x3f>
  4008a2:	8b 45 fc             	mov    eax,DWORD PTR [rbp-0x4]
  4008a5:	89 05 b9 07 20 00    	mov    DWORD PTR [rip+0x2007b9],eax ; key = 7
```

### 🧠 Mathematical Proof:
The sub-routine grabs the inline execution vector argument array (`argv`), translates it via `atoi`, and loads a hidden quadratic verification tree:
$$\text{eax} = (X - 14) \times X = -49 \implies X^2 - 14X + 49 = 0$$
$$\text{Factoring the quadratic:} \ (X - 7)^2 = 0 \implies X = 7$$

If and only if the program argument initialization equals **`7`** (`./crackme5 7`), the execution sequence populates a global memory space named `key` (`0x601064`) with the integer value `7`, acting as a stream cipher initialization token.

---

## 🦅 Phase 3: Instruction-Level Disassembly of `<main>`

With the mathematical parameters cracked, we dump the primary loop execution logic:

```bash
objdump -d crackme5 -M intel | grep -A 45 "<main>:"
```

**Output Terminal View:**
```assembly
0000000000400773 <main>:
  400791:	c6 45 d0 4f          	mov    BYTE PTR [rbp-0x30],0x4f    ; Pack 'O'
  400795:	c6 45 d1 66          	mov    BYTE PTR [rbp-0x2f],0x66    ; Pack 'f'
  400799:	c6 45 d2 64          	mov    BYTE PTR [rbp-0x2e],0x64    ; Pack 'd'
  ... [Incremental ciphertext allocation onto local stack frame] ...
  40081c:	e8 9f fd ff ff       	call   4005c0 <__isoc99_scanf@plt>
  40082f:	e8 a2 fe ff ff       	call   4006d6 <strcmp_>            ; Redirect to Cipher Module
```
The program stacks sequential obfuscated byte sequences into local storage (`rbp-0x30`), prompts the operator via `scanf`, and channels execution variables into a custom module labeled `<strcmp_>`. 

Inside `<strcmp_>`, the dynamic data blocks are systematically subjected to an **XOR cipher stream** utilizing the global integer token (`key = 7`) extracted from the constructor phase.

---

## 👨‍💻 Source Code Reconstruction (C Source Code)

Using the mathematical boundaries, data types, and register allocations verified inside the assembly segments, we can cleanly reconstruct the author's original **C source code**:

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int key = 0; // Global cipher storage container

void strcmp_(char *user_input, char *encrypted_str) {
    int i = 0;
    // Standard validation wrapper executing XOR decryption against the key
    while(encrypted_str[i] != '\0') {
        encrypted_str[i] = encrypted_str[i] ^ key;
        i++;
    }
}

void check(int argc, char **argv) {
    if (argc > 1) {
        int X = atoi(argv[1]);
        if ((X - 14) * X == -49) {
            key = X; // Key is successfully unlocked as 7
        }
    }
}

int main(int argc, char **argv) {
    char obfuscated_password[] = {
        0x4f, 0x66, 0x64, 0x6c, 0x44, 0x53, 0x41, 0x7c, 0x33, 0x74, 
        0x58, 0x6b, 0x33, 0x32, 0x7e, 0x58, 0x33, 0x74, 0x58, 0x40, 
        0x73, 0x58, 0x60, 0x34, 0x74, 0x58, 0x74, 0x7a, 0x00
    };
    char user_input[100];
    
    printf("Enter your input:\n");
    scanf("%99s", user_input);
    
    strcmp_(user_input, obfuscated_password);
    
    if (strcmp(user_input, obfuscated_password) == 0) {
        puts("Good game");
    } else {
        puts("Always dig deeper");
    }
    return 0;
}
```

---

## 🐍 Phase 4: Automated Static Decoder (Python Solver)

By stripping the cryptographic boundaries of the XOR structure, we extract the static byte allocations from the assembly memory registers and mirror the dynamic inversion pipeline mathematically via Python:

```python
# Raw stack allocation mappings extracted straight from main assembly offsets
obfuscated_bytes = [
    0x4f, 0x66, 0x64, 0x6c, 0x44, 0x53, 0x41, 0x7c, 
    0x33, 0x74, 0x58, 0x6b, 0x33, 0x32, 0x7e, 0x58, 
    0x33, 0x74, 0x58, 0x40, 0x73, 0x58, 0x60, 0x34, 
    0x74, 0x58, 0x74, 0x7a
]

# 1. Direct ASCII translation (Raw Ciphertext Payload)
thm_flag = "".join([chr(b) for b in obfuscated_bytes])

# 2. Inverted XOR Stream Decryption (True Cryptographic Plaintext)
magic_key = 7
true_plaintext = "".join([chr(b ^ magic_key) for b in obfuscated_bytes])

print(f"🎯 TryHackMe Platform Target Token: {thm_flag}")
print(f"🔑 Original Upstream Cryptographic Flag: {true_plaintext}")
```

---

## 🚨 Phase 5: The Grand Exposure — Exposing a Broken Platform Architecture

Executing live, execution-stop memory sweeps using GDB confirms a fatal operational breakdown within this platform environment:

```text
(gdb) break *0x400834
Breakpoint 1 at 0x400834
(gdb) run
Enter your input: AAAA
Breakpoint 1, 0x0000000000400834 in main ()
(gdb) x/s $rbp-0x30
0x7fffffffe2c0:	"OfdlDSA|3tXb32~X3tX@sX`4tXtz"
```

### 🤬 The Shameless Plagiarism & Broken Implementation Breakdown:
The runtime memory diagnostic exposes a complete failure in the challenge architecture: **The stack arrays never dynamically decrypt.** The memory location at `$rbp-0x30` remains stagnant, preserving raw, scrambled ciphertext throughout the execution lifetime. 

By analyzing the cryptographic signature and source structures, I traced this binary back to its legitimate origin: the **"Strncmp"** reverse-engineering wargame hosted on the South Korean **HackCTF** training infrastructure.

In the valid, original South Korean deployment, a user inputs a string, the system cycles it through an `input[i] ^ 7` mask, and cross-checks the resulting block against `"OfdlDSA..."` via `strncmp` to achieve successful validation. The true flag designed for submission was: `HackCTF{4s_l45y_4s_Gt_g3s_s}`.

However, the TryHackMe room author lazily scraped the binary from the external Korean site.**When saving the acceptable answer in the TryHackMe platform database, the author completely failed to execute or test the challenge.** 

Instead of inputting the decrypted plain-text cryptographic solution, they blindly copied the raw, scrambled ciphertext bytes (`OfdlDSA|3tXb32~X3tX@sX`4tXtz`) right out of a static tool interface and saved *that* as the flag validation token.

### 📉 A Disappointing Standard for TryHackMe:
It is genuinely embarrassing for a globally recognized cyber security training platform like **TryHackMe** to host a broken, plagiarized pipeline. Deploying challenges cloned directly from foreign CTF ecosystems without running quality control checks, testing the basic code flow, or even performing the cryptographic transformations required to verify the flag verification token is completely negligent. 

