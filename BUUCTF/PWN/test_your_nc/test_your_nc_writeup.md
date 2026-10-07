# BUUCTF — Pwn: `test_your_nc`

**Category:** Pwn (Binary Exploitation)
**Difficulty:** Easy / Warm-up
**Author:** Gantosay
**Flag:** `CTF2{b4ed9fd3-****-****-****-e338d203}` *(partially redacted)*

## TL;DR

The binary calls `system("/bin/sh")` unconditionally from `main()`. No memory corruption, no user input parsing, no exploit primitive needed — connecting to the service and reading `flag.txt` is enough. This writeup walks through the *process* of confirming that, rather than just stating the conclusion, since the methodology is the same one used on harder pwn challenges.

## 1. Reconnaissance

First step on any pwn challenge: identify the binary and check which exploit mitigations are enabled, before touching a disassembler.

```bash
$ file test_your_nc
test_your_nc: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV),
dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2,
for GNU/Linux 3.2.0, not stripped
```

```bash
$ pwn checksec ./test_your_nc
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        PIE enabled
```

| Protection | Status | Implication |
|---|---|---|
| Stack Canary | Disabled | Stack buffer overflows, if present, would go undetected until `ret` |
| NX | Enabled | No shellcode injection on the stack — must reuse existing executable code |
| PIE | Enabled | Base address is randomized per run; hardcoded absolute addresses won't work |
| RELRO | Partial | GOT is writable for non-PLT entries, but not the primary attack surface here |

At this point the mitigations tell us *what kind* of exploit we'd need **if** a bug exists — PIE means we'd need a relative offset or a leak, NX rules out raw shellcode. Worth noting before disassembling, even though it turns out not to matter for this challenge.

## 2. Static analysis

Disassembling with `objdump -d -M intel` produces the usual compiler-generated scaffolding (`_init`, `.plt`, `_start`, `__libc_csu_init`, `deregister_tm_clones`, etc.) — none of that is application logic and can be skipped. The only function worth reading is `main`:

```asm
0000000000001135 <main>:
    1135: push   rbp
    1136: mov    rbp, rsp
    1139: lea    rdi, [rip+0xec4]        # 2004 <_IO_stdin_used+0x4>
    1140: call   1030 <system@plt>
    1145: mov    eax, 0x0
    114a: pop    rbp
    114b: ret
```

Two things stand out immediately:

- `main` takes no input at all — no `read`, `gets`, `scanf`, nothing. There is no attacker-controlled data flow to corrupt.
- It calls `system@plt` with a single RIP-relative argument loaded into `rdi` (the first argument register under the System V x86-64 calling convention).

`lea rdi, [rip+0xec4]` resolves to the address `0x2004` — objdump's own disassembly comment confirms this. That's a read-only data reference, so the next step is just reading what's actually stored there.

## 3. Confirming the argument to `system()`

```bash
$ objdump -s -j .rodata ./test_your_nc

Contents of section .rodata:
 2000 01000200 2f62696e 2f736800           ..../bin/sh.
```

Breaking down the hex starting at offset `0x2004` (the address `lea` computed):

```
2f 62 69 6e   →  / b i n
2f 73 68 00   →  / s h \0
```

So the call is, effectively:

```c
int main(void) {
    system("/bin/sh");
    return 0;
}
```

No parsing, no buffer, no corruption needed — the binary spawns a shell as soon as it runs.

## 4. Exploitation

Given the above, "exploitation" here is just connecting to the service:

```bash
$ nc <host> <port>
ls
cat flag.txt
```

The shell drops immediately on connection. `flag.txt` is in the working directory.



## 5. Takeaways

- Always run `checksec` before disassembling — it tells you what *kind* of exploit path to expect (or rules techniques out) before you've read a single instruction.
- Compiler-generated boilerplate (`_init`, `_start`, `__libc_csu_init`, the `tm_clones` functions) is noise in nearly every pwn challenge. Jump straight to `main` and whatever it calls.
- `lea reg, [rip+offset]` with a PIE binary is RIP-relative addressing — objdump's trailing comment resolves the target address for you, so always check it rather than computing by hand.
- Not every "pwn" challenge involves memory corruption. Some are deliberately trivial (`system("/bin/sh")` with no input) to test that a player's netcat/shell workflow works before harder challenges in the set.



