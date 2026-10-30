# Reversing ELF: Crackme1 — Beyond "Just Run It"

> **Room:** TryHackMe — Reversing ELF
> **Binary:** `crackme1` (ELF 64-bit, x86-64)
> **Level:** Beginner
> **Goal:** Understand *how* the binary produces its output, not just *what* it prints.

Most write-ups for this challenge stop at "run the binary, copy the flag." That works, but it teaches almost nothing about reverse engineering. In this write-up I do three things:

1. Solve it the quick way (and explain why it's fine here).
2. Disassemble `main()` and translate every instruction back into C.
3. Answer two questions that make this challenge a great learning tool:
   - **What if this file were malware and running it was not an option?**
   - **The flag isn't visible with `strings`. Why, and how do we get it without executing anything?**

---

## 1. The Quick Way

```bash
chmod +x crackme1
./crackme1
```

The program prints the flag. Done.

That is acceptable in a CTF sandbox, because we *know* the file is a training challenge. In the real world, **you never run an unknown binary on a whim**. Keep reading.

---

## 2. Static Analysis: Reading `main()`

### 2.1 First look

```bash
file crackme1
strings crackme1 | less
```

`strings` shows library names (`puts`, `memset`) but **no flag**. This is the first clue: the flag is not stored as plain text. It is **built at runtime**.

### 2.2 Disassemble

```bash
objdump -d crackme1 -M intel | grep -A 80 "<main>:"
```

The output looks long, but most of it is repetition. Let's break it into four parts.

### 2.3 Part 1 — Prologue

```asm
push rbp
mov  rbp, rsp
sub  rsp, 0xa0
```

Standard function setup: save the old frame pointer, set a new one, and reserve `0xa0` bytes on the stack for local variables.

### 2.4 Part 2 — A hidden array of integers

```asm
mov DWORD PTR [rbp-0x70], 0x25
mov DWORD PTR [rbp-0x6c], 0x2b
mov DWORD PTR [rbp-0x68], 0x20
...
mov DWORD PTR [rbp-0x8],  0xffffffbf
```

Notice the addresses go up by **4** each time (`-0x70`, `-0x6c`, `-0x68`, ...). Each `DWORD` is 4 bytes, so this is an **array of `int`**, 27 elements long:

```c
int key[27] = {0x25, 0x2b, 0x20, 0x26, 0x3a, ..., -0x41};
```

The last value, `0xffffffbf`, is `-65` as a signed integer. Remember that `0x41` is `'A'` (65). We'll see why this matters in a moment.

### 2.5 Part 3 — `memset`

```asm
lea rax, [rbp-0x90]
mov edx, 0x1b
mov esi, 0x41
mov rdi, rax
call memset
```

On Linux x86-64, function arguments go in `rdi, rsi, rdx, rcx, r8, r9`. So this is:

```c
char buf[27];
memset(buf, 'A', 27);   // rdi = buf, rsi = 'A' (0x41), rdx = 27 (0x1b)
```

`lea` computes an **address** (it doesn't read memory). Here it gives us the start of `buf`.

### 2.6 Part 4 — The loop

```asm
mov DWORD PTR [rbp-0x4], 0     ; i = 0
jmp 400669                     ; jump to the condition first

; --- loop body ---
mov    eax, DWORD PTR [rbp-0x4]
cdqe
movzx  eax, BYTE PTR [rbp+rax*1-0x90]   ; eax = buf[i]
mov    edx, eax
mov    eax, DWORD PTR [rbp-0x4]
cdqe
mov    eax, DWORD PTR [rbp+rax*4-0x70]  ; eax = key[i]
add    eax, edx                         ; eax = key[i] + buf[i]
mov    edx, eax
mov    eax, DWORD PTR [rbp-0x4]
cdqe
mov    BYTE PTR [rbp+rax*1-0x90], dl    ; buf[i] = low byte of result
add    DWORD PTR [rbp-0x4], 1           ; i++

; --- loop condition ---
mov eax, DWORD PTR [rbp-0x4]
cmp eax, 0x1a
jbe 40063d                              ; if i <= 26, repeat
```

Tips for reading this:

- **`*4` in the address means an `int` array** (4-byte elements). **`*1` means a `char` array.** That's how we tell `key` and `buf` apart.
- `cdqe` just sign-extends the 32-bit `i` to 64 bits so it can be used in address math.
- `movzx` loads one byte and zero-extends it to 32 bits.
- Compilers place the loop **condition at the bottom** and jump to it first; that's why we see the early `jmp`.
- `cmp eax, 0x1a` + `jbe` means `i <= 26`, i.e. `i < 27`.
- This is `-O0` code, so `i` is constantly re-loaded from memory. It's noisy, but the logic is a single line of C.

### 2.7 Part 5 — Output and return

```asm
lea  rax, [rbp-0x90]
mov  rdi, rax
call puts
mov  eax, 0
leave
ret
```

That's `puts(buf); return 0;`.

### 2.8 The full program, reconstructed in C

```c
#include <stdio.h>
#include <string.h>

int main(void) {
    int key[27] = { 0x25, 0x2b, 0x20, 0x26, 0x3a, 0x2d, 0x2e, 0x33, 0x1e,
                    0x33, 0x27, 0x20, 0x33, 0x1e, 0x2a, 0x28, 0x2d, 0x23,
                    0x1e, 0x2e, 0x25, 0x1e, 0x24, 0x2b, 0x25, 0x3c, -0x41 };
    char buf[27];

    memset(buf, 'A', 27);
    for (int i = 0; i <= 26; i++)
        buf[i] = buf[i] + key[i];

    puts(buf);
    return 0;
}
```

### 2.9 What is this program actually doing?

It is **not** brute-forcing or "working hard." It is a tiny obfuscation trick:

- Instead of storing the flag as a string (which `strings` would reveal), the author stores **offsets** from the letter `'A'`.
- At runtime, each `'A'` (65) is added to its offset to reconstruct the real character.

Example for the first characters:

| i | key[i] | `'A'` + key[i] | char |
|---|--------|----------------|------|
| 0 | 0x25 (37) | 65 + 37 = 102 | `f` |
| 1 | 0x2b (43) | 65 + 43 = 108 | `l` |
| 2 | 0x20 (32) | 65 + 32 = 97  | `a` |
| 3 | 0x26 (38) | 65 + 38 = 103 | `g` |

**A neat detail:** the final key value is `-0x41` (`-65`). `65 + (-65) = 0`, which produces a **null byte**. That's the string terminator `\0` that makes `puts` stop printing. The author used the same trick to build the terminator, too.

---

## 3. Getting the Flag Without Running the Program

Since the flag is just `'A' + key[i]`, we can compute it ourselves from the disassembly. No execution needed.

```python
key = [0x25, 0x2b, 0x20, 0x26, 0x3a, 0x2d, 0x2e, 0x33, 0x1e,
       0x33, 0x27, 0x20, 0x33, 0x1e, 0x2a, 0x28, 0x2d, 0x23,
       0x1e, 0x2e, 0x25, 0x1e, 0x24, 0x2b, 0x25, 0x3c, -0x41]

flag = ""
for k in key:
    c = (ord('A') + k) & 0xFF   # keep only one byte, like the `dl` store
    if c == 0:                  # null terminator
        break
    flag += chr(c)

print(flag)
```

This is the real skill: **understanding the algorithm well enough to reproduce it**. It works even if the binary can't be executed (wrong architecture, hostile, or missing libraries).

### Other ways to recover it

| Method | Idea | Runs the binary? |
|--------|------|------------------|
| Run it | `./crackme1` | Yes |
| `ltrace` | Shows library calls such as `puts("...")` | Yes |
| GDB breakpoint | `break puts`, then inspect `rdi` / the buffer | Yes |
| Python script (above) | Re-implement the algorithm | **No** |
| Ghidra decompiler | Reads the key array and loop as C | **No** |

---

## 4. Why `strings` Doesn't Work Here

`strings` only finds **sequences of printable bytes stored in the file**. In this binary, the flag characters never exist in the file as a string. What's stored is a list of **small numbers** (`0x25`, `0x2b`, ...), and those are embedded in `mov` instructions as immediate values. They are not contiguous printable text.

The flag only comes into existence **in memory, during execution**, after the loop runs. This is a basic form of **string obfuscation**, and malware uses far more advanced versions of the same idea (XOR, base64, custom encodings, stack strings) to hide URLs, commands, and file paths from simple scanners.

> Building strings one byte at a time on the stack, like this binary does with its `mov` instructions, is commonly called **stack strings**. It's a very common pattern worth recognizing.

---

## 5. What If This Were Malware?

Imagine this exact file came from a suspicious email attachment. You should **not** double-click it or run it on your normal machine. A safe approach looks like this.

### Step 0 — Set up a safe lab

- Use a **virtual machine** that holds nothing important (no personal files, no saved credentials).
- Take a **snapshot** before you start, so you can roll back.
- **Disable networking** or use an isolated/host-only network. Malware may phone home, spread, or download more payloads.
- Never share folders between the VM and your real system.

### Step 1 — Identify without executing (basic static analysis)

```bash
file sample                 # what type of file is it?
sha256sum sample            # fingerprint; look it up on VirusTotal-style services
strings -n 8 sample         # readable text, URLs, paths, library names
readelf -h sample           # ELF header, architecture, entry point
readelf -S sample           # sections (odd names or high entropy can mean packing)
readelf -d sample           # dynamic libraries it depends on
nm -D sample                # imported functions (socket? fork? execve?)
```

Questions to ask:

- Which functions does it import? `socket`, `connect`, `execve`, `fork`, `ptrace` tell you a lot.
- Are there suspiciously few strings? That suggests obfuscation or packing.
- Do the section names and sizes look normal?

### Step 2 — Deep static analysis (disassembly / decompilation)

Open it in **Ghidra**, **radare2**, **IDA**, or simply `objdump`, and read the logic **without running anything**. This is exactly what we did with `crackme1`:

- Find `main` (or the entry point).
- Identify arrays, loops, and `call`s.
- Look for decoding routines like our `buf[i] = buf[i] + key[i]` loop. These usually guard the interesting strings: C2 addresses, file paths, commands.
- Re-implement the decoding in Python to recover the hidden data **safely**.

In our case, this step alone fully solves the challenge.

### Step 3 — Dynamic analysis (only inside the isolated VM)

If static analysis isn't enough, you may run it **inside the sandbox**, ideally under a debugger:

```bash
gdb ./sample
(gdb) break puts          # stop before output is printed
(gdb) run
(gdb) x/s $rdi            # inspect the decoded string in memory
```

Here you're letting the program decode itself, then stopping at the right moment to read the result, without letting it do anything further. You can also monitor with `strace` / `ltrace` and watch network traffic from the host side.

### Step 4 — Document and clean up

- Record hashes, behaviors, indicators (IPs, domains, files created).
- Revert the VM snapshot when done.

### The key idea

> **Static first, dynamic second, and only in isolation.**
> Reading the code teaches you what the program *intends* to do, and it can't hurt you.

---

## 6. Key Takeaways

- A flag (or malware config) can be **built at runtime** so `strings` never sees it.
- `[rbp-X]` are local variables; **the scale factor in an address (`*4` vs `*1`) reveals the element size** of an array.
- Function arguments on Linux x86-64: `rdi, rsi, rdx, rcx, r8, r9`.
- `cmp` + `jXX` = `if` or loop; a loop condition at the bottom with an early `jmp` is a normal compiler pattern.
- You can often **reproduce the algorithm in Python** and skip execution completely.
- When the file is untrusted: **VM, snapshot, no network, static analysis first.**

## 7. Tools Used

`file`, `strings`, `objdump`, `readelf`, `nm`, `gdb`, `ltrace`, Python 3 (and Ghidra as an optional alternative)

## 8. Practice Exercise

Write the 3-element version of this program yourself, compile it, and compare the assembly:

```bash
gcc -O0 -o test test.c
objdump -d test -M intel | grep -A 50 "<main>:"
```

Matching each line of C to its assembly is the fastest way to make these patterns stick.

---

*Written as part of my reverse engineering learning journey. Feedback and corrections are welcome!*
