# Reversing ELF: Crackme2 — Reading the Logic, Then Bypassing It

> **Room:** TryHackMe — Reversing ELF
> **Binary:** `crackme2` (ELF **32-bit** x86)
> **Level:** Beginner
> **Goal:** Understand how the password check works, and recover the flag in several different ways, including ones that never need the password.

In [Crackme1](./crackme1-writeup.md) the program simply printed a flag it built at runtime. Crackme2 adds something new: **user input and a decision**. The program asks for a password, compares it, and only then reveals the flag. That makes it a perfect first look at `if` statements in assembly (`cmp` / `test` + conditional jumps) and at the **32-bit calling convention**.

---

## 1. First Look

```bash
file crackme2
./crackme2
strings crackme2 | less
```

- `file` reports a **32-bit** ELF. This matters: registers are `eax/ebp/esp` instead of `rax/rbp/rsp`, and function arguments are passed on the **stack**, not in registers.
- Running with no arguments prints a usage message, so the program expects **one argument**.
- `strings` already reveals interesting text, but, as in Crackme1, **not the flag**.

---

## 2. 32-bit vs 64-bit: What Changes

| | 64-bit (Crackme1) | 32-bit (Crackme2) |
|---|---|---|
| Registers | `rax`, `rbp`, `rsp` | `eax`, `ebp`, `esp` |
| Passing arguments | `rdi, rsi, rdx, rcx, r8, r9` | `push` onto the stack, **right to left** |
| Pointer size | 8 bytes | 4 bytes |
| After a `call` | nothing | `add esp, N` removes the arguments |

For `f(a, b)` the compiler pushes `b` first, then `a`. **The last value pushed is the first argument.**

---

## 3. Disassembling `main`

```bash
objdump -d crackme2 -M intel | grep -A 110 "<main>:"
```

### 3.1 Stack alignment boilerplate

```asm
lea  ecx,[esp+0x4]
and  esp,0xfffffff0
push DWORD PTR [ecx-0x4]
```

This is just the compiler aligning the stack to 16 bytes at the start of `main` in 32-bit code. It isn't part of the program's logic. After it, `ecx` points to where `argc` lives.

### 3.2 Checking the argument count

```asm
mov  eax,ecx
cmp  DWORD PTR [eax],0x2      ; argc == 2 ?
je   80484d0                  ; yes -> continue
mov  eax,DWORD PTR [eax+0x4]  ; eax = argv
mov  eax,DWORD PTR [eax]      ; eax = argv[0]
sub  esp,0x8                  ; alignment padding
push eax                      ; 2nd arg: argv[0]
push 0x8048660                ; 1st arg: format string
call printf
add  esp,0x10
mov  eax,0x1                  ; return 1
```

`argc == 2` means *program name + one argument*. If that's not the case, the program prints a usage string and returns 1.

### 3.3 The password comparison

```asm
mov  eax,DWORD PTR [eax+0x4]  ; eax = argv
add  eax,0x4                  ; eax = &argv[1]  (pointers are 4 bytes)
mov  eax,DWORD PTR [eax]      ; eax = argv[1]   (what the user typed)
sub  esp,0x8
push 0x8048674                ; 2nd arg: the secret string
push eax                      ; 1st arg: argv[1]
call strcmp
add  esp,0x10
test eax,eax
je   8048504                  ; zero -> strings were equal
```

Key points:

- `strcmp` returns **`0` when the strings are equal**.
- `test eax,eax` sets the zero flag if `eax` is `0`, and `je` ("jump if equal / zero") then takes the success branch.
- If the jump is not taken, `puts` prints a failure message and the program returns `1`.
- If it is taken, `puts` prints a success message and **`giveFlag()` is called**.

### 3.4 Control flow at a glance

```
argc != 2  -> print usage, return 1
argc == 2  -> strcmp(argv[1], secret)
                 |- != 0 -> "Access denied.", return 1
                 '- == 0 -> "Access granted." + giveFlag()
```

---

## 4. Disassembling `giveFlag`

Same idea as Crackme1, with one new instruction.

```asm
lea  eax,[ebp-0xe8]
mov  ebx,0x80486c0         ; source: read-only data in the binary
mov  edx,0x33              ; 51 elements
mov  edi,eax               ; destination: local array
mov  esi,ebx
mov  ecx,edx
rep movs DWORD PTR es:[edi],DWORD PTR ds:[esi]
```

`rep movs` means *"copy one dword (4 bytes) from `[esi]` to `[edi]`, repeat `ecx` times."* So 51 integers are copied from `0x80486c0` onto the stack. In Crackme1 each element had its own `mov`; here the array is larger, so the compiler used a block copy instead. The result is the same: `int key[51] = {...}`.

Then:

```asm
push 0x33                  ; memset(buf, 'A', 51)
push 0x41
push buf
call memset
```

and the loop:

```asm
cmp eax,0x32               ; i <= 50
jbe loop_body
...
mov eax,DWORD PTR [ebp+eax*4-0xe8]   ; key[i]   (*4 -> int array)
...
mov BYTE PTR [eax],cl                ; buf[i] = buf[i] + key[i]
```

It ends with `puts(buf)`.

**Sanity check on the stack layout:** `key` starts at `ebp-0xe8` and takes `51 * 4 = 204 (0xcc)` bytes, so it ends at `ebp-0x1c`, which is exactly where the loop counter `i` lives. The pieces fit together.

---

## 5. Reconstructed C

After reading the strings from memory (see next section), the whole program looks like this:

```c
#include <stdio.h>
#include <string.h>

void giveFlag(void) {
    int key[51] = { /* 51 values stored at 0x80486c0 */ };
    char buf[51];

    memset(buf, 'A', 51);
    for (int i = 0; i <= 50; i++)
        buf[i] = buf[i] + key[i];

    puts(buf);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        printf("Usage: %s password\n", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "super_secret_password") != 0) {
        puts("Access denied.");
        return 1;
    }

    puts("Access granted.");
    giveFlag();
    return 0;
}
```

---

## 6. Method 1 — Find the Password and Run It

The disassembly shows only **addresses** of strings. Read what lives there:

```bash
gdb -q ./crackme2 \
  -ex 'x/s 0x8048660' -ex 'x/s 0x8048674' \
  -ex 'x/s 0x804868a' -ex 'x/s 0x8048699' -ex quit
```

```
0x8048660: "Usage: %s password\n"
0x8048674: "super_secret_password"
0x804868a: "Access denied."
0x8048699: "Access granted."
```

A small consistency check: the secret starts at `0x8048674` and the next string starts at `0x804868a`, a difference of 22 bytes, which is 21 characters plus the null terminator. That matches `super_secret_password` (21 characters).

```bash
./crackme2 super_secret_password
```

**Another handy trick: `ltrace`.** It shows library calls with their arguments, so the secret leaks directly from the `strcmp` call:

```bash
ltrace ./crackme2 anything
# strcmp("anything", "super_secret_password") = ...
```

---

## 7. Method 2 — Skip the Check Entirely

`giveFlag` exists in the binary, so we can jump straight into it and never touch the password:

```bash
gdb -q ./crackme2
(gdb) break main
(gdb) run
(gdb) jump *0x8048526        # exact start of giveFlag
```

The flag is printed. Two things worth noting:

- Using `jump giveFlag` (without `*`) makes gdb skip the function's prologue and land a few instructions in (`0x804852c` in my run). It worked here, but jumping to the exact start with `jump *ADDRESS` is safer.
- The process exits with a strange code (`063` octal = 51). That's simply the leftover return value of `puts` (50 characters + newline) in `eax`, because we jumped in and the stack frame was never set up the normal way. Harmless, but a good reminder that **forcing control flow has side effects**.

This is the core idea behind many real-world bypasses: **if a check is just a conditional jump, an attacker can often skip or flip it.** Another classic variant is patching the binary so that `je` becomes `jne`, which makes *every wrong password* succeed.

---

## 8. Method 3 — Rebuild the Algorithm (No Execution)

Dump the 51 integers from the binary without running it:

```bash
gdb -q ./crackme2 -ex 'x/51dw 0x80486c0' -ex quit
```

```
37 43 32 38 58 40 37 30 40 30 50 52 33 44 40 51
30 51 39 40 50 30 37 43 32 38 30 51 39 36 45 30
40 30 54 40 43 43 30 38 36 51 30 47 46 40 45 51
50 60 -65
```

Each value is an offset from `'A'` (65). Python reproduces the loop:

```python
key = [37, 43, 32, 38, 58, 40, 37, 30, 40, 30, 50, 52, 33, 44, 40, 51,
       30, 51, 39, 40, 50, 30, 37, 43, 32, 38, 30, 51, 39, 36, 45, 30,
       40, 30, 54, 40, 43, 43, 30, 38, 36, 51, 30, 47, 46, 40, 45, 51,
       50, 60, -65]

buf = bytearray(b"A" * 51)
for i in range(51):
    buf[i] = (buf[i] + key[i]) & 0xFF   # same as writing the low byte (cl)

print(buf.split(b"\x00")[0].decode())
```

Output:

```
flag{if_i_submit_this_flag_then_i_will_get_points}
```

As in Crackme1, the final value `-65` makes `65 + (-65) = 0`, producing the **null terminator** that tells `puts` where the string ends. The flag is 50 characters plus that terminator, which is exactly 51 elements.

---

## 9. Why `strings` Shows the Password but Not the Flag

- The **password** is a normal string literal, so it sits in the file as printable bytes. `strings` finds it immediately.
- The **flag** is stored as a list of small numbers and only becomes text in memory after the loop runs. `strings` never sees it.

In real malware and firmware, the same distinction applies: **hardcoded credentials** are often found with a simple `strings`, while more interesting data (URLs, commands, keys) is usually obfuscated and has to be recovered through analysis like we did here.

---

## 10. Summary of the Three Methods

| Method | How | Runs the binary? | What it teaches |
|---|---|---|---|
| Correct password | `strings` / `x/s` / `ltrace`, then `./crackme2 <pass>` | Yes | Reading comparison logic |
| Jump to `giveFlag` | `jump *0x8048526` in gdb | Yes | Control-flow manipulation |
| Rebuild in Python | Dump array, re-implement loop | **No** | Understanding the algorithm |

---

## 11. Key Takeaways

- **32-bit calling convention:** arguments are pushed on the stack right to left, and the caller cleans up with `add esp, N`.
- `test eax,eax` + `je` is the standard "is it zero?" check; `strcmp` returns `0` for equal strings.
- `argv[1]` is read as `argv + 4` (pointers are 4 bytes on 32-bit).
- `rep movs` copies a block of memory; it's how compilers initialize larger arrays.
- A `*4` in an address means an `int` array, `*1` a `char` array.
- A password check is only as strong as its conditional jump. Reading the logic shows you **where** it can be bypassed.
- Reproducing an algorithm in a script is often safer and more instructive than running the binary.


