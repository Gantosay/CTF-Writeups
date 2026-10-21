# Reverse Challenge `reverse_3` — Base64 + Index Shift (Windows PE32)

> **Binary:** `reverse_3` (Windows PE32, 32-bit, Visual Studio **Debug** build)
> **Tools:** `rizin` (static analysis), Python 3, a C compiler
> **Level:** Medium-Hard
> **Goal:** Figure out what input the program accepts, **without needing to run it**, and understand every step of the logic.

This write-up is based entirely on static analysis in Rizin: strings, cross-references and the disassembly of `main`. I'll show the reasoning, a C reconstruction of the program, and two solvers (Python and C) that work by **reversing the algorithm**.

---

## 1. First Look

The program asks for a flag and answers either `rigth flag!` (sic, the typo is in the binary) or `wrong flag!`.

> **Safety note:** this is a Windows executable from a challenge. Even though it looks harmless, don't run unknown `.exe` files on your main machine. Everything below is static analysis. If you want to run it, do it in an isolated VM with a snapshot and no network.

Open it in Rizin and let it analyze:

```
rizin reverse_3.exe
[0x00000000]> aaa            # analyze everything
[0x00000000]> iI             # file info: PE32, x86, 32-bit
[0x00000000]> iz             # strings in data sections
[0x00000000]> afl            # list functions
[0x00000000]> pdf @ main     # disassemble main
```

---

## 2. Reading the Strings (`iz`)

Most of the output is Visual Studio runtime noise, but a few lines tell the whole story:

| String | Address | What it tells us |
|---|---|---|
| `please enter the flag:` | `0x417b74` | The program prompts for input |
| `%20s` | `0x417b8c` | `scanf("%20s", ...)`: reads at most **20 characters** |
| `wrong flag!\n` / `rigth flag!\n` | `0x417b94` / `0x417c4c` | Failure / success messages |
| `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=` | `0x417b30` | **The Base64 alphabet** (65 chars including `=`) |
| `e3nifIH9b_C@n@dH` | `0x41a034` (`.data`) | A suspicious 16-char string: probably the **target** the input is compared against |
| `...\Debug\reverse_3.pdb`, `VCRUNTIME140D.dll`, `Stack around the variable '...' was corrupted` | `.rdata` | A **Debug** build made with Visual Studio. Expect extra compiler-inserted checks |

### Clues worth noting

1. A Base64 alphabet in the binary means Base64 is involved somewhere.
2. The odd string `e3nifIH9b_C@n@dH` has characters like `@` and `_` that are not typical for plain Base64 text. So it is likely **Base64 output that was modified afterward**.
3. Its length is **16**, which is a multiple of 4. That's consistent with Base64 of 12 bytes, with no `=` padding.

To see who uses the target string, ask Rizin for cross-references:

```
[0x...]> axt @ str.e3nifIH9b_C_n_dH
main 0x415822 [DATA] push str.e3nifIH9b_C_n_dH
```

Only `main` references it, so the whole check lives in `main`.

---

## 3. Disassembling `main` (`pdf @ main`)

`main` is at `0x4156e0`. Let's read it in sections and separate the **real logic** from the **compiler noise**.

### 3.1 Compiler noise: how to recognize and ignore it

Debug builds from Visual Studio insert extra code. None of the following is program logic:

```asm
mov ecx, 0x5f
mov eax, 0xcccccccc
rep stosd                       ; fills the whole stack frame with 0xCC
```
`0x5f * 4 = 380 = 0x17c` bytes, which is exactly the `sub esp, 0x17c` frame size. Debug builds fill locals with `0xCC` so that using an uninitialized variable is obvious. (This also matches the string "A local variable was used before it was initialized".)

```asm
mov eax, dword [0x41a004]
xor eax, ebp
mov dword [var_8h], eax         ; stack cookie (buffer overflow guard)
...
mov ecx, dword [var_8h]
xor ecx, ebp
call fcn.00411280               ; checks the cookie at the end
```

```asm
mov esi, esp
... call something ...
cmp esi, esp
call fcn.00411127               ; "ESP was not properly saved across a function call"
```
This `esi`/`esp` compare-and-call pattern appears after **every** function call in a Debug build. It's the runtime check behind the long "The value of ESP was not properly saved..." string.

```asm
cmp dword [var_17ch], 0x64
jnb 0x415743
...
call fcn.00411154               ; runtime array-bounds failure handler
```
A bounds check on the array index. Again, not part of the real logic.

> **Display glitch:** you'll see operands like `byte [var_8h + 0x4x*1-0x94]`. The `0x4x` is a decompilation display glitch. From context it simply means `dest[index]`. When a tool prints something that doesn't make sense, check it against the surrounding logic rather than trusting it blindly.

### 3.2 Step 1: zero out a buffer

```asm
mov dword [var_a4h], 0x00        ; i = 0
...
cmp dword [var_a4h], 0x64        ; i < 100 ?
jnl 0x415758
...
mov byte [dest + i], 0x00        ; dest[i] = 0
```

A simple loop clears a 100-byte buffer (`dest`).

```c
char dest[100];
for (int i = 0; i < 100; i++)
    dest[i] = 0;
```

### 3.3 Step 2: read the input

```asm
push str.please_enter_the_flag:
call fcn.0041132f                ; printf
lea  eax, [var_2ch]
push eax                         ; arg 2: buffer
push str.20s                     ; arg 1: "%20s"
call fcn.00411375                ; scanf
```

```c
char Str[21];
printf("please enter the flag:");
scanf("%20s", Str);
```
(32-bit calling convention: arguments pushed right to left, so the format string is pushed last.)

### 3.4 Step 3: Base64 encode the input

This is the most interesting block. The pushes are interleaved, so read it carefully:

```asm
push 0x28                        ; (A) pushed early, used much later
lea  eax, [var_10h]
push eax                         ; (B) &out_len
lea  ecx, [var_2ch]
push ecx                         ; (C) Str
call fcn.004110c8                ; takes 1 arg: returns strlen(Str)
add  esp, 0x04                   ; removes only (C)
push eax                         ; len
lea  edx, [var_2ch]
push edx                         ; Str
call fcn.004110be                ; takes 3 args: (Str, len, &out_len)
add  esp, 0x0c                   ; removes Str, len, (B)
push eax                         ; src = result of the previous call
lea  eax, [dest]
push eax                         ; dest
call strncpy                     ; (dest, src, 0x28) -- (A) is the 3rd arg
add  esp, 0x0c                   ; removes dest, src, (A)
```

The trick: the compiler pushed `0x28` **before** the other calls, and it stays on the stack until `strncpy`. Following each `add esp, N` shows which arguments belong to which call:

```c
int outlen;
int len = strlen(Str);                       // fcn.004110c8
char *enc = base64_encode(Str, len, &outlen);// fcn.004110be
strncpy(dest, enc, 0x28);
```

**How do we know `fcn.004110be` is Base64?** From the clues, not from guessing blindly:

- the Base64 alphabet exists in `.rdata`,
- the function takes (input, length, pointer to output length) and returns a new string,
- the target string is 16 characters long (a multiple of 4).

You should still confirm it by disassembling that function (`pdf @ fcn.004110be`, then follow the thunk if it's just a `jmp`) and checking that it indexes the alphabet with 6-bit values (`>> 2`, `& 0x3F`, and so on). It does.

### 3.5 Step 4: shift every character by its index

```asm
mov  dword [var_b0h], 0          ; j = 0
...
mov  eax, dword [var_b0h]
cmp  eax, dword [var_a4h]        ; j < len (var_a4h holds strlen(dest))
jnl  exit
movsx ecx, byte [dest + j]
add  ecx, dword [var_b0h]        ; dest[j] + j
mov  byte [dest + j], cl         ; dest[j] = dest[j] + j
```

```c
int len = strlen(dest);
for (int j = 0; j < len; j++)
    dest[j] = dest[j] + j;
```

Each character gets its position added to it: first char `+0`, second `+1`, third `+2`, and so on.

### 3.6 Step 5: compare with the target

```asm
lea  eax, [dest]
push eax
call fcn.004110c8                ; strlen(dest)
...
push eax                         ; n = strlen(dest)
push str.e3nifIH9b_C_n_dH        ; "e3nifIH9b_C@n@dH"
push ecx(dest)
call strncmp                     ; strncmp(dest, target, strlen(dest))
test eax, eax
jz   0x415851                    ; 0 -> equal -> "rigth flag!"
```

```c
if (strncmp(dest, "e3nifIH9b_C@n@dH", strlen(dest)) == 0)
    printf("rigth flag!\n");
else
    printf("wrong flag!\n");
```

### 3.7 Function map

| Function | Role | Confidence |
|---|---|---|
| `fcn.0041132f` | `printf` wrapper | from usage (called with a message) |
| `fcn.00411375` | `scanf` wrapper | from usage (`"%20s"` + buffer) |
| `fcn.004110c8` | `strlen` | from usage (one argument, its result is used as a length) |
| `fcn.004110be` | Base64 encode | inferred; **confirm by reading the function** |
| `sym.imp...strncpy` / `strncmp` | CRT imports | named by Rizin |
| `fcn.00411127`, `fcn.00411154`, `fcn.0041126c`, `fcn.00411280` | Debug runtime checks | from context (esp check, bounds check, stack cookie) |

---

## 4. The Whole Program in C

```c
#include <stdio.h>
#include <string.h>

char *base64_encode(const char *in, int len, int *out_len);   /* standard Base64 */

int main(void) {
    char dest[100];
    char Str[21];
    int  outlen;

    for (int i = 0; i < 100; i++)
        dest[i] = 0;

    printf("please enter the flag:");
    scanf("%20s", Str);

    char *enc = base64_encode(Str, (int)strlen(Str), &outlen);
    strncpy(dest, enc, 0x28);

    int len = (int)strlen(dest);
    for (int j = 0; j < len; j++)
        dest[j] = dest[j] + j;

    if (strncmp(dest, "e3nifIH9b_C@n@dH", strlen(dest)) == 0)
        printf("rigth flag!\n");
    else
        printf("wrong flag!\n");

    return 0;
}
```

### The algorithm in one line

```
input  ->  Base64  ->  add index j to the j-th character  ->  compare to "e3nifIH9b_C@n@dH"
```

---

## 5. Solving It: Reverse the Pipeline

When a program applies several reversible steps and compares the result to a constant, we **undo the steps in reverse order**, starting from the constant:

| Program does | We do |
|---|---|
| 1. Base64 encode | 3. Base64 **decode** |
| 2. `c = c + j` | 2. `c = c - j` |
| 3. compare to target | 1. start from the target |

### 5.1 By hand (first four characters)

| j | target char | code | minus j | result |
|---|---|---|---|---|
| 0 | `e` | 101 | 101 | `e` |
| 1 | `3` | 51 | 50 | `2` |
| 2 | `n` | 110 | 108 | `l` |
| 3 | `i` | 105 | 102 | `f` |

So the Base64 text begins with `e2lf`. Decoding `e2lf` gives the bytes `{i_`, which already looks like the start of a flag.

*   Character 0:  `'e'` (ASCII 101) - 0 = 101 $\rightarrow$ 'e'
*   Character 1:  `'3'` (ASCII 51)  - 1 = 50  $\rightarrow$ '2'
*   Character 2:  `'n'` (ASCII 110) - 2 = 108 $\rightarrow$ 'l'
*   Character 3:  `'i'` (ASCII 105) - 3 = 102 $\rightarrow$ 'f'
*   Character 4:  `'f'` (ASCII 102) - 4 = 98  $\rightarrow$ 'b'
*   Character 5:  `'I'` (ASCII 73)  - 5 = 68  $\rightarrow$ 'D'
*   Character 6:  `'H'` (ASCII 72)  - 6 = 66  $\rightarrow$ 'B'
*   Character 7:  `'9'` (ASCII 57)  - 7 = 50  $\rightarrow$ '2'
*   Character 8:  `'b'` (ASCII 98)  - 8 = 90  $\rightarrow$ 'Z'
*   Character 9:  `'_'` (ASCII 95)  - 9 = 86  $\rightarrow$ 'V'
*   Character 10: `'C'` (ASCII 67)  - 10 = 57 $\rightarrow$ '9'
*   Character 11: `'@'` (ASCII 64)  - 11 = 53 $\rightarrow$ '5'
*   Character 12: `'n'` (ASCII 110) - 12 = 98 $\rightarrow$ 'b'
*   Character 13: `'@'` (ASCII 64)  - 13 = 51 $\rightarrow$ '3'
*   Character 14: `'d'` (ASCII 100) - 14 = 86 $\rightarrow$ 'V'
*   Character 15: `'H'` (ASCII 72)  - 15 = 57 $\rightarrow$ '9'

### 5.2 Python solver

```python
import base64

target = b"e3nifIH9b_C@n@dH"

# Step 1: undo "dest[j] += j"
b64 = bytes((c - j) & 0xFF for j, c in enumerate(target))
print("after undoing the shift:", b64)          # b'e2lfbDB2ZV95b3V9'

# Step 2: undo Base64
answer = base64.b64decode(b64)
print("answer:", answer.decode())               # {i_l0ve_you}
```

### 5.3 Verify by running the program's logic forward

The best check is to implement the program's check and test the answer. A solver that was never verified is only a guess.

```python
import base64

TARGET = b"e3nifIH9b_C@n@dH"

def check(user_input: bytes) -> bool:
    enc = base64.b64encode(user_input)                       # Base64
    shifted = bytes((c + j) & 0xFF for j, c in enumerate(enc))  # dest[j] += j
    n = len(shifted)
    return shifted[:n] == TARGET[:n]                         # strncmp(dest, target, strlen(dest))

print(check(b"{i_l0ve_you}"))   # True
print(check(b"wrong"))          # False
```

### 5.4 C solver

The same idea in C: undo the shift, then decode Base64 by hand (no library).

```c
#include <stdio.h>
#include <string.h>

static int b64_index(char c) {
    const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *p = strchr(alphabet, c);
    return p ? (int)(p - alphabet) : -1;
}

int main(void) {
    const char target[] = "e3nifIH9b_C@n@dH";
    int len = (int)strlen(target);        /* 16 */
    char b64[64];

    /* Step 1: undo dest[j] = dest[j] + j */
    for (int j = 0; j < len; j++)
        b64[j] = (char)(target[j] - j);
    b64[len] = '\0';

    /* Step 2: Base64 decode (len is a multiple of 4, no '=' padding) */
    unsigned char out[64];
    int o = 0;
    for (int k = 0; k < len; k += 4) {
        int a = b64_index(b64[k]);
        int b = b64_index(b64[k + 1]);
        int c = b64_index(b64[k + 2]);
        int d = b64_index(b64[k + 3]);
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
        out[o++] = (unsigned char)(((b & 0xF) << 4) | (c >> 2));
        out[o++] = (unsigned char)(((c & 0x3) << 6) | d);
    }
    out[o] = '\0';

    printf("Base64 text: %s\n", b64);     /* e2lfbDB2ZV95b3V9 */
    printf("Answer     : %s\n", out);     /* {i_l0ve_you} */
    return 0;
}
```

Compile and run:

```bash
gcc -o solve solve.c && ./solve
```

### 5.5 The decoding math (why the bit-shifts work)

Base64 packs 3 bytes (24 bits) into 4 characters of 6 bits each:

```
bytes:     b0        b1        b2
bits:   aaaaaabb  bbbbcccc  ccdddddd
chars:  [aaaaaa] [bbbbbb]  [cccccc] [dddddd]
         idx a    idx b     idx c    idx d
```

Decoding rebuilds the bytes from the four 6-bit values `a, b, c, d`:

```
b0 = (a << 2) | (b >> 4)
b1 = ((b & 0xF) << 4) | (c >> 2)
b2 = ((c & 0x3) << 6) | d
```

That's exactly what the C solver does.


---

## 6. A Quirk: `strncmp` With `strlen(dest)` as the Length

Look again at the final comparison:

```c
strncmp(dest, target, strlen(dest))
```

The length used is that of the user's **transformed** input, not of the target. So the program only compares as many characters as the input produced. That means a **prefix** of the correct answer can pass too. For example, the first 3 bytes `{i_` encode to 4 characters that, after the shift, become `e3ni`, which is exactly the start of the target:

```python
print(check(b"{i_"))        # True  -- a short prefix passes
print(check(b"{i_l0v"))     # True
print(check(b"{i_l0ve_y"))  # True
print(check(b"{i_l0ve_you}"))  # True -- the full answer
```

Only prefixes whose Base64 length is a multiple of 4 (no `=` padding) work, because `=` would break the match. This is a nice reminder that **a comparison is only as strong as its length argument**: using the wrong buffer's length in `strncmp` / `memcmp` is a classic real-world bug.

(I derived this from the disassembly: the length argument pushed to `strncmp` is the result of `strlen(dest)`. You can confirm it by running `check()` above, or by testing in a VM.)

---

## 7. Patching the Binary

Solving the challenge means finding the right input. **Patching** is a different skill: changing the program itself so the decision no longer depends on the input. This is only done here on a challenge binary made for practice; I only patch binaries that I'm allowed to modify.

### 7.1 Find the decision point

The whole check boils down to one conditional jump after `strncmp`:

```asm
0x0041583e   test eax, eax
0x00415840   jz   0x415851          ; zero (equal) -> "rigth flag!"
0x00415842   push str.wrong_flag    ; otherwise -> "wrong flag!"
```

Whatever the user types, the program only asks one question: *"is `eax` zero?"* If we change the jump, we change the answer to that question.

### 7.2 Choose a patch

| Change | Bytes | Effect |
|---|---|---|
| `jz` -> **`jmp`** | `74 0f` -> `eb 0f` | Every input prints `rigth flag!` |
| `jz` -> `jnz` | `74 0f` -> `75 0f` | Logic inverted: wrong input accepted, correct input rejected |
| `jz` -> two `nop`s | `74 0f` -> `90 90` | Never jumps: always `wrong flag!` |

Why these bytes work: a short `jz` is 2 bytes, `74` (opcode) and `0f` (relative offset). The success branch starts `0x0f` bytes after the end of the jump instruction (`0x415842 + 0x0f = 0x415851`). The unconditional short jump `jmp` uses opcode `eb` with the **same** offset, so only the first byte has to change.

I chose `jz` -> `jmp`.

### 7.3 Patch with Rizin

Always work on a copy and open it in write mode (`-w`):

```
cp reverse_3.exe reverse_3_patched.exe
rizin -w reverse_3_patched.exe
[0x00411046]> aaa
[0x00411046]> s 0x415840
[0x00415840]> pd 1
│       ┌─< 0x00415840      jz    0x415851
[0x00415840]> wx eb0f
[0x00415840]> pd 1
│       ┌─< 0x00415840      jmp   0x415851
[0x00415840]> q
```

`wx` writes raw hex bytes. Alternatively `wa jmp 0x415851` lets Rizin assemble the instruction for you. Disassembling before **and** after the write confirms the patch landed where intended.

### 7.4 Verify that exactly one byte changed

Don't just trust the tool; compare the two files byte by byte:

```bash
cmp -l reverse_3.exe reverse_3_patched.exe
19521 164 353
```

How to read it:

| Field | Meaning |
|---|---|
| `19521` | Byte position, **1-based**, so the 0-based file offset is `19520` = `0x4C40` |
| `164` | Original byte in **octal**: `0o164` = `0x74` = `jz` |
| `353` | New byte in octal: `0o353` = `0xEB` = `jmp` |

Only one line is printed, so the `0f` offset byte was left untouched, as expected.

> **Virtual address vs file offset:** Rizin shows virtual addresses (`0x415840`), but a patcher script edits the **file**, so it needs the file offset (`0x4C40`). Rizin can convert it for you with `?p 0x415840`. Mixing these two up is the most common patching mistake.

### 7.5 A reusable patcher script

Anyone with the original file can reproduce the patch. The script checks the original bytes first, so it refuses to touch the wrong file or the wrong offset:

```python
import shutil, sys

src, dst = "reverse_3.exe", "reverse_3_patched.exe"
offset   = 0x4C40                    # file offset of the `jz` (VA 0x415840)
original = bytes.fromhex("740f")     # jz  0x415851
patched  = bytes.fromhex("eb0f")     # jmp 0x415851

shutil.copyfile(src, dst)
with open(dst, "r+b") as f:
    f.seek(offset)
    if f.read(2) != original:
        sys.exit("bytes at offset don't match; wrong file or wrong offset")
    f.seek(offset)
    f.write(patched)
print("patched OK")
```

Running it printed `patched OK`, and `cmp -l` afterwards again showed the same single changed byte.

### 7.6 Expected behavior

With the patch applied, the program still reads the input, still Base64-encodes it and still shifts the characters. It just **ignores the result of the comparison**. So any input, even `abc`, should print `rigth flag!`.


### 7.7 Patching is not solving

Patching changed the *message*, but it did not reveal the answer. In this challenge the flag **is the input** (`{i_l0ve_you}`), and the program never stores it. Reversing the algorithm was the real solution; patching is a way to bypass the check.

**Static patching vs runtime jumping:** earlier I used `jump giveFlag` in gdb, which only changes execution in memory for one run. A patch modifies the file, so the change is **permanent**.

---

## 8. Why `strings` Alone Wasn't Enough

- `strings` revealed the Base64 alphabet and the odd 16-character target, but **neither is the answer**.
- The answer was never stored. It is the result of **undoing two transformations**, so we had to read the code to learn what those transformations are.

This is the same lesson as the earlier ELF crackmes: simple obfuscation (here Base64 plus an index shift) defeats `strings`, but not someone who reads the logic.

---

## 9. Key Takeaways

- **Recognize compiler noise.** `0xCCCCCCCC` fills, stack cookies, `cmp esi, esp` after calls, and bounds-check calls are Debug-build extras. Skim past them and focus on the loops and comparisons.
- **Read pushes carefully in 32-bit code.** Arguments can be pushed early, and the `add esp, N` after each call tells you how many were consumed.
- **The Base64 alphabet in `.rdata` is a strong hint** that Base64 is used. Confirm it by looking at the function.
- **Odd-looking constants** (like `e3nifIH9b_C@n@dH`) are often encoded data. Ask "what transformations produced this?"
- **To solve a transformation pipeline, reverse it step by step**, starting from the target, and **always verify** by running the forward logic.
- **Check the comparison itself.** The `strncmp` length argument created a surprising extra behavior.
- Don't trust display glitches (like `0x4x*1`); check them against the logic.
- **Patching changes the decision, not the secret.** Flip the one conditional jump (`jz` -> `jmp`), but verify with `cmp -l` that exactly one byte changed, and remember virtual address and file offset are different things.

## 10. Tools

`rizin` (`aaa`, `iI`, `iz`, `afl`, `pdf`, `axt`, and `-w` with `wx` for patching), `cmp -l`, Python 3 (`base64`), `gcc`

## 11. Practice Ideas

1. Change the index shift to `dest[j] ^= j` in your own C version, then write the solver for it.
2. Write your own `base64_encode` in C and compare its output to Python's `base64` module.
3. Patch the binary the other way: turn `jz` into `jnz` and see how the behavior inverts. Then find the file offset yourself with `?p`.
4. Reproduce the Debug noise: compile a tiny program with MSVC in Debug mode and find the `0xCC` fill and the stack cookie in the disassembly.

---
