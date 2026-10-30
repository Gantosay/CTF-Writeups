# Writeup: Reverse Engineering and Patching Challenge "BUUCTF Rome"

This writeup documents the step-by-step technical analysis, vulnerability discovery, dynamic patching, and mathematical reversal of the **Rome** Windows reverse engineering challenge using **Rizin** on Linux.

---

## 1. Initial Triage & Static Analysis

I started by examining the compiled Windows binary (`rome.exe`) inside Rizin using static analysis tools. Our goal was to uncover embedded telemetry, layout formats, and important string assets.

### Command Executed:
```text
rizin rome.exe
[0x00401280]> iz
```

### Discovered Strings:
* `0x00001600` `0x00403000`  13   14 .rdata        ascii   `libgcj-13.dll`
* `0x0000160e` `0x0040300e`  19   20 .rdata        ascii   `_Jv_RegisterClasses`
* `0x00001624` `0x00403024`  13   14 .rdata        ascii   `Please input:`
* `0x00001635` `0x00403035`  16   17 .rdata        ascii   `You are correct!`


From the output of the string dumping tool (`iz`), several key references stood out:
* `0x00403024`: `"Please input:"` — Prompt signaling that the binary accepts command-line input via standard input (`scanf`).
* `0x00403035`: `"You are correct!"` — The critical success block indicating a valid flag has been evaluated.
* `GCC: (tdm-1) 4.9.2` — Information about the environment compiler used to construct the target binary.

### Finding References (`Cross-References`):
To locate the code block controlling the application's logic, I ran a global analysis and looked up references pointing directly to the success message:

```text
[0x00401280]> aa
[0x00401280]> s 0x00403035
[0x00403035]> axt
sym._func 0x4014fd [DATA] mov dword [esp], str.You_are_correct
```

This confirmed that the core execution logic resides inside a single modular routine named `sym._func`.

---

## 2. Deep Dive Assembly Analysis

By analyzing `sym._func`, we uncovered two major validation mechanisms: an early gatekeeper check and a custom mathematical loop.

### Phase A: The Hidden Gatekeeper (Length & Format)
Right at the function prologue, after memory space is reserved on the execution stack, the binary sets up a hardcoded cipher key directly in memory:

```asembly
[0x004014a0]> s sym._func
[0x00401340]> pd 30

 sym._func();
│ stack: 29 (vars 29, args 0)
│ rg: 0 (vars 0, args 0)
│           0x00401340      push  ebp
│           0x00401341      mov   ebp, esp
│           0x00401343      sub   esp, 0x58
│           0x00401346      mov   byte [var_21h], 0x51                 ; 'Q' ; 81
│           0x0040134a      mov   byte [var_20h], 0x73                 ; 's' ; 115
│           0x0040134e      mov   byte [var_1fh], 0x77                 ; 'w' ; 119
│           0x00401352      mov   byte [var_1eh], 0x33                 ; '3' ; 51
│           0x00401356      mov   byte [var_1dh], 0x73                 ; 's' ; 115
│           0x0040135a      mov   byte [var_1ch], 0x6a                 ; 'j' ; 106
│           0x0040135e      mov   byte [var_1bh], 0x5f                 ; '_' ; 95
│           0x00401362      mov   byte [var_1ah], 0x6c                 ; 'l' ; 108
│           0x00401366      mov   byte [var_19h], 0x7a                 ; 'z' ; 122
│           0x0040136a      mov   byte [var_18h], 0x34                 ; '4' ; 52
│           0x0040136e      mov   byte [var_17h], 0x5f                 ; '_' ; 95
│           0x00401372      mov   byte [var_16h], 0x55                 ; 'U' ; 85
│           0x00401376      mov   byte [var_15h], 0x6a                 ; 'j' ; 106
│           0x0040137a      mov   byte [var_14h], 0x77                 ; 'w' ; 119
│           0x0040137e      mov   byte [var_13h], 0x40                 ; '@' ; 64
│           0x00401382      mov   byte [var_12h], 0x6c                 ; 'l' ; 108
│           0x00401386      mov   byte [var_11h], 0x00
│           0x0040138a      mov   dword [esp], str.Please_input:       ; [0x403024:4]=0x61656c50 ; "Please input:" ; const char *format
│           0x00401391      call  sym._printf                          ; int printf(const char *format)
│           0x00401396      lea   eax, dword [var_38h]
│           0x00401399      mov   dword [var_58h], eax
│           0x0040139d      mov   dword [esp], str.s                   ; [0x403032:4]=0x59007325 ; "%s" ; const char *format
│           0x004013a4      call  sym._scanf                           ; int scanf(const char *format)
│           0x004013a9      movzx eax, byte [var_38h]
│           0x004013ad      cmp   al, 0x41                             ; 'A' ; 65
│       ┌─< 0x004013af      jnz   0x4013d1
│       │   0x004013b1      movzx eax, byte [var_37h]

```

```assembly
0x00401346      mov   byte [var_21h], 0x51                 ; 'Q'
0x0040134a      mov   byte [var_20h], 0x73                 ; 's'
0x0040134e      mov   byte [var_1fh], 0x77                 ; 'w'
0x00401352      mov   byte [var_1eh], 0x33                 ; '3'
...
0x00401382      mov   byte [var_12h], 0x6l                 ; 'l'
```

Concatenating these raw hexadecimal values reveals the internal target signature string:
**`Qsw3sj_lz4_Ujw@l`**

Directly following `scanf`, an early check evaluates the input's layout structure:
```assembly
0x004013a9      movzx eax, byte [var_38h]
0x004013ad      cmp   al, 0x41                             ; 'A'
0x004013af      jnz   0x4013d1                             ; Early exit trap
```
This serves as a format parser verifying the challenge wrapper framework (`ACTF{`). If the header framework doesn't match perfectly, the binary takes a silent jump branch straight to `leave` and `ret`, exiting without printing anything.

### Phase B: The Cipher Loop Mechanics
If the header gatekeeper is passed, the program slices off the first 5 characters (`ACTF{`) and copies the inner text block to a processing array (`var_48h`). It then executes a math transformation loop over a range constraint of `0x0f` (15 characters):

```assembly
[0x004014a0]> pd 30 @ 0x00401400

     0x00401400      mov   dword [var_10h], 0x00
│       ┌─< 0x00401407      jmp   0x4014c4
│       │   0x0040140c      lea   edx, dword [var_48h]
│       │   0x0040140f      mov   eax, dword [var_10h]
│       │   0x00401412      add   eax, edx
│       │   0x00401414      movzx eax, byte [eax]
│       │   0x00401417      cmp   al, 0x40                             ; '@' ; 64
│      ┌──< 0x00401419      jle   0x401466
│      ││   0x0040141b      lea   edx, dword [var_48h]
│      ││   0x0040141e      mov   eax, dword [var_10h]
│      ││   0x00401421      add   eax, edx
│      ││   0x00401423      movzx eax, byte [eax]
│      ││   0x00401426      cmp   al, 0x5a                             ; 'Z' ; 90
│     ┌───< 0x00401428      jnle  0x401466
│     │││   0x0040142a      lea   edx, dword [var_48h]
│     │││   0x0040142d      mov   eax, dword [var_10h]
│     │││   0x00401430      add   eax, edx
│     │││   0x00401432      movzx eax, byte [eax]
│     │││   0x00401435      movsx eax, al
│     │││   0x00401438      lea   ecx, dword [eax-0x33]
│     │││   0x0040143b      mov   edx, 0x4ec4ec4f
│     │││   0x00401440      mov   eax, ecx
│     │││   0x00401442      imul  edx
│     │││   0x00401444      sar   edx, 0x03
│     │││   0x00401447      mov   eax, ecx
│     │││   0x00401449      sar   eax, 0x1f
│     │││   0x0040144c      sub   edx, eax
│     │││   0x0040144e      mov   eax, edx
│     │││   0x00401450      imul  eax, eax, 0x1a
│     │││   0x00401453      sub   ecx, eax

```


```assembly
0x00401417      cmp   al, 0x40                             ; Check lower bound '@'
0x00401419      jle   0x401466                             ; Jump if not Uppercase
0x00401426      cmp   al, 0x5a                             ; Check upper bound 'Z'
0x00401428      jnle  0x401466                             ; Jump if not Uppercase
0x00401438      lea   ecx, dword [eax-0x33]                ; Subtract 51
0x0040143b      mov   edx, 0x4ec4ec4f                      ; Division Magic Number for 26
0x00401442      imul  edx                                  ; Multiply 
0x00401444      sar   edx, 0x03                            ; Shift right (Modulo 26 calculation)
```

The transformation consists of two distinct mathematical conditions:
1. **Uppercase alphabet bounds (`A-Z`):** Shifts the character code using the equation: `((Char - 51) % 26) + 65` (equivalent to an alphanumeric ROT13 rotation).
2. **Lowercase alphabet bounds (`a-z`):** Shifts the character code via a fallback block using the equation: `((Char - 79) % 26) + 97` (equivalent to an 11-step rotation).
3. **Symbols and Numbers:** Completely bypasses the shift loops, keeping elements like `_`, `@`, and numbers unchanged.

### Phase C: Character Validation Check
Finally, the modified string data is cross-checked item-by-item against the hardcoded target string:

```assembly
[0x00403035]> s 0x004014a0
[0x004014a0]> pd 40

│       ╎   0x004014a0      add   ecx, dword [ecx+0x1ff8c1c8]
│       ╎   0x004014a6      sub   edx, eax
│       ╎   0x004014a8      mov   eax, edx
│       ╎   0x004014aa      imul  eax, eax, 0x1a
│       ╎   0x004014ad      sub   ecx, eax
│       ╎   0x004014af      mov   eax, ecx
│       ╎   0x004014b1      add   eax, 0x61                            ; 97
│       ╎   0x004014b4      mov   ecx, eax
│       ╎   0x004014b6      lea   edx, dword [var_48h]
│       ╎   0x004014b9      mov   eax, dword [var_10h]
│       ╎   0x004014bc      add   eax, edx
│       ╎   0x004014be      mov   byte [eax], cl
│       ╎   0x004014c0      add   dword [var_10h], 0x01
│       ╎   ; CODE XREF from sym._func @ 0x401407
│       ╎   0x004014c4      cmp   dword [var_10h], 0x0f
│       └─< 0x004014c8      jle   0x40140c
│           0x004014ce      mov   dword [var_10h], 0x00
│       ┌─< 0x004014d5      jmp   0x4014f7
│      ┌──> 0x004014d7      lea   edx, dword [var_48h]
│      ╎│   0x004014da      mov   eax, dword [var_10h]
│      ╎│   0x004014dd      add   eax, edx
│      ╎│   0x004014df      movzx edx, byte [eax]
│      ╎│   0x004014e2      lea   ecx, dword [var_21h]
│      ╎│   0x004014e5      mov   eax, dword [var_10h]
│      ╎│   0x004014e8      add   eax, ecx
│      ╎│   0x004014ea      movzx eax, byte [eax]
│      ╎│   0x004014ed      cmp   dl, al
│     ┌───< 0x004014ef      jz    0x4014f3
│    ┌────< 0x004014f1      jmp   0x40150a
│    │└───> 0x004014f3      add   dword [var_10h], 0x01
│    │ ╎│   ; CODE XREF from sym._func @ 0x4014d5
│    │ ╎└─> 0x004014f7      cmp   dword [var_10h], 0x0f
│    │ └──< 0x004014fb      jle   0x4014d7
│    │      0x004014fd      mov   dword [esp], str.You_are_correct     ; [0x403035:4]=0x20756f59 ; "You are correct!" ; const char *format
│    │      0x00401504      call  sym._printf                          ; int printf(const char *format)
│    │      0x00401509      nop

```



```assembly
0x004014ed      cmp   dl, al
0x004014ef      jz    0x4014f3
0x004014f1      jmp   0x40150a                             ; Failure trap
```
If a single character fails validation, it drops into the failure trap, skipping the success statement entirely. Furthermore, because the success statement lacks a newline terminator (`\n`), output buffering can cause standard terminals to discard the printed buffer upon exit, adding another layer of confusion.

---

## 3. Algorithmic Key Reversal (Python)

To solve the challenge cleanly without guess-work, I write a reversal script. By testing every ASCII character against the exact mathematical constraints of the binary, we determine which inputs accurately map to the target array `Qsw3sj_lz4_Ujw@l`.

```python
target = "Qsw3sj_lz4_Ujw@l"
flag_chars = ""

for char in target:
    
    found = False
    for x in range(32, 127):
        temp = x
        if 64 < temp <= 90:    
            temp = (temp - 51) % 26 + 65
        elif 96 < temp <= 122:  
            temp = (temp - 79) % 26 + 97
            
        if chr(temp) == char:
            flag_chars += chr(x)
            found = True
            break
    if not found:
        flag_chars += char

print(f"Inside bracket: {flag_chars}")

```

---

## 4. Advanced Binary Patching Guide

I explored two separate patching strategies inside Rizin to modify the application's runtime logic.

### Strategy 1: Neutralizing individual validation gates
By overwriting the conditional instruction paths inside the string loop, we can trick the logic gate into ignoring character mismatches.

```text
# Open binary in read-write mode
rizin -w rome.exe

# Navigate to the loop conditional jump step
[0x00401280]> s 0x004014ef

# Change conditional jump (jz) to an unconditional jump (jmp)
[0x004014ef]> wx eb

# Fill the old failure trap branch space with NOP instructions
[0x004014ef]> s 0x004014f1
[0x004014f1]> wx 9090
```

*Result:* While this cleanly handles character checks, it still requires the input to pass the early length gatekeeper.

### Strategy 2: The Ultimate Entry Point Hijack (Full Bypass)
To bypass every single validation step, length check, and input condition completely, we can hijack the function entry point. By placing a direct jump at the very first line of functional code inside `_func`, the program skips input processing entirely and jumps directly to the success block.

I calculate the little-endian layout for an absolute long jump (`jmp 0x004014fd`) from address `0x00401346` to get the opcode array `e9b2010000`.

```text
# Open binary in read-write mode
rizin -w rome.exe

# Seek to the primary instruction location after the stack prologue
[0x00401280]> s 0x00401346

# Directly overwrite instructions with our calculated relative jump opcode
[0x00401346]> wx e9b2010000

# Verify the modification
[0x00401346]> pd 5 @ 0x00401340
```

### Verified Disassembly Output after Patch:
```assembly
;-- _func:
0x00401340      push  ebp
0x00401341      mov   ebp, esp
0x00401343      sub   esp, 0x58
0x00401346      jmp   0x4014fd                             ; Hijacked! Directly jumps to victory
0x0040134b      inc   ebp
```

When I close the session (`q`) and run `./rome.exe`, the program skips `scanf` entirely and instantly prints out `You are correct!`, finalizing a complete logic bypass!

---

## 5. Decompiled Source Structure (C Code)

Below is the reconstructed layout of the author's original source implementation, illustrating how the validation gates, custom Caesar wheel transformations, and conditional loops were architected.

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void func() {
    // 1. Encrypted target string hidden in memory (Qsw3sj_lz4_Ujw@l)
    char encrypted_target[17] = {
        0x51, 0x73, 0x73, 0x33, 0x73, 0x6a, 0x5f, 0x6c, 
        0x7a, 0x34, 0x5f, 0x55, 0x6a, 0x77, 0x40, 0x6c, 0x00
    };
    
    char input[100];
    char processed_input[17];
    int i;

    printf("Please input:");
    scanf("%s", input);

    // 2. Early validation check for the flag format (ACTF{)
    // If the input doesn't start with the correct header, it exits silently
    if (input[0] != 'A' || input[1] != 'C' || input[2] != 'T' || input[3] != 'F' || input[4] != '{') {
        return;
    }

    // 3. Extract the inner content inside the brackets (skipping the first 5 chars "ACTF{")
    for (i = 0; i < 16; i++) {
        processed_input[i] = input[i + 5];
    }
    processed_input[16] = '\0';

    // 4. Main custom Caesar cipher encryption loop
    for (i = 0; i < 16; i++) {
        char c = processed_input[i];

        if (c >= 'A' && c <= 'Z') {
            // Uppercase transformation (13-step shift)
            processed_input[i] = ((c - 51) % 26) + 65;
        } 
        else if (c >= 'a' && c <= 'z') {
            // Lowercase transformation (11-step shift)
            processed_input[i] = ((c - 79) % 26) + 97;
        }
        // Special characters (_, @) and numbers are left completely unchanged
    }

    // 5. Character-by-character validation loop against the encrypted target
    for (i = 0; i < 16; i++) {
        if (processed_input[i] != encrypted_target[i]) {
            return; // Loser trap: exits silently if even a single character mismatches
        }
    }

    // 6. Success block executed only if all checks pass successfully
    printf("You are correct!");
}

int main() {
    func();
    return 0;
}

```
