CTF Write-up: easyre (Reverse Engineering)

## 📝 Challenge Description
* **Category:** Reverse Engineering
* **Difficulty:** Easy
* **Platform/Context:** CTF Binary Analysis
* **Target Artifact:** `easyre.exe` (x86_64 Windows PE Executable)
**Author:** Gantosay

---

## 🔍 Phase 1: Initial Gathering & Information
Since the binary is a Windows executable (`.exe`), the analysis was performed on a **Ubuntu Linux** environment using modern open-source reverse engineering tools. 

First, we can inspect the binary's basic properties using the `file` command:
```bash
file easyre.exe
```
This confirms the file is a **64-bit PE (Portable Executable)** binary. To dive straight into the code layout, I leveraged **Rizin** (a modern, fast fork of Radare2) to perform auto-analysis:

```bash
rizin -A easyre.exe
```

---

## 💻 Phase 2: Static Analysis
Navigating to it via `pdf` (Print Disassembled Function) provided the following assembly disassembly:

```assembly
WARNING: '10h' uses a deprecated trailing base suffix; use the 0x prefix (0x10) instead
WARNING: '10h' uses a deprecated trailing base suffix; use the 0x prefix (0x10) instead
            ; CALL XREF from dbg.__tmainCRTStartup @ 0x4013b0
┌ int main()
│           ; var int var_10h @ stack - 0x10
│           ; var int var_ch @ stack - 0xc
│           0x004014f0      push  rbp                                  ; easyre.cpp:3
│           0x004014f1      mov   rbp, rsp
│           0x004014f4      sub   rsp, 0x30
│           0x004014f8      call  dbg.__main                           ;  __main(void)
│           0x004014fd      lea   rdx, qword [var_10h]                 ; easyre.cpp:5
│           0x00401501      lea   rax, qword [var_ch]
│           0x00401505      mov   r8, rdx
│           0x00401508      mov   rdx, rax
│           0x0040150b      lea   rcx, qword [str.d_d]                 ; section..rdata
│                                                                      ; 0x429000 ; "%d%d" ; const char *format
│           0x00401512      call  sym.scanf                            ; int scanf(const char *format)
│           0x00401517      mov   edx, dword [var_ch]                  ; easyre.cpp:6
│           0x0040151a      mov   eax, dword [var_10h]
│           0x0040151d      cmp   edx, eax
│       ┌─< 0x0040151f      jnz   0x40152f
│       │   0x00401521      lea   rcx, qword [str.flag_this_Is_a_EaSyRe] ; easyre.cpp:7 ; 0x429005 ; "flag{this_Is_a_EaSyRe}" ; const char *format
│       │   0x00401528      call  sym.printf                           ; int printf(const char *format)
│      ┌──< 0x0040152d      jmp   0x40153b
│      │└─> 0x0040152f      lea   rcx, qword [str.sorry_you_can_t_get_flag] ; easyre.cpp:9 ; 0x42901c ; "sorry,you can't get flag" ; const char *format
│      │    0x00401536      call  sym.printf                           ; int printf(const char *format)
│      │    ; CODE XREF from dbg.main @ 0x40152d
│      └──> 0x0040153b      mov   eax, 0x00                            ; easyre.cpp:11
│       ┌─< 0x00401540      jmp   0x40154a
..
│       │   ; CODE XREF from dbg.main @ 0x401540
│       └─> 0x0040154a      add   rsp, 0x30                            ; easyre.cpp:12
│           0x0040154e      pop   rbp
└           0x0040154f      ret
```

### Key Technical Breakdown:
1. **Stack Allocation (`0x004014f4`):** The program reserves `0x30` bytes on the stack frame. It allocates two distinct integer buffers: `var_ch` (at `stack - 0xc`) and `var_10h` (at `stack - 0x10`).
2. **User Input Handling (`0x004014fd - 0x00401512`):** The addresses of both local variables are loaded into the appropriate registers (`rdx` and `rax`) and passed as references into `sym.scanf`. The format controller loaded from `.rdata` is `"%d%d"`, pointing to an expectation of two integers.
3. **The Validation Gate (`0x00401517 - 0x0040151f`):** 
   * The program moves the values of the two stored inputs into `edx` and `eax`.
   * It runs a `cmp edx, eax` operation, which internally subtracts the registers to set CPU flags.
   * A conditional jump `jnz 0x40152f` (Jump if Not Zero / Not Equal) controls the execution branch.
4. **Branching Results:**
   * **Branch A (Inputs are NOT equal):** The program jumps to `0x0040152f`, references the string `"sorry,you can't get flag"`, prints the failure string, and exits.
   * **Branch B (Inputs ARE equal):** The `jnz` instruction falls through. The binary references the hardcoded string literal at address `0x429005` containing the flag, prints it via `sym.printf`, and cleanly drops out.

---

## 🛠️ Phase 3: Source Code Reconstruction
Based on the exact control flow graph, stack offsets, and imported C-runtime symbols (`scanf`/`printf`), the high-level original **C++ source code** (`easyre.cpp`) can be seamlessly decompiled and modeled as follows:

```cpp
#include <iostream>
#include <cstdio>

int main() {
    // Stack allocation for local integers
    int var_ch;   // Input 1
    int var_10h;  // Input 2

    // Corresponds to: call sym.scanf with format string "%d%d"
    if (scanf("%d%d", &var_ch, &var_10h) != 2) {
        return 1;
    }

    // Corresponds to: cmp edx, eax followed by jnz
    if (var_ch == var_10h) {
        // Fall-through path
        printf("flag{this_Is_a_EaSyRe}\n");
    } else {
        // jnz target path (0x0040152f)
        printf("sorry,you can't get flag\n");
    }

    // Clean exit routine (mov eax, 0x00)
    return 0;
}
```


