# CTF Write-up: BUUCTF - Happy (UPX Unpacking & Win11 Control Flow Cracking)

## 📝 Challenge Description
* **Category:** Reverse Engineering / Malware Triage
* **Difficulty:** Medium
* **Target Artifact:** `Happy.exe` (32-bit Windows Portable Executable)
* **Core Concepts:** Anti-Analysis (UPX Packing), Windows PE Memory Alignment, Control Flow Hijacking (Binary Patching)

---

## 🛡️ Phase 1: Breaking the Anti-Analysis Shell (UPX Unpacking)
Initial static analysis of the pristine `Happy.exe` binary inside **Rizin** showed heavily obfuscated data. Scanning section headers via `iz` revealed the signature of a well-known packer:

```text
0x00001860 0x0040f060  12   13 UPX2    ascii KERNEL32.DLL
0x0000186d 0x0040f06d  10   11 UPX2    ascii msvcrt.dll
```

The presence of the `UPX2` segment means the original program logic and string headers are fully compressed inside an encrypted capsule. To break this shield, we dropped back to the Ubuntu CLI and ran the native decompression suite:

```bash
upx -d Happy.exe
```
**Output:** `Unpacked 1 file.`

---

## 🔍 Phase 2: Static Reconnaissance & Deep Assembly Mapping
Once un-packed, we loaded the clean footprint back into Rizin. Running the `iz` scan immediately harvested the true plain-text target validation assets out of `.rdata`:

```text
0x00001424 0x00403024  27   28 .rdata  ascii   please input the true flag:
0x00001443 0x00403043  18   19 .rdata  ascii   this is true flag!
0x00001456 0x00403056   6    7 .rdata  ascii   wrong!
0x0000145d 0x0040305d  13   14 .rdata  ascii   HappyNewYear!
```

Seeking directly to the main code block (`s main`) and issuing the `pdf` disassembly routine exposed the absolute machine-level execution flow:

```assembly
0x00401c10      push  ebp
0x00401c11      mov   ebp, esp
0x00401c13      push  edi
0x00401c14      push  esi
0x00401c15      push  ebx
0x00401c16      and   esp, 0xfffffff0
0x00401c19      sub   esp, 0x40
0x00401c1c      call  sym.___main
0x00401c21      lea   edi, dword [var_3eh]
0x00401c25      mov   esi, str.HappyNewYear                        ; 0x40305d ; "HappyNewYear!"
0x00401c2a      mov   ecx, 0x0e                                    ; 0xe ; 14
0x00401c2f      rep   movsb
0x00401c31      mov   ax, word [data.0040306b]
0x00401c37      mov   word [var_30h], ax
0x00401c3c      lea   edi, dword [var_2eh]
0x00401c40      xor   ebx, ebx
0x00401c42      mov   cl, 0x1e                             ; 30
0x00401c44      mov   al, bl
0x00401c46      rep   stosb
0x00401c48      mov   dword [esp], str.please_input_the_true_flag ; 0x403024 ; "please input the true flag:" ; const char *format
0x00401c4f      call  sym._printf                          ; int printf(const char *format)
0x00401c54      lea   esi, dword [var_30h]
0x00401c58      mov   dword [s2], esi
0x00401c5c      mov   dword [esp], str.s                   ; 0x403040 ; "%s" ; const char *format
0x00401c63      call  sym._scanf                           ; int scanf(const char *format)
0x00401c68      lea   edx, dword [var_3eh]
0x00401c6c      mov   ecx, 0xffffffff                      ; -1
0x00401c71      mov   al, bl
0x00401c73      repne scasb
0x00401c77      not   ecx
0x00401c79      dec   ecx
0x00401c7a      mov   dword [n], ecx                       ; size_t n
0x00401c7e      mov   dword [s2], edx                      ; const char *s2
0x00401c82      mov   dword [esp], esi                     ; const char *s1
0x00401c85      call  sym._strncmp                         ; int strncmp(const char *s1, const char *s2, size_t n)
0x00401c8a      test  eax, eax
0x00401c8c      jz    0x401ca2
```
---

### Detailed Assembly Operation Breakdown:
* **`0x00401c25 - 0x00401c2f` (`Buffer Setup`):** The program loads the memory location of the static hardcoded string `"HappyNewYear!"` into the source index register `esi`. It defines a size counter of 14 bytes (`0x0e`) inside `ecx` and fires `rep movsb` to quickly copy the correct flag key into a local stack buffer variable (`var_3eh`).
* **`0x00401c48 - 0x00401c4f` (`User Prompt`):** The pointer to the format string `"please input the true flag:"` is pushed onto the top of the stack execution layout (`[esp]`), and `sym._printf` is invoked to print the prompt message to the terminal console window.
* **`0x00401c5c - 0x00401c63` (`Input Ingestion`):** The program loads the format identifier `"%s"` and calls `sym._scanf` to actively capture the string sequence submitted by the user, dynamically writing it straight into the local stack buffer variable `var_30h` (pointed to by `esi`).
* **`0x00401c68 - 0x00401c7a` (`String Length Calculation`):** This is a compiled inline adaptation of `strlen`. By initializing `ecx` to `-1` (`0xffffffff`) and searching using `repne scasb` for a null terminator byte (`\x00`), the CPU calculates the exact length constraint of the string and updates the `size_t n` parameter at stack location `[n]`.
* **`0x00401c85` (`The Cryptographic Checkpoint`):** The application loads the user input reference (`s1`), the correct hardcoded reference variable (`s2`), and the string length variable (`n`) before calling `sym._strncmp`. If both string matrices match perfectly, `strncmp` returns a success score of exactly `0` stored in the `eax` register.
* **`0x00401c8a - 0x00401c8c` (`The Decision Gate`):** `test eax, eax` runs a bitwise verification against the evaluation register. If `eax` is `0`, the CPU's internal **Zero Flag (ZF)** trips to `1`. The conditional instruction `jz 0x401ca2` (Jump if Zero) reads this flag condition. If it evaluates cleanly, the program branches immediately away from the failure route to leap down to the success execution node (`0x401ca2`), printing out `"this is true flag!"`.

---


## 🛠️ Phase 3: Original Source Code Reconstruction (C)
By studying the compiled parameters, string allocations, and runtime execution blocks, we can model the original high-level **C source map**:

```c
#include <stdio.h>
#include <string.h>

int main() {
    // The key value hidden natively in read-only segment
    char target_key[] = "HappyNewYear!";
    char user_input[30];

    printf("please input the true flag:");
    scanf("%s", user_input);

    // Corresponds to: call sym._strncmp followed by jz
    if (strncmp(user_input, target_key, strlen(target_key)) == 0) {
        printf("this is true flag!\n");
    } else {
        printf("wrong!\n");
    }

    return 0;
}
```

---

## 😈 Phase 4: Exploit & Control Flow Hijacking (The Crack)
Instead of typing the key, we target the conditional jump checker at VMA `0x00401c8c` to force an unconditional win.

### Advanced PE Section Cross-Mapping:
To execute a precise file patch, we must compute the exact location of the code on disk using section rules pulled via Rizin's `iS` command:
```text
  paddr       size        vaddr        vsize     name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
0x00000400   0xe00    0x00401000      0x1000    .text
```
* **Target Assembly VMA:** `0x00401c8c`
* **Virtual Base Address of Text Section:** `0x00401000`
* **Raw File Offset of Text Section on Disk:** `0x00000400`

**Mathematical Deduction Formula:**
\[{File Disk Offset} = (\text{0x00401c8c} - \{0x00401000}) + \{0x400} = \{0x108c}\]

The critical gating byte `74 14` (`jz short`) resides at file offset **`0x108c`**. By swapping this byte configuration to `eb 14` (`jmp short`), the program will skip string checking flags and jump straight into the victory routine.

### Cross-Platform Environment Constraint Note:
Executing the patching task directly inside a live **Windows 11** environment can trigger internal real-time AV protection or file-locking telemetry mechanisms, distorting memory alignments and causing patch mismatches (e.g., encountering unrelated byte headers like `c6504149`). To bypass this runtime defense, the patch script was executed natively on a **neutral Linux sandbox environment (Ubuntu)** before transferring the final cracked bundle back to Windows.

### Automated Binary Patcher Script (Python)
```python
#!/usr/bin/env python3
"""
Cross-Platform PE Binary Patcher Tool-Gantosay
"""
import os

def execute_binary_patch():
    target_exe = "Happy.exe"
    cracked_exe = "Happy_cracked.exe"
    
    # Exact physical raw file address mapped from PE offsets
    file_disk_offset = 0x108c
    
    # Overwrite payload: Change 74 (jz) -> eb (jmp)
    patch_payload = b'\xeb\x14'
    
    if not os.path.exists(target_exe):
        print(f"[-] Error: File '{target_exe}' not found in current path!")
        return

    with open(target_exe, "rb") as source:
        binary_stream = bytearray(source.read())
        
    print(f"[+] Successfully loaded raw footprint into stream buffer.")
    print(f"[*] Verified original opcodes: {binary_stream[file_disk_offset:file_disk_offset+2].hex()}")
    
    # Inject the machine instruction patch
    binary_stream[file_disk_offset:file_disk_offset+2] = patch_payload
    print(f"[+] Injected unconditional jump patch at offset: {hex(file_disk_offset)}")
    
    with open(cracked_exe, "wb") as output:
        output.write(binary_stream)
        
    print(f"[+] Success! Cracked software cloned as: ./{cracked_exe}")

if __name__ == "__main__":
    execute_binary_patch()
```

---

## 🧪 Verification Check
Deploying the newly patched cloned binary on **Windows 11** and typing arbitrary placeholder strings immediately triggers the success branch:

```powershell
PS C:\Users\Gantosay\Desktop> .\Happy_cracked.exe
please input the true flag: AAAA
this is true flag!
```

---

## 🏁 Final Flag
**`flag{HappyNewYear!}`**
