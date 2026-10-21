# CTF Write-up: BUUCTF - reverse1 (Windows PE x64)

## 📝 Challenge Description
* **Category:** Reverse Engineering
* **Difficulty:** Easy-Medium
* **Target Artifact:** `reverse1.exe` (64-bit Windows Portable Executable)
* **Objective:** Analyze a compiled, stripped Windows binary to either reconstruct the target input validation algorithm or actively hijack the internal control flow.

---

## 🛡️ Phase 1: Reconnaissance & Triage
The binary analysis was orchestrated inside a **Ubuntu Linux**.
I initiated a static analysis sweep using **Rizin** to extract embedded plain-text strings out of the global read-only data segment (`.rdata`).

```bash
rizin -A reverse1.exe
```

Inside Rizin, executing `iz` (Print Strings in Data Sections) yielded several critical clues:
```text
0x00008a10 0x140019c10  11   12 .rdata  ascii   wrong flag\n
0x00008a90 0x140019c90  24   25 .rdata  ascii   this is the right flag!\n
0x00008b24 0x140019d24   4    5 .rdata  ascii   %20s
0x00008b30 0x140019d30  15   16 .rdata  ascii   input the flag:
0x0000aa00 0x14001c000  13   14 .data   ascii   {hello_world}
```

### Key Triage Insights:
1. **Target Logic Identified:** The strings `"input the flag:"`, `"this is the right flag!"`, and `"wrong flag"` clearly demarcate the main verification gate.
2. **Suspicious Global Const:** A hardcoded string component `{hello_world}` resides distinctly within the mutable `.data` segment at base address `0x14001c000`.
3. **Stripped Roadblock:** Running `s main` failed with an error: `Cannot seek to unknown address 'main'`. The symbol table was completely stripped from the executable file by the compiler.

---

## 🔍 Phase 2: Locating the Hidden Main Function
Since standard symbol flags were stripped, we isolated the underlying verification gate by tracing cross-references (xrefs) originating from the memory address of the user prompt string (`0x140019d30`).

By seeking directly to the string's Virtual Memory Address and running `axt` (Analyze Cross-References To):
```radare2
s 0x140019d30
axt
```

**Output:**
```text
fcn.140011159 0x140011948 [DATA] lea rcx, qword str.input_the_flag:
```

This successfully pinpointed the exact virtual offset of our main routine: **`fcn.140011159`**.

---

## 💻 Phase 3: Assembly Control Flow Graph Analysis
Navigating to `s fcn.140011159` and executing `pdr` (Print Disassembly Recursive) provided the complete execution blueprint:

```assembly
; CALL XREF from fcn.1400123e0 @ 0x14001240f
┌ fcn.140011159();
│ ...
│ 0x1400118ef      mov   dword [var_134h], 0x00
│ 0x1400118f6      jmp   0x140011900
│
│ ; Loop Body
│ 0x140011923      movsxd rax, dword [var_134h]
│ 0x140011927      lea   rcx, qword [str.hello_world]                  ; 0x14001c000 ; "{hello_world}"
│ 0x14001192e      movsx eax, byte [rcx+rax*1]
│ 0x140011932      cmp   eax, 0x6f                                     ; 'o' ; Hex 0x6f
│ 0x140011935      jnz   0x140011946                                   ; Jump if not equal
│ 0x140011937      movsxd rax, dword [var_134h]
│ 0x14001193b      lea   rcx, qword [str.hello_world]
│ 0x140011942      mov   byte [rcx+rax*1], 0x30                        ; '0' ; Overwrite with Hex 0x30
│ 0x140011946      jmp   0x1400118f8
│
│ ; Input & Verification Routine
│ 0x140011948      lea   rcx, qword [str.input_the_flag:]              ; 0x140019d30
│ 0x14001194f      call  fcn.1400111d1                                 ; printf
│ 0x140011954      lea   rdx, qword [s1]                               ; User buffer destination
│ 0x140011958      lea   rcx, qword [str.20s]                          ; "%20s"
│ 0x14001195f      call  fcn.14001128f                                 ; scanf
│ 0x14001197e      call  qword [sym.imp.ucrtbased.dll_strncmp]         ; Compares user input with mutated string
│ 0x140011984      test  eax, eax
│ 0x140011986      jz    0x140011996                                   ; The Guard Gate (Jump if Zero / Equal)
│ 0x140011988      lea   rcx, qword [str.wrong_flag]                   ; Failure path
│ 0x14001198f      call  fcn.1400111d1
└ ...
```

### High-Level Algorithm Analysis:
1. **The In-Memory Mutator Loop:** The binary iterates over the string `{hello_world}` stored at `0x14001c000`. It checks each character against the hex byte `0x6f` (ASCII character `'o'`).
2. **The Substitution:** If a character matches `'o'`, it is dynamically overwritten in-place with hex byte `0x30` (ASCII character `'0'`).
3. **The Validation Phase:** It captures a 20-character input string from the user via `scanf` and feeds it along with the altered memory string into `strncmp`. If they are structurally identical, `strncmp` yields `0`, driving the execution stream directly to the victory path.

---

## 🏆 Solution Method 1: Mathematical String Extraction
Because the obfuscation pattern is simple, the flag can be extracted statically with an open eyes check without any binary execution:

* **In-Memory Original Buffer:** `{hello_world}`
* **Mutation Formula:** Swap every occurrence of `'o'` with `'0'`.
* **Substituted Payload Output:** `{hell0_w0rld}`


---

## 😈 Solution Method 2: Exploit & Crack (Binary Control Flow Hijacking)
Instead of locating the valid key, we can actively crack the checking gate itself so it cleanly prints out a victory status regardless of what garbage input we pass to the binary.

### Decoupling the PE Architecture Mapping Error:
When dealing with Windows Portables Executables (PE), mapping a file offset isn't as simple as checking the Virtual Address due to differing segment properties between memory space and raw storage on the disk.

By execution of `iS` (Info Sections) inside Rizin:
```text
       paddr     size       vaddr       vsize    name
――――――――――――――――――――――――――――――――――――――――――――――――――――――
  0x00000400   0x7a00   0x140011000    0x8000   .text
```

* **Target Gate Virtual Memory Address (VMA):** `0x140011986`
* **Text Section Start Address in RAM:** `0x140011000`
* **Text Section Start Offset on Disk (`paddr`):** `0x00000400`

### Calculating Raw File Offset:
\[Relative Offset} = \{VMA} - \{Section Vaddr} = 0x140011986 - 0x140011000 = 0x986\]
\[{Raw File Disk Offset} = \{Section Paddr} + \{Relative Offset} = 0x400 + 0x986 = 0xD86\]

The execution checkpoint instruction `jz 0x140011996` resides strictly at disk offset **`0xD86`**. Its raw opcode signature is `74 0e` (Conditional Jump Short). By replacing the byte configuration to `eb 0e` (Unconditional Short `jmp`), we force the binary to bypass string correctness evaluation flags entirely.

### Automated Patching Auto-Cracker Script (Python)
The script below targets the computed raw section file offset to transform the target structure instantly:

```python
#!/usr/bin/env python3
"""
Automated Structural PE Binary Patcher for reverse1 Challenge
Author: Gantosay
"""
import os

def apply_control_flow_hijack():
    original_exe = "reverse1.exe"
    cracked_exe = "reverse1_cracked.exe"
    
    # Accurate physical disk target offset calculated via PE section structures
    target_disk_offset = 0xD86
    
    # Patch array conversion blueprint: Swap 74 (jz) -> eb (jmp)
    patch_payload = b'\xeb\x0e'
    
    if not os.path.exists(original_exe):
        print(f"[-] Critical Error: File '{original_exe}' not found inside workspace!")
        return

    # Ingest the target application stream
    with open(original_exe, "rb") as target_file:
        file_bytes = bytearray(target_file.read())
        
    print(f"[+] Loaded raw PE binary footprint into dynamic memory.")
    print(f"[*] Original opcodes tracked at target checkpoint: {file_bytes[target_disk_offset:target_disk_offset+2].hex()}")
    
    # Force patch mutation injection
    file_bytes[target_disk_offset:target_disk_offset+2] = patch_payload
    print(f"[+] Successfully injected unconditional jump modification at offset: {hex(target_disk_offset)}")
    
    # Save the modified cracked clone executable
    with open(cracked_exe, "wb") as output_file:
        output_file.write(file_bytes)
        
    print(f"[+] Executable cracked successfully! Output file built as: ./{cracked_exe}")
    print("[+] Launch the cracked asset inside Windows or Wine and submit any input text to bypass authentication rules!")

if __name__ == "__main__":
    apply_control_flow_hijack()
```

### Verification & Crack Deployment:
```powershell
PS C:\Users\VM\Desktop> .\reverse1_cracked.exe
input the flag: completely_wrong_input_text
this is the right flag!
```


## 🛠️ Source Code Reconstruction & Logic Breakdown

By carefully reverse engineering the compiled machine instructions, mapping the stack parameters, and identifying the control flow branches, we can accurately reconstruct the developer's original **C Source Code**:

```c
#include <stdio.h>
#include <string.h>

// Global buffer holding the misleading honey-pot string at offset 0x14001c000
char flag_buffer[] = "{hello_world}"; 

int main() {
    // --- 1. Runtime Mutator Loop ---
    // This phase triggers immediately at runtime to dynamically patch the memory buffer
    int length = strlen(flag_buffer);
    for (int i = 0; i < length; i++) {
        // Corresponds to: cmp eax, 0x6f ('o')
        if (flag_buffer[i] == 'o') {
            // Corresponds to: mov byte [rcx+rax*1], 0x30 ('0')
            flag_buffer[i] = '0'; 
        }
    }

    // --- 2. User Input Capture ---
    printf("input the flag:"); 
    
    char user_input[100];
    // Captured with the "%20s" width constraint seen in disassembly
    scanf("%20s", user_input); 

    // --- 3. The Validation Check ---
    // Evaluating user input against the dynamically mutated in-memory buffer
    if (strncmp(user_input, flag_buffer, length) == 0) {
        // Triggered via the 'jz' conditional jump instruction on success
        printf("this is the right flag!\n");
    } else {
        // Fall-through failure path
        printf("wrong flag\n");
    }

    return 0;
}
```

### 🧠 Tactical Developer Strategy Breakdown

The source architecture reveals a clever two-phase defensive layout designed to deceive automated triage tools and security analysts who rely purely on shallow static analysis techniques:

1. **The Static Honey-Pot Trap:** The developer intentionally omitted the true, winning flag value (`{hell0_w0rld}`) from the global binary compilation data. Instead, they hardcoded a misleading baseline placeholder string, `{hello_world}`, into the `.data` segment. Anyone relying solely on basic string extraction utilities (like `strings` or Rizin's `iz`) will harvest the incorrect honey-pot string asset.
2. **Just-In-Time Runtime Mutation:** To correctly align the flag state while maintaining static deception on disk, the mutator loop runs instantly upon binary initialization. The CPU performs an in-memory modification sweep across the volatile memory buffer right before the user prompt checkpoint. It executes a substitution algorithm swapping every character byte matching `0x6f` (`'o'`) dynamically to `0x30` (`'0'`).
3. **The Comparative Trap:** When the validation gate calls `strncmp`, it checks your input against the mutated string state (`{hell0_w0rld}`) currently residing in live RAM. Because the real validation vector only exists inside volatile registers and RAM after the application launches, entering the default static text string extracted from the file on disk will invariably yield a `wrong flag` authentication failure. 

This makes the binary an elegant, textbook demonstration of an anti-strings security implementation.

---
