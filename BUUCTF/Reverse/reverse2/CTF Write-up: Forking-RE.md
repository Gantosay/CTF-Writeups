# CTF Write-up: Forking-RE (Reverse Engineering & Anti-Analysis & Cracking)

## 📝 Challenge Description
* **Category:** Reverse Engineering / Binary Analysis
* **Difficulty:** Medium
* **Architecture:** Linux x86_64 (ELF Binary)
* **Concepts:** Multiprocessing (`fork`), Shared Memory Mutex, Exploit Mitigations (Stack Canary)

---

## 🛡️ Phase 1: Security Triage & Binary Mitigations
Before looking into the assembly control flow, a checksec analysis was performed on the binary to evaluate its built-in exploit mitigations.

```text
Arch:       amd64-64-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
Stripped:   No
```

### Key Architectural Findings:
1. **Stack Canary Found:** The compiler inserted a safety stack guard. This is corroborated in the disassembly by the initialization block `mov rax, QWORD PTR fs:0x28` [0x0040077d] and the epilogue check `xor rdx, QWORD PTR fs:0x28` [0x0040081d], preventing standard Stack Buffer Overflow attacks.
2. **NX Enabled:** No-Execute prevents execution from stack space.
3. **No PIE (`0x400000`):** Position Independent Executable is disabled. Memory mapping layouts remain static, meaning memory markers such as `0x601080` are absolute and un-randomized [0x004007ac, 0x0040081d].

---

## 💻 Phase 2: Assembly Analysis (`main`)
We dissect the disassembled `main` function routine block by block:

### 1. The Multiprocessing Trap (`fork`)
At the start, after the stack canary layout, the program makes a Call Subroutine to `fork()` [0x0040077d]:
```assembly
400795:    e8 e6 fe ff ff          call   400680 <fork@plt>
40079a:    89 45 cc                mov    DWORD PTR [rbp-0x34],eax
40079d:    83 7d cc 00             cmp    DWORD PTR [rbp-0x34],0x0
4007a1:    75 50                   jne    4007f3 <main+0x76>
```
* **How `fork()` behaves:** It duplicates the current process. For the **Child Process**, `eax` returns `0` [0x0040077d]. For the **Parent Process**, `eax` returns the PID of the child (greater than 0) [0x0040077d].
* **The Branch:** The conditional instruction `jne` routes the **Parent Process** directly to address `0x4007f3` where it triggers a `waitpid` block [0x0040077d]. The **Child Process** falls through to execution block `0x4007a3` to perform an obfuscation loop [0x0040077d].

### 2. The Child's Secret Task (Obfuscation Loop)
The child routine systematically iterates through a static global string buffer located at `0x601080` [0x004007ac]:
```assembly
4007b1:    0f b6 80 80 10 60 00    movzx  eax,BYTE PTR [rax+0x601080]
4007b8:    3c 69                   cmp    al,0x69   ; Character 'i'
4007ba:    74 10                   je     4007cc
...
4007c1:    0f b6 80 80 10 60 00    movzx  eax,BYTE PTR [rax+0x601080]
4007c8:    3c 72                   cmp    al,0x72   ; Character 'r'
4007ca:    75 0c                   jne    4007d8
4007cc:    ...
4007d1:    c6 80 80 10 60 00 31    mov    BYTE PTR [rax+0x601080],0x31 ; Character '1'
```
* **Logic:** The child scans characters. If a specific byte matches hex value `0x69` (`'i'`) or `0x72` (`'r'`), it modifies that index block by swapping it with hex value `0x31` (`'1'`) [0x004007ac].

### 3. The Parent's Validation Gate
Once the child exits, the parent process awakes, takes a string array buffer from user space via `__isoc99_scanf`, and evaluates it against the global memory target block `0x601080` using `strcmp` [0x0040081d]:
```assembly
40083a:    bf 80 10 60 00          mov    edi,0x601080
40083f:    e8 fc fd ff ff          call   400640 <strcmp@plt>
```
Because memory spaces are altered by the child process before the parent performs the comparative check, evaluating the default static binary files would result in an incorrect flag submission.

---

## 📥 Phase 3: Memory Carving & Flag Extraction
We hook up the binary file using **Rizin** to extract the pristine base text directly from the target reference block:

```radare2
rizin -A challenge_binary
[0x0040077d]> ps @ 0x601080
```
**Output:**
```text
{hacking_for_fun}
```

Now, manually compiling the mutations handled within the child execution branch:
* Base String: `{hack`**`i`**`ng_fo`**`r`**`_fun}`
* Swap Target `'i'` -> `'1'`
* Swap Target `'r'` -> `'1'`

Resulting mutated payload matching the binary validation parameters: `{hack1ng_fo1_fun}`

---

## 🛠️ Phase 4: High-Level Source Code Modeling (C)
Reconstructing the exact operational control flow extracted from the binary results in the following **C source map**:

```c
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>
#include <stdlib.h>

// Located globally at absolute offset 0x601080
char flag_buffer[] = "{hacking_for_fun}"; 

int main() {
    // Canary guard automatically deployed here by standard GCC flags 
    // Corresponds to: mov rax, QWORD PTR fs:0x28
    
    pid_t pid = fork();

    if (pid == 0) {
        // --- Child Execution Branch ---
        int length = strlen(flag_buffer);
        for (int i = 0; i < length; i++) {
            if (flag_buffer[i] == 'i' || flag_buffer[i] == 'r') {
                flag_buffer[i] = '1'; // Swap to ascii hex 0x31
            }
        }
        exit(0);
    } 
    else {
        // --- Parent Execution Branch ---
        waitpid(pid, NULL, 0); // Hold for child context mutation loop

        printf("Enter Flag: ");
        char user_input[100];
        scanf("%99s", user_input);

        if (strcmp(user_input, flag_buffer) == 0) {
            puts("Success! Correct Flag.");
        } else {
            puts("Wrong Flag! Access Denied.");
        }
    }
    return 0;
}
```

---

## 🤖 Phase 5: Automated Solver Script (Python)
The following Python script replicates the exact multiprocessing logic to transform the carved baseline string into the winning flag solution automatically:

```python
#!/usr/bin/env python3
"""
Automated Memory-Mutation Solver for Forking-RE Challenge
"""

def extract_mutated_flag():
    # Carved string extracted via 'ps @ 0x601080' in Rizin
    initial_flag_state = "{hacking_for_fun}"
    
    # Cast to a lists structure for linear mutation tasks
    flag_characters = list(initial_flag_state)
    
    # Mirror the child process instruction behavior 
    for index in range(len(flag_characters)):
        if flag_characters[index] in ['i', 'r']:
            flag_characters[index] = '1'
            
    final_solution = "".join(flag_characters)
    
    print("[+] Emulation Matrix Complete.")
    print(f"[+] Extracted Flag: flag{{{final_solution}}}")

if __name__ == "__main__":
    extract_mutated_flag()
```

---

# Specialized Deep Dive: Cracking via Control Flow Hijacking (Binary Patching)

## 🎯 Core Objective
Instead of performing traditional static analysis to find the correct flag values, this section focuses entirely on **Cracking (Software Piracy Techniques)**. We will bypass the cryptographic or logic gates of the binary by modifying its compiled machine instructions in-place, transforming it into a "keyless" version that accepts any garbage input.

---

## 🔬 Technical Breakdown of the Validation Gate
By inspecting the disassembly of the binary right after the user input and string comparison routines, we isolate the following atomic execution block:

```assembly
  40083f:   e8 fc fd ff ff          call   400640 <strcmp@plt>
  400844:   85 c0                   test   eax,eax
  400846:   74 0c                   je     400854 <main+0xd7>
```

### Low-Level CPU Mechanics:
1. **The Comparison (`strcmp`):** The binary pushes the user's input buffer and the memory flag buffer onto the registers and executes `strcmp`. If the strings are completely different, `strcmp` returns a non-zero value (e.g., `1` or `-1`) inside the `eax` register.
2. **The Test Instruction (`test eax, eax`):** This instruction performs a bitwise `AND` operation on `eax` with itself. Since `eax` contains a non-zero value (due to incorrect input), the CPU's **ZF (Zero Flag)** is set to **0** (Not Zero).
3. **The Conditional Gate (`je 0x400854`):** The `je` (Jump if Equal / Jump if Zero) opcode operates entirely by checking the status of the **Zero Flag**. 
   * If `ZF == 1` (Correct flag entered) \(\rightarrow\) It jumps to the success block at `0x400854`.
   * If `ZF == 0` (Wrong flag entered) \(\rightarrow\) It falls through to the failure block (`wrong flag!`).

---

## 😈 Method 1: Interactive Assembly Patching (via Rizin)
To hijack the application logic, we must convert the conditional jump `je` into a hardcoded, forced **unconditional jump (`jmp`)**. 

1. Fire up the target binary in **Write Mode (`-w`)**:
   ```bash
   rizin -w reverse_2
   ```
2. Seek to the absolute virtual address of the branch decision point:
   ```radare2
   s 0x00400846
   ```
3. Swap out the conditional logic opcode by overwriting the hex bytes. The short `je` opcode (`74`) is replaced with the short `jmp` opcode (`eb`), maintaining the identical offset distance (`0c`):
   ```radare2
   wx eb0c
   ```
4. Verify that the control flow graph has been successfully rewritten:
   ```radare2
   pd 1
   ```
   **Modified Assembly Result:** `0x00400846      jmp   0x400854`

Now, when the binary encounters this instruction, it will ignore the status of the **Zero Flag (ZF)** entirely and unconditionally branch straight into the success routine.

---

## 🤖 Method 2: Automated Byte-Patching (Python Auto-Cracker)
To automate this modification without interactive debuggers, we calculate the file offset relative to the base address and manipulate the raw binary stream on the disk.

### Mathematical Offset Mapping:
* **Virtual Memory Address (VMA):** `0x00400846`
* **Static ELF Base Address:** `0x00400000`
* **Target Raw File Offset:** `0x00400846 - 0x00400000 = 0x846`

### The Automated Script (`cracker.py`):
```python
#!/usr/bin/env python3
"""
Automated Software Cracker - Bypassing Native String Validation Gates - Gantosay
"""
import os

def apply_binary_crack():
    original_binary = "reverse_2"
    cracked_binary = "reverse_2_cracked"
    
    # Target raw file offset mapping inside the ELF structure
    file_offset = 0x846 
    
    # Overwrite payload: Change \x74\x0c (je) into \xeb\x0c (jmp)
    crack_payload = b'\xeb\x0c'
    
    if not os.path.exists(original_binary):
        print(f"[-] Error: Native file '{original_binary}' missing from directory!")
        return

    # Ingest raw bytes stream from disk
    with open(original_binary, "rb") as target_file:
        binary_stream = bytearray(target_file.read())
        
    print("[+] Ingested raw binary bytes stream into mutable memory buffer.")
    
    # Splice and corrupt the validation checkpoint 
    binary_stream[file_offset:file_offset+2] = crack_payload
    print(f"[+] Overwrote conditional opcode at file offset: {hex(file_offset)}")
    
    # Output the modified executable package
    with open(cracked_binary, "wb") as cracked_file:
        cracked_file.write(binary_stream)
        
    # Programmatically assign execution permissions (Linux chmod +x)
    os.chmod(cracked_binary, 0o755)
    print(f"[+] Success! Fully cracked executable compiled: ./{cracked_binary}")
    print("[+] Run the cracked binary and input ANY text to trigger the victory branch!")

if __name__ == "__main__":
    apply_binary_crack()
```

---

## 🧪 Verification Check
Executing the newly generated cracked clone and feeding it completely arbitrary, garbage text bypasses the validation gate instantly:

```bash
\$ ./reverse_2_cracked
input the flag: completely_wrong_text_here
Success! Correct Flag.
```

