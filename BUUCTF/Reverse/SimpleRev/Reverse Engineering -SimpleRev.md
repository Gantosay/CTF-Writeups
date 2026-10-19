# CTF Technical Write-up: Reverse Engineering - SimpleRev (Linux x64)
## Deep-Dive Analysis on Multi-Alphabet Vigenère Ciphers & Modular Matrix Inversion

## 📝 Challenge Description
* **Category:** Reverse Engineering / Algorithmic Code Analysis.
* **Difficulty:** Medium (Algorithmic Logic Tracking).
* **Target Artifact:** `rev` (64-bit ELF Linux Executable).
* **Platform Protections:** Full RELRO, Stack Canary, NX Enabled, PIE Enabled, Not Stripped.
* **Core Concepts:** Little-Endian Data Recovery, Vigenère Modular Algebra, Memory Variable Chains, C Source Code Modeling.

---

## 🛡️ Phase 1: Environmental Security Triage & String Carving
We initiated our pipeline by auditing the binary framework parameters via `file` and `checksec` on our Ubuntu Linux server. Since the target was compiled as **Not Stripped**, all function names and structural global symbols remained completely intact.

Running Rizin's `iz` command to harvest static text primitives from the read-only data segment (`.rodata` & `.data`) revealed essential operational strings:

```text
0x00000d78  .rodata  ascii   Please input your flag:
0x00000d90  .rodata  ascii   Congratulation!\n
0x00000da1  .rodata  ascii   Try again!\n
0x00002010  .data    ascii   ADSFK
0x00002030  .data    ascii   kills
```

### Initial Triage Insights:
1. **The Validation Targets:** The strings `Congratulation!` and `Try again!` mark the explicit win/loss terminal blocks.
2. **The Obfuscated Constants:** The flat segments `ADSFK` and `kills` represent isolated base key variables sitting globally in memory. They act as structural pieces of a hidden encryption key.

---

## 🔍 Phase 2: Locating Symbols and Disassembling the Encryption Core
We executed a complete function table scan (`afl`). Beyond `main`, the binary explicitly exposed a dedicated subroutine symbol named **`sym.Decry`** at offset `0x0000093a`. 

Decompiling `sym.Decry` inside **IDA Pro** uncovered the internal cryptographic engine:

```c
unsigned __int64 Decry()
{
  // ... local stack allocation variables ...
  *(_QWORD *)src = 0x534C43444ELL;                     // Little-Endian String 1
  v9[0] = 0x776F646168LL;                              // Little-Endian String 2
  
  text = (char *)join(key3, v9);                       // Concatenation target
  strcpy(key, key1);
  strcat(key, src);                                    // Key reconstruction
  
  v5 = strlen(key);
  for ( i = 0; i < v5; ++i ) {
    if ( key[v3 % v5] > 64 && key[v3 % v5] <= 90 )
      key[i] = key[v3 % v5] + 32;                      // Upper-to-Lowercase Conversion
    ++v3;
  }
  
  printf("Please input your flag:");
  while ( 1 ) {
    v1 = getchar();                                    // Byte-by-byte ingestion
    if ( v1 == 10 ) break;                             // Break on newline (Enter)
    if ( v1 == 32 ) {
      ++v2;
    } else {
      // THE CORE ENCRYPTION MATHEMATICAL GATE
      str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
      ++v3;
      ++v2;
    }
  }
  if ( !strcmp(text, str2) )                           // Ultimate Validation Check
    puts("Congratulation!\n");
  else
    puts("Try again!\n");
}
```

---

## 🔬 Phase 3: Step-by-Step Assembly Tracking & Logical Carving
An elite reverse engineer analyzes an assembly dump by mapping three critical checkpoints: **Input location, data mutation, and final comparison.** Let's trace how the binary dynamically sets up its encryption algorithm:

### Step 1: Reconstructing the Little-Endian Constants
The compiler hides raw strings by loading them as 64-bit immediate hexadecimal integers (`QWORD`). Due to **Little-Endian memory mapping**, the bytes are stored completely in reverse order on the stack frame. We unroll them by reading the hex pairs from right to left:
* `0x534C43444E` \(\---->\) `4E 44 43 4C 53` \(\---->\) ASCII: **`NDCLS`**
* `0x776F646168` \(\---->\) `68 61 64 6F 77` \(\---->\) ASCII: **`hadow`**

### Step 2: Key and Reference Array Harmonization
The binary maps out its global arrays (`key1` = `ADSFK`, `key3` = `kills`) using execution concatenations (`join` / `strcat` / `strcpy`):
1. **The Comparison Target (`text`):** Combines `key3` (`kills`) and `v9` (`hadow`) \(\---->\) **`killshadow`**
2. **The Scrambler Key (`key`):** Combines `key1` (`ADSFK`) and `src` (`NDCLS`) \(\---->\) **`ADSFKNDCLS`**

The program loops over `key` and adds `32` to any character code between 64 and 90, effectively performing an in-memory lowercase conversion. This hard-locks our master loop cipher key into: **`adsfkndcls`** (Length: 10).

### Step 3: De-mystifying the Modular Encryption Formula
When you submit a character, it runs through the modular formula:
```text
Output_Byte = (User_Byte - 39 - Key_Byte + 97) % 26 + 97
```
1. **`User_Byte - 39 - Key_Byte`**: The program subtracts a fixed offset (39) and the corresponding rotating byte from our lowercase key `adsfkndcls`. This scrambles your character into an arbitrary integer.
2. **`% 26` (The Alphabet Clock)**: This is a **Modular Remainder Operation**. It mimics a 26-hour clock representing the English alphabet (`a-z`). If the calculation spins way past standard limits, the `% 26` wraps the value securely between `0` and `25`.
3. **`+ 97`**: In the ASCII chart, lowercase **`'a'`** starts at index **`97`**. Adding 97 guarantees that our final scrambled byte is maps cleanly back into a readable, lowercase letter (`a-z`).

Finally, `strcmp` compares this mutated buffer against **`killshadow`**. If a single typed letter is wrong, it shifts the modular cascade, corrupting the subsequent output array and failing the check.

---

## 🤖 Phase 4: Automated Decoding Script (Python Solver Matrix)
To solve this cleanly, we reverse the encryption math from the bottom up. By working backwards from the known target vector (`killshadow`), we apply a **Modular Inverse Matrix** to isolate the true user input byte at each rotation index:
\[{User\_Byte} = ({Target\_Byte} - 97 - 97 + {Key\_Byte} + 39 + 260) \pmod{26} + 97\]
*(I inject `260` into the script to prevent negative remainder calculations from breaking the Python modulo operator).*

```python
def solve_perfect_simplerev():
    target_text = "killshadow"
    key = "adsfkndcls"
    v5 = len(key)
    
    # 🔒 The Critical Fix: v3 is already 10 after the first key loop!
    v3 = 10
    
    flag = []
    
    for i in range(len(target_text)):
        t_char = ord(target_text[i])
        k_char = ord(key[v3 % v5])
        
        # Check all possible valid characters (A-Z and a-z)
        found = False
        for v1 in range(65, 123):
            # Exclude non-alpha chars between Z (90) and a (97)
            if 90 < v1 < 97:
                continue
                
            # Replicating the exact calculation logic
            if (v1 - 39 - k_char + 97) % 26 + 97 == t_char:
                flag.append(chr(v1))
                found = True
                break
        v3 += 1

    print("═" * 50)
    print(f"RAW RECOVERED TEXT: {''.join(flag)}")
    print("═" * 50)

solve_perfect_simplerev()


```


---

## 🛠️ Phase 5: High-Level C Source Code Reconstruction
To understand how the original compiler built this challenge, I have reconstructed the developer's complete **C Source Code blueprint**:

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


char* join(const char* s1, const char* s2) {
    char* result = malloc(strlen(s1) + strlen(s2) + 1);
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

void Exit() {
    exit(0);
}

int Decry() {
    char v1;
    int v2 = 0;
    int v3 = 0;
    int i;
    int v5;
    
    
    const char* key1 = "ADSFK";
    const char* key3 = "kills";
    
    char key[100] = {0};
    char str2[100] = {0};
    char* text;

    
    char src[8] = "NDCLS"; 
    char v9[2][8] = {"hadow", ""}; 

    
    text = join(key3, v9[0]); 
    strcpy(key, key1);        
    strcat(key, src);         
    getchar(); 

    
    v5 = strlen(key);
    for (i = 0; i < v5; ++i) {
        if (key[v3 % v5] > 64 && key[v3 % v5] <= 90) {
            key[i] = key[v3 % v5] + 32; 
        }
        ++v3;
    }

    
    printf("Please input your flag:");
    while (1) {
        v1 = getchar();
        if (v1 == 10) 
            break;
            
        if (v1 == 32) { 
            ++v2;
        } else {
            
            if ((v1 <= 96 || v1 > 122) && (v1 > 64 && v1 <= 90)) {
                str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
                ++v3;
            } else if (v1 > 96 && v1 <= 122) {
                str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
                ++v3;
            }
            
            if (!(v3 % v5)) {
                putchar(32);
            }
            ++v2;
        }
    }

    if (strcmp(text, str2) == 0) {
        puts("Congratulation!\n");
    } else {
        puts("Try again!\n");
    }

    return 0;
}

int main(int argc, const char **argv) {
    int v3;
    char v4;

    while (1) {
        while (1) {
            printf("Welcome to CTF game!\nPlease input d/D to start or input q/Q to quit this program: ");
            v4 = getchar();
            if (v4 != 'd' && v4 != 'D') 
                break;
            Decry();
        }
        if (v4 == 'q' || v4 == 'Q') 
            Exit();
            
        puts("Input fault format!");
        v3 = getchar();
        putchar(v3);
    }
}
‍‍
```

