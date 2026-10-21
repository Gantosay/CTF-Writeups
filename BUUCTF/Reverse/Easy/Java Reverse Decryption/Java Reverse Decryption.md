# CTF Reverse Engineering - "Java Reverse Decryption" Writeup

This write-up covers the complete reverse engineering and cryptographic inversion process for the `Reverse.class` Java bytecode challenge. The objective is to reconstruct the programmatic execution pipeline of a lost file encryption key verification algorithm and statically extract the valid authentication token.

---

## 🛠️ Phase 1: Architectural Triage & Decompilation

Upon assessing the challenge file payload, we identify the `.class` extension, indicating compiled **Java Bytecode** built to execute inside a Java Virtual Machine (JVM). 

Unlike native compiled binaries (e.g., C/C++ compiled ELF or PE structures) which reduce logic to abstract machine code, Java Bytecode preserves an immense wealth of structural metadata. We bypass standard low-level disassembly tools like `objdump` or `GDB` and execute a clean high-level static decompilation using an out-of-band decompiler tree (`CFR` / `JD-Core`), yielding the pristine original programmatic implementation:

```java
import java.util.ArrayList;
import java.util.Scanner;

public class Reverse {
   public static void main(String[] args) {
      Scanner s = new Scanner(System.in);
      System.out.println("Please input the flag ：");
      String str = s.next();
      System.out.println("Your input is ：");
      System.out.println(str);
      char[] stringArr = str.toCharArray();
      Encrypt(stringArr);
   }

   public static void Encrypt(char[] arr) {
      ArrayList<Integer> Resultlist = new ArrayList();

      for(int i = 0; i < arr.length; ++i) {
         int result = arr[i] + 64 ^ 32;
         Resultlist.add(result);
      }

      int[] KEY = new int[]{180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65};
      ArrayList<Integer> KEYList = new ArrayList();

      for(int j = 0; j < KEY.length; ++j) {
         KEYList.add(KEY[j]);
      }

      System.out.println("Result:");
      if (Resultlist.equals(KEYList)) {
         System.out.println("Congratulations！");
      } else {
         System.err.println("Error！");
      }
   }
}
```

---

## ⚡ Phase 2: Operator Precedence & Cipher Analysis

Analyzing the core cryptographic algorithm inside the `Encrypt` routine reveals the processing tree applied to every character character-by-character:

```java
int result = arr[i] + 64 ^ 32;
```

### 🧠 Critical JVM Operator Precedence Note:
According to the Java Virtual Machine specification, arithmetic operators hold higher evaluation precedence than bitwise bit-shift or bitwise logical operators. Therefore, the statement does **not** evaluate left-to-right as `(arr[i] + (64 ^ 32))`. Instead, the addition operator (`+`) fires prior to the bitwise Exclusive-OR (`^`) operator.

The definitive mathematical expression of the encryption function is:
\[Result = (Character + 64) \oplus 32\]

The final output block `Resultlist` is matched dynamically via a list comparison interface against a hardcoded static numerical verification vector array:
```text
KEY = [180, 136, 137, 147, 191, 137, 147, 191, 148, 136, 133, 191, 134, 140, 129, 135, 191, 65]
```

---

## 📐 Phase 3: Cryptographic Inversion (Algebraic Derivation)

To derive the original plain-text characters without dynamically interacting with the running JVM environment, we must construct the perfect inverse mathematical function.

Given the encryption formula:
\[E(x) = (x + 64) \oplus 32 = Y\]

We leverage the self-inverse, reflexive property of the Exclusive-OR cipher (\(A \oplus B \oplus B = A\)) to eliminate the bitwise mask:
\[x + 64 = Y \oplus 32\]

Finally, we isolate the plain-text variable x by subtracting the static arithmetic scalar value:
\[x = (Y \oplus 32) - 64\]

### Walkthrough of the First Element:
* Target Cipher Value (Y): `180`
* Applying Bitwise Inversion: \(180 \oplus 32 = 148\)
* Applying Arithmetic Inversion: 148 - 64 = 84
* ASCII Interpretation: `84` translates directly to the character **`T`**.

---

## 🐍 Phase 4: Automated Static Decoder (Python Solver)

We automate this algebraic inversion process across the entire dataset by mapping the extracted hardcoded key array through a custom Python linear processing loop:

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Statically extracted ciphertext validation array from Reverse.class
target_key_array = [
    180, 136, 137, 147, 191, 137, 147, 191, 
    148, 136, 133, 191, 134, 140, 129, 135, 
    191, 65
]

extracted_plaintext = ""

# Execute the exact inverse mathematical transformation loop
for cipher_val in target_key_array:
    # 1. Reverse XOR shift layer with mask 32
    # 2. Reverse arithmetic scaling layer by subtracting 64
    plain_char_code = (cipher_val ^ 32) - 64
    
    # Cast byte integers back to human-readable characters
    extracted_plaintext += chr(plain_char_code)

# Enforce target contest flag wrapping requirements
final_flag = f"flag{{{extracted_plaintext}}}"

print("\n[+] Cryptographic Inversion Complete!")
print(f"🥇 Flag: {final_flag}\n")
```

---


