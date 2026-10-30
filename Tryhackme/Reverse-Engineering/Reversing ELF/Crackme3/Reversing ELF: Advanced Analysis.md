# Reversing ELF: Crackme3 : Advanced Analysis of Crackme3

This write-up provides an in-depth, instruction-level reverse engineering analysis of **Crackme3** from the *Reversing ELF* room on TryHackMe. Unlike the previous challenges, this binary introduces professional evasion techniques, including **symbol stripping** and **dynamic memory encoding (Base64/Custom Cipher)**. 

Our goal is to dissect the execution flow purely through static assembly analysis and reconstruct the target logic.

---

## 🏗️ Binary Profile & Triage
Before looking at the instructions, we perform a standard examination of the binary characteristics:
* **Architecture:** ELF 32-bit LSB executable, Intel 80386 (i386).
* **Symbols:** **Stripped**. The compiler option `-s` was used during build time, which completely purges the `.symtab` and `.strtab` sections. Functions like `main`, `global variables`, and internal routine names are stripped of their human-readable identifiers.

---

## 🔍 Phase 1: Resolving the Hidden Entry Point & `main`

When a binary is stripped, `objdump` defaults to mapping code chunks under generic section offsets like `<.text+0xbf>`. To find where the program actually kicks off, we leverage the ELF header using `readelf`:

```bash
readelf -h crackme3 | grep "Entry point"
```
**Output:** `Entry point address: 0x8048440`

This address marks the starting point of the execution flow, traditionally named `_start`. Let's inspect the exact assembly initialization setup under this sector:

```assembly
08048440 <.text>:
 8048440:	31 ed                	xor    ebp,ebp          ; Clear EBP to signify the top of the stack frame
 8048442:	5e                   	pop    esi              ; Pop argc (argument count) into ESI
 8048443:	89 e1                	mov    ecx,esp          ; Move the argv pointer array into ECX
 8048445:	83 e4 f0             	and    esp,0xfffffff0   ; Align the Stack Pointer (ESP) to a 16-byte boundary
 ...
 8048457:	68 f4 84 04 08       	push   0x80484f4        ; [CRITICAL] Push the address of the hidden main()
 80484c:	e8 bf ff ff ff       	call   8048420 <__libc_start_main@plt>
```

### 💡 Deep-Dive Architectural Note:
In Linux x86 (32-bit) architectures, the entry routine `_start` sets up the environment and instantly invokes `__libc_start_main` from the standard C library. The System V Application Binary Interface (ABI) dictates that `__libc_start_main` expects the pointer to the real `main()` function to be pushed onto the stack right before initialization.

By locating `push 0x80484f4` followed immediately by the libc initialization call, we definitively locate the hidden `main()` routine at address **`0x80484f4`**.

---

## 🧠 Phase 2: Instruction-Level Disassembly of `main` (`0x80484f4`)

Now, I zoom directly into the hidden `main` loop to decode its internal mechanics block-by-block.

### Block A: Argument Length Validation
```assembly
 80484f7:	57                   	push   edi
 80484f8:	56                   	push   esi
 80484f9:	83 ec 10             	sub    esp,0x10
 80484fc:	8b 45 0c             	mov    eax,DWORD PTR [ebp+0xc]   ; Load argv array pointer
 80484ff:	83 7d 08 02          	cmp    DWORD PTR [ebp+0x8],0x2   ; Compare argc against 2
 8048503:	74 20                	je     0x8048525                 ; If argc == 2, jump to validation
```
* **Mechanism:** The binary expects exactly one argument passed via the command line (the password string). `argc` counts the binary path itself (`argv[0]`) plus user arguments. If `argc != 2`, it passes structural parameters down to an error logging block `fprintf@plt`, displays usage instructions, and gracefully returns `-1` (`0xffffffff`).

### Block B: Dynamic Heap Allocation & Security Buffer Setup
If validation passes, execution continues to address `0x8048525`:
```assembly
 8048525:	8b 78 04             	mov    edi,DWORD PTR [eax+0x4]   ; Load user input (argv[1]) into EDI
 8048528:	89 3c 24             	mov    DWORD PTR [esp],edi
 804852b:	e8 e0 fe ff ff       	call   8048410 <strlen@plt>       ; Calculate length of user input
 8048530:	01 c0                	add    eax,eax                   ; Double the length size (EAX = len * 2)
 8048532:	89 04 24             	mov    DWORD PTR [esp],eax
 8048535:	e8 a6 fe ff ff       	call   80483e0 <malloc@plt>       ; Dynamically allocate space on Heap
 804853a:	89 c6                	mov    esi,eax                   ; ESI holds the newly allocated Heap pointer
```
* **Analysis:** The application calculates the string length of your input using `strlen`. It multiplies the byte length by two (`add eax, eax`) to securely account for decoding padding. It then instantiates an isolated memory region via `malloc`. The returned base address pointer is cached safely inside the **`esi`** register.

### Block C: Bypassing Obfuscation via Cryptographic Decoding
Further down, the program loads a hardcoded reference point and invokes a heavily obfuscated sub-routine:
```assembly
 8048567:	89 3c 24             	mov    DWORD PTR [esp],edi
 804856a:	e8 a1 fe ff ff       	call   8048410 <strlen@plt>
 ...
 8048582:	e8 29 01 00 00       	call   80486b0                   ; Custom Base64 Decoding Routine
```
* **Discovery:** Although `objdump` references this block arbitrarily based on PLT offsets, analyzing the sub-functions below address `0x80485d0` reveals systematic index lookups checking for bounds like ASCII `0x41` ('A'), `0x5a` ('Z'), `0x61` ('a'), and `0x7a` ('z'). 
* **Logic:** This is an implementation of a **Base64 decoding alphabet**. The binary captures the hardcoded encoded asset string discovered via static string indexing (ending in `==`) and drops the decoded plain-text translation matrix raw into the memory pointer initialized inside `esi`.

### Block D: The Final Character Verification Matrix
```assembly
 8048594:	89 34 24             	mov    DWORD PTR [esp],esi             ; Argument 1: Decoded password string
 8048597:	c7 44 24 04 8b 8e 04 	mov    DWORD PTR [esp+0x4],0x8048e8b   ; Argument 2: User input string pointer
 804859e:	08 
 804859f:	e8 1c fe ff ff       	call   80483c0 <strcmp@plt>             ; Execute string match comparison
 80485a4:	85 c0                	test   eax,eax                          ; Check if EAX return value is 0
 80485a6:	75 10                	jne    0x80485b8                       ; If not 0 (mismatch), jump to Fail block
```
* **The Verdict:** The execution pipeline performs a standard runtime comparison using `strcmp`. 
    * `esi` points to the freshly unmasked password validation matrix.
    * `0x8048e8b` holds the address of your interactive input string.
    * `test eax, eax` coupled with `jne` dictates the final outcome. A non-zero return value routes code execution to `0x80485b8` (`Access Denied`). If they match perfectly, execution drops seamlessly into `0x80485a8` which loads the successful reference block and yields the target flag via `puts`.

---

## 🛠️ Reverse Engineer's Cheat Sheet (Static Extraction)

Since I know the program simply extracts a hardcoded Base64 array, dynamically transforms it on the heap, and compares it directly, we can bypass the entire runtime execution tree manually:

1. Extract the base64 string from the binary assets using `strings crackme3`.
2. Decode the raw data payload out-of-band:
   ```bash
   echo "ZjByX3kwdXJfNWVjMG5kX...==" | base64 -d
   ```
3. Pass the unmasked payload string back directly into the interactive execution argument list to enforce a true-positive match conditional state:
   ```bash
   ./crackme3 <extracted_password>
   ```
