# CTF Write-up: picoCTF - PW Crack 3 (General Skills)

## 📝 Challenge Description
* **Category:** General Skills
* **Difficulty:** (Beginner-Friendly Automation)
* **Event:** picoMini 
* **Target Artifacts:** `level3.py`, `level3.flag.txt.enc`, `level3.hash.bin` 
* **Objective:** Analyze an authentication script, extract potential validation candidates, and dynamically recover an encrypted file structure using Python automated scripting.

---

## 🔬 Phase 1: Operational Architectural Mapping
Unlike compiled target architectures (e.g., ELF or PE executable binaries), this challenge operates cleanly inside an interpretable native Python environment. We are dropped into a directory with three separate forensic files:
1. `level3.py`: The executable python logic checking wrapper.
2. `level3.hash.bin`: A raw 128-bit MD5 binary digest configuration holding the compressed signature verification state of the true target password.
3. `level3.flag.txt.enc`: An XOR-encrypted volatile flat data file housing the target string asset (Flag).

### Cryptographic Logic Evaluation:
By checking the main execution script, we capture the data ingestion paths:
```python
flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()
```
The program grabs data streams out of raw storage blocks and handles key validation routines dynamically using an MD5 digest structure:
```python
def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()
```
The user input string undergoes ASCII byte conversion, feeds straight into an internal MD5 hasher matrix, and returns the raw binary digest bytes (`m.digest()`) to match against `correct_pw_hash`.

### The Developer's Hardcoded Candidate Array:
At the absolute baseline of the script, the developer embedded a hardcoded list string tracking seven distinct potential verification candidate entries:
```python
# The strings below are 7 possibilities for the correct password. 
# (Only 1 is correct)
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]
```

---

## 🤖 Phase 2: Automated Exploitation Blueprint (Brute-Force Automation)
Instead of executing manual iterative entries against the user-interactive prompt shell, we implement an automated **Python Solver (`solve.py`)**. 

The automation scripts replicate the internal `hash_pw` and `str_xor` logic blocks, iterate through the seven candidates inside a high-speed runtime execution loop, compare generated MD5 byte structures, and instantly isolate the winning key sequence to dump the flag plaintext stream:

```python
#!/usr/bin/env python3
"""
picoCTF PW Crack 3 Automated Solution Tool
"""
import hashlib

def str_xor(secret, key):
    # Extend key to secret length dynamically
    new_key = key
    i = 0
    while len(new_key) < len(secret):
        new_key = new_key + key[i]
        i = (i + 1) % len(key)        
    return "".join([chr(ord(secret_c) ^ ord(new_key_c)) for (secret_c,new_key_c) in zip(secret,new_key)])

def hash_pw(pw_str):
    pw_bytes = bytearray()
    pw_bytes.extend(pw_str.encode())
    m = hashlib.md5()
    m.update(pw_bytes)
    return m.digest()

# Load isolated encrypted static targets into memory stream
flag_enc = open('level3.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level3.hash.bin', 'rb').read()

# Target Candidate Entry Array mined from source comments
pos_pw_list = ["6997", "3ac8", "f0ac", "4b17", "ec27", "4e66", "865e"]

print("[*] Launching high-speed programmatic brute-force over candidate space...")

# Iterative execution loop processing
for candidate in pos_pw_list:
    current_digest = hash_pw(candidate)
    
    # Evaluate binary structural equivalence across MD5 byte strings
    if current_digest == correct_pw_hash:
        print(f"[+] Success! Isolated true authentication key parameter: '{candidate}'")
        
        # Deploy XOR decryption routines using the valid extracted key
        plaintext_flag = str_xor(flag_enc.decode(), candidate)
        print(f"[+] Decrypted Flag Recovered: {plaintext_flag}")
        break
```

### Script Execution Trace:
```bash
$ python3 solve.py
[*] Launching high-speed programmatic brute-force over candidate space...
[+] Success! Isolated true authentication key parameter: 'ec27'
[+] Decrypted Flag Recovered: academy{m45h_fl1ng1ng_b8034615}
```

---
