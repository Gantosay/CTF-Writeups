# CTF Write-up: picoCTF - PW Crack 5 (General Skills)

## 📝 Challenge Description
* **Category:** General Skills
* **Difficulty:** (Beginner-Friendly Automation)
* **Event:** picoMini 
* **Target Artifacts:** `level5.py`, `level5.flag.txt.enc`, `level5.hash.bin`, `dictionary`
* **Objective:** Perform a programmatic **Dictionary Attack** by reading external key assets, purging structural trailing whitespaces, and executing automated MD5 verification passes.

---

## 🔍 Phase 1: Operational Evaluation & Dictionary Parsing
In this final iteration of the `PW Crack` sequence, the developer completely eliminated hardcoded candidate arrays from the execution logic. Instead, we are provided with an external payload flat-file named `dictionary` containing a massive list of potential words.

To crack the MD5 verification gate without interactive deadlocks, our automated solution script must ingest this file stream line-by-line. A critical parameter highlighted in the challenge hints is the presence of trailing newline characters (`\n`) embedded during file creation, which requires programmatic sanitation using the native Python `.strip()` method before feeding strings into the hashing engine.

---

## 🤖 Phase 2: Automated Exploitation Suite
We constructed a standalone automation harness (`solve.py`) designed to parse the raw dictionary, sanitize inputs, execute low-level MD5 hashing, and dynamically dump the plaintext flag layout via XOR decoding:

```python
#!/usr/bin/env python3
import hashlib
import os

def str_xor(secret, key):
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

flag_enc = open('level5.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level5.hash.bin', 'rb').read()
dict_file = 'dictionary.txt' if os.path.exists('dictionary.txt') else 'dictionary'

with open(dict_file, 'r', encoding='utf-8', errors='ignore') as f:
    for line in f:
        password = line.strip() # Purge dynamic whitespaces (\n)
        if hash_pw(password) == correct_pw_hash:
            print(f"[+] Success! Mapped core authentication pass: '{password}'")
            print(f"[+] Recovered Plaintext Flag: {str_xor(flag_enc.decode(), password)}")
            break
```

---

