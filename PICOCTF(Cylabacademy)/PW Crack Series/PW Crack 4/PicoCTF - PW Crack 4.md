# CTF Write-up: picoCTF - PW Crack 4 (General Skills)

## 📝 Challenge Description
* **Category:** General Skills
* **Difficulty:** (Beginner-Friendly Automation)
* **Event:** picoMini 
* **Target Artifacts:** `level4.py`, `level4.flag.txt.enc`, `level4.hash.bin`
* **Objective:** Scale up authentication brute-force methodologies to process a larger password candidate dictionary space dynamically.

---

## 🔍 Phase 1: Operational Evaluation & Dictionary Scaling
This challenge shares an identical architectural design with `PW Crack 3`, relying on an MD5 hashing checkpoint to evaluate input parameters before executing an inline XOR decryption function on `level4.flag.txt.enc`.

However, the developer scaled the complexity by replacing the small 7-item array with an expanded candidate workspace containing **100 potential passwords**:
```python
pos_pw_list = ["6288", "6152", "4c7a", ... "49ec"]
```

While manual execution becomes highly inefficient at this scale, the automated programmatic solver framework easily absorbs the dictionary expansion without requiring any logical structural updates.

---

## 🤖 Phase 2: Automated Solver Implementation
We deployed a high-speed Python automation tool (`solve_level4.py`) to map through the 100-item sequence, calculate MD5 byte streams, and immediately decrypt the flag asset:

```python
#!/usr/bin/env python3
import hashlib

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

flag_enc = open('level4.flag.txt.enc', 'rb').read()
correct_pw_hash = open('level4.hash.bin', 'rb').read()

pos_pw_list = [
    "6288", "6152", "4c7a", "b722", "9a6e", "6717", "4389", "1a28", "37ac", "de4f", 
    "eb28", "351b", "3d58", "948b", "231b", "973a", "a087", "384a", "6d3c", "9065", 
    "725c", "fd60", "4d4f", "6a60", "7213", "93e6", "8c54", "537d", "a1da", "c718", 
    "9de8", "ebe3", "f1c5", "a0bf", "ccab", "4938", "8f97", "3327", "8029", "41f2", 
    "a04f", "c7f9", "b453", "90a5", "25dc", "26b0", "cb42", "de89", "2451", "1dd3", 
    "7f2c", "8919", "f3a9", "b88f", "eaa8", "776a", "6236", "98f5", "492b", "507d", 
    "18e8", "cfb5", "76fd", "6017", "30de", "bbae", "354e", "4013", "3153", "e9cc", 
    "cba9", "25ea", "c06c", "a166", "faf1", "2264", "2179", "cf30", "4b47", "3446", 
    "b213", "88a3", "6253", "db88", "c38c", "a48c", "3e4f", "7208", "9dcb", "fc77", 
    "e2cf", "8552", "f6f8", "7079", "42ef", "391e", "8a6d", "2154", "d964", "49ec"
]

print(f"[*] Executing dictionary crack sweep over {len(pos_pw_list)} metrics...")

for candidate in pos_pw_list:
    if hash_pw(candidate) == correct_pw_hash:
        print(f"[+] Success! Mapped correct key asset: '{candidate}'")
        print(f"[+] Recovered Plaintext Flag: {str_xor(flag_enc.decode(), candidate)}")
        break
```

---

