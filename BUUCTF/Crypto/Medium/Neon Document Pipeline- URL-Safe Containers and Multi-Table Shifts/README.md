# VOIDDOC // 容器文档管线 – Vault Entry 17

**CTF Challenge Write-up**  
**Category:** Web / Crypto / Stego (Client-side + Classical Cipher)  
**Difficulty:** Medium  


---

## Challenge Overview

The challenge presents a custom document system called **VOIDDOC** that uses a container format named **VDOC1**.

Three documents are available in the “Document Bay”:

| File              | Class  | Purpose                          |
|-------------------|--------|----------------------------------|
| `README.vdoc`     | note   | Explains the VDOC1 format        |
| `CHANGELOG.vdoc`  | note   | Release notes                    |
| `vault-17.vdoc`   | vault  | Encrypted secret (the target)    |

The interface has two modes:
- **容器模式** (Container Mode) – decodes VDOC1 blobs and shows a live JSON preview
- **解密模式** (Decrypt Mode) – applies a polyalphabetic shift recovery on the left-hand text

---

## Step 1 – Understanding the VDOC1 Format

From the README:

> VDOC1 containers wrap one UTF-8 JSON document in a URL-safe payload.  
> Older tooling expects the standard alphabet and padding, so normalize first.

A typical blob looks like:

```
VDOC1.eyJ0aXRsZSI6IlJFQURNRSIsImNsYXNzIjoibm90ZSIs...
```

Decoding process:
1. Strip the `VDOC1.` prefix
2. Convert URL-safe Base64 (`-` → `+`, `_` → `/`) and add padding
3. Base64-decode → UTF-8 JSON

After decoding we obtain a structure similar to:

```json
{
  "title": "...",
  "class": "note | vault",
  "body": "...",
  "meta": { ... }
}
```

---

## Step 2 – The Vault Encryption Scheme

The README clearly describes how `class: "vault"` documents are protected:

> Documents of class 'vault' keep their body under a polyalphabetic shift:
> - alphabet A-Z only, letters only, case preserved, punctuation untouched
> - encryption shifts forward, recovery shifts backward, key cycles on letters
> - the key is a short word, uppercase
>
> Example key for sandbox demos: SAMPLE (example only, never used by releases).  
> **Each release records its own short key word inside the release notes.**

This is a classic **Vigenère cipher** restricted to the Latin alphabet, with the following properties:

- Only alphabetic characters are shifted
- Case is preserved
- Digits, spaces and punctuation stay unchanged
- The key is repeated only over the letters (non-letters do not consume key material)

---

## Step 3 – Locating the Key (Acrostic Technique)

The README states that the real key used by a release is recorded **inside the release notes**.  
The release notes are exactly the body of `CHANGELOG.vdoc`:

```
Migrated every preview render to the new container pipeline.
All archived blobs stay readable after alphabet normalization.
Gradient tokens removed; palette now lives in the stylesheet.
Editor streams a live preview on every keystroke.
Non-printable characters are dropped before decoding.
Toolbar shortcuts are listed in the handbook.
Archive exports now use the compact container by default.
```

Taking the **first letter of each non-empty line** yields:

```
M A G E N T A
```

→ **MAGENTA**

This is a classic **acrostic** steganography technique – hiding a secret word by using the initial letters of successive lines or sentences.

---

## Step 4 – Decrypting the Vault

Encrypted body of `vault-17.vdoc`:

```
xejkrk eztxc 17: gae ooavvxr tathrw ohex xux sqariq trohozr ueroxi gae brkzvxw ritmfaep rkrqxrunm. xux hmnjssy wunjsj pae eriixn yitygxs mnj rb vobikw jxrq mghr. mhq cawghdk tuorg falrsjl: CFF2{xxxxxxxxxxxxj67895911062}. gyhsq tni fairt grq weetxsl mhus riny.
```

Applying Vigenère recovery with key `MAGENTA` produces the clean plaintext:

```
ledger entry 17: the courier handed over the sealed archive before the preview finished rendering. the handoff window was eleven minutes and no copies were made. the custody token follows: CTF2{xxxxxxxxxxxx-d67895911062}. close the shift and destroy this leaf.
```

The custody token is the flag.

---

## Full Solver Script

```python
#!/usr/bin/env python3
"""
VOIDDOC / VDOC1 - Vault Decryptor
Automatically extracts documents, finds the key via acrostic,
and decrypts the vault entry.
"""

import re
import json
import base64
import urllib.request
from typing import List, Dict


BASE_URL = "http://9cf20d7fc3d4c1ac225f5439.http-ctf2.dasctf.com:80"


def fetch(url: str) -> str:
    with urllib.request.urlopen(url, timeout=15) as r:
        return r.read().decode("utf-8", "replace")


def decode_vdoc(blob: str) -> Dict:
    """Decode a VDOC1.xxxx blob into a JSON object."""
    if not blob.startswith("VDOC1."):
        raise ValueError("Not a VDOC1 blob")

    b64 = blob[6:]
    # Normalize URL-safe base64
    b64 = b64.replace("-", "+").replace("_", "/")
    b64 += "=" * ((4 - len(b64) % 4) % 4)

    raw = base64.b64decode(b64)
    return json.loads(raw)


def extract_docs(html: str) -> List[Dict]:
    """Extract the DOCS array from the page JavaScript."""
    m = re.search(r"const\s+DOCS\s*=\s*(\[.*?\]);", html, re.DOTALL)
    if not m:
        raise RuntimeError("Could not find DOCS array in page source")
    return json.loads(m.group(1))


def find_key_from_changelog(body: str) -> str:
    """
    The key is hidden as an acrostic (first letter of each line)
    inside the CHANGELOG release notes.
    """
    lines = [line.strip() for line in body.splitlines() if line.strip()]
    key = "".join(line[0].upper() for line in lines if line[0].isalpha())
    return key


def vigenere_decrypt(text: str, key: str) -> str:
    """
    Polyalphabetic (Vigenère) recovery.
    - Only A-Z letters are shifted
    - Case is preserved
    - Punctuation and digits stay untouched
    - Key cycles over letters only
    """
    key = key.upper()
    result = []
    ki = 0

    for ch in text:
        if ch.isalpha():
            shift = ord(key[ki % len(key)]) - ord("A")
            base = ord("A") if ch.isupper() else ord("a")
            # recovery = shift backward
            decrypted = chr((ord(ch) - base - shift) % 26 + base)
            result.append(decrypted)
            ki += 1
        else:
            result.append(ch)

    return "".join(result)


def main():
    print("[*] Fetching challenge page...")
    html = fetch(BASE_URL)

    print("[*] Extracting documents...")
    docs = extract_docs(html)

    changelog = None
    vault = None

    for doc in docs:
        data = decode_vdoc(doc["blob"])
        title = data.get("title", "")
        cls = data.get("class", "")

        print(f"    - {doc['title']}  (class={cls})")

        if "CHANGELOG" in title.upper():
            changelog = data
        if cls == "vault":
            vault = data

    if not changelog:
        # fallback: second document is usually CHANGELOG
        changelog = decode_vdoc(docs[1]["blob"])

    if not vault:
        raise RuntimeError("Vault document not found")

    # --- Find the key via acrostic ---
    key = find_key_from_changelog(changelog["body"])
    print(f"\n[+] Key recovered from CHANGELOG acrostic: {key}")

    # --- Decrypt the vault body ---
    ciphertext = vault["body"]
    plaintext = vigenere_decrypt(ciphertext, key)

    print("\n" + "=" * 60)
    print("DECRYPTED VAULT ENTRY")
    print("=" * 60)
    print(plaintext)
    print("=" * 60)

    # Extract flag
    flag_match = re.search(r"CTF2\{[0-9a-f-]+\}", plaintext)
    if flag_match:
        print(f"\n[+] FLAG: {flag_match.group(0)}")
    else:
        print("\n[-] Flag pattern not found in plaintext")


if __name__ == "__main__":
    main()
```

---

## Techniques Used

| Technique                    | Description                                                                 |
|-----------------------------|-----------------------------------------------------------------------------|
| **VDOC1 container analysis**| Reverse-engineered the custom Base64-wrapped JSON format                    |
| **Acrostic steganography**  | Recovered the Vigenère key by reading the first letter of each CHANGELOG line |
| **Vigenère (polyalphabetic) cipher** | Classic letter-shift cipher with key cycling only on alphabetic characters |
| **Known-plaintext hints**   | The almost-flag `CFF2{...}` confirmed that a letter substitution was in use  |

---

## Lessons Learned

- Always read the documentation (README) carefully – the challenge author often tells you exactly where the secret is hidden.
- Classical ciphers combined with simple steganography (acrostic) are still very effective in CTF challenges.
- When a key is said to be “inside the release notes”, check both the obvious words **and** structural patterns such as initial letters.
- Automating the whole pipeline (fetch → parse → acrostic → decrypt) makes the solution reproducible and elegant.

---

