#!/usr/bin/env python3
"""
VOIDDOC / VDOC1 - Vault Decryptor - Gantosay
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

        if "CHANGELOG" in title.upper() or cls == "note" and "release" in str(data.get("meta", {})).lower():
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
