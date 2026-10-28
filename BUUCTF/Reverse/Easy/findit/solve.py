#!/usr/bin/env python3
"""
CTF Solver — Gatekeeper bypass via logic replication.
Replicates Section 3's (b -> y) decryption from MainActivity.onClick,
including its non-standard >= 'z' boundary-wrap condition. Never touches
the UI, the serial key, or Section 1/2 at all.
"""

CIPHER_B = [
    'p', 'v', 'k', 'q', '{', 'm', '1', '6', '4', '6', '7', '5', '2', '6',
    '2', '0', '3', '3', 'l', '4', 'm', '4', '9', 'l', 'n', 'p', '7', 'p',
    '9', 'm', 'n', 'k', '2', '8', 'k', '7', '5', '}',
]


def decrypt_b(cipher: list[str]) -> str:
    out = []
    for ch in cipher:
        if ('A' <= ch <= 'Z') or ('a' <= ch <= 'z'):
            shifted = ord(ch) + 16
            # Exact replica of: (y > 'Z' && y < 'a') || y >= 'z'
            if (ord('Z') < shifted < ord('a')) or (shifted >= ord('z')):
                shifted -= 26
            out.append(chr(shifted))
        else:
            out.append(ch)  # digits and braces pass through untouched
    return ''.join(out)


def derive_serial_key(seed: str) -> str:
    """Bonus: replicates Section 1 too, in case you want to try the real UI."""
    out = []
    for ch in seed:
        if ('A' <= ch < 'I') or ('a' <= ch < 'i'):
            out.append(chr(ord(ch) + 18))
        elif ('A' <= ch <= 'Z') or ('a' <= ch <= 'z'):
            out.append(chr(ord(ch) - 8))   # '\b' == ASCII 8
        else:
            out.append(ch)
    return ''.join(out)


if __name__ == "__main__":
    flag = decrypt_b(CIPHER_B)
    key = derive_serial_key("ThisIsTheFlagHome")

    print(f"[+] Exploit complete — no key search needed")
    print(f"[-] Extracted flag       : {flag}")
    print(f"[-] Serial key (for UI)  : {key}")