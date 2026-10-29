#!/usr/bin/env python3
"""
Reverse-engineering solver for the "pyre" Python 2 cipher-Gantosay.

Undoes, in order:
  1. Stage 2 (chained XOR, undone RIGHT TO LEFT, anchored on the
     untouched last byte caused by the challenge's `range(l - 1)` bug)
  2. Stage 1 (positional additive shift, undone LEFT TO RIGHT)
"""


def reverse_cipher():
    # Normalize the challenge's mixed hex-escape / literal-char token
    # list into a flat list of plain integers.
    encrypted_code = [
        0x1f, 0x12, 0x1d, ord('('), ord('0'), ord('4'), 0x01, 0x06,
        0x14, ord('4'), ord(','), 0x1b, ord('U'), ord('?'), ord('o'),
        ord('6'), ord('*'), ord(':'), 0x01, ord('D'), ord(';'), ord('%'), 0x13,
    ]
    length = len(encrypted_code)

    # --- Step 1: undo Stage 2, right to left --------------------------
    # code[length-1] is never touched by the original encryption, so it
    # is already correct. Starting one position to its left, each byte
    # is restored using the neighbor we *just* restored.
    for i in range(length - 2, -1, -1):
        encrypted_code[i] ^= encrypted_code[i + 1]

    # --- Step 2: undo Stage 1, left to right ---------------------------
    flag_chars = []
    for i in range(length):
        original_ascii_val = (encrypted_code[i] - i) % 128
        flag_chars.append(chr(original_ascii_val))

    flag = ''.join(flag_chars)
    print(f"[+] Decryption successful!")
    print(f"[+] Extracted flag: {flag}")
    return flag


if __name__ == "__main__":
    reverse_cipher()