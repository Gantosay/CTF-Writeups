#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# [GWCTF 2019] xxor - full offline solver- Gantosay
#
# Strategy:
#   1. Re-implement the modified-TEA round function exactly as disassembled
#      from fcn.00400686, and its inverse.
#   2. Self-test the inverse against the forward function on random data
#      before trusting it on the real ciphertext.
#   3. Solve the 3-equation / 3-unknown modular linear system for
#      enc[2], enc[3], enc[4] from the validator's constraints
#      (fcn.00400770), handling the mod 2^32 "divide by 2" ambiguity
#      by trying both roots and keeping the one that decrypts to ASCII.
#   4. Decrypt all three (v0, v1) pairs and reassemble the flag.

import struct

MASK = 0xffffffff


# ----------------------------------------------------------------------
# Cipher: exact re-implementation of fcn.00400686
# ----------------------------------------------------------------------
DELTA  = 0x458bcd42
ROUNDS = 64


def encrypt_block(v0, v1, key):
    """Forward direction -- only used here to self-test the inverse."""
    k0, k1, k2, k3 = key
    s = 0
    for _ in range(ROUNDS):
        s = (s + DELTA) & MASK
        v0 = (v0 + ((((v1 << 6) & MASK) + k0) & MASK
                    ^ (s + v1 + 0x0b) & MASK
                    ^ ((v1 >> 9) + k1) & MASK
                    ^ 0x20)) & MASK
        v1 = (v1 + ((((v0 << 6) & MASK) + k2) & MASK
                    ^ (s + v0 + 0x14) & MASK
                    ^ ((v0 >> 9) + k3) & MASK
                    ^ 0x10)) & MASK
    return v0, v1


def decrypt_block(v0, v1, key):
    """
    Inverse direction -- this is what actually recovers the flag.
    Must undo the two per-round updates in REVERSE order relative to the
    forward function, because the forward function computed v1's update
    using the freshly-updated v0.
    """
    k0, k1, k2, k3 = key
    s = (DELTA * ROUNDS) & MASK

    for _ in range(ROUNDS):
        v1 = (v1 - ((((v0 << 6) & MASK) + k2) & MASK
                    ^ (s + v0 + 0x14) & MASK
                    ^ ((v0 >> 9) + k3) & MASK
                    ^ 0x10)) & MASK
        v0 = (v0 - ((((v1 << 6) & MASK) + k0) & MASK
                    ^ (s + v1 + 0x0b) & MASK
                    ^ ((v1 >> 9) + k1) & MASK
                    ^ 0x20)) & MASK
        s = (s - DELTA) & MASK

    return v0, v1


def self_test(key):
    """Round-trip a handful of random blocks before trusting decrypt_block."""
    import random
    random.seed(1337)
    for _ in range(16):
        a = random.randint(0, MASK)
        b = random.randint(0, MASK)
        enc_a, enc_b = encrypt_block(a, b, key)
        dec_a, dec_b = decrypt_block(enc_a, enc_b, key)
        assert (dec_a, dec_b) == (a, b), "cipher inverse is WRONG -- stop and recheck the disassembly"
    print("[+] Cipher inverse self-test passed (16/16 random round-trips)")


# ----------------------------------------------------------------------
# Key, extracted from 0x601060 via `pxw 32 @ 0x601060` in rizin
# ----------------------------------------------------------------------
KEY = (2, 2, 3, 4)


# ----------------------------------------------------------------------
# Target ciphertext constants, extracted from fcn.00400770
# ----------------------------------------------------------------------
ENC0 = 0xdf48ef7e   # exact:   enc[0]        == ENC0
ENC1 = 0x20caacf4   # exact:   enc[1]        == ENC1
ENC5 = 0x84f30420   # exact:   enc[5]        == ENC5

DIFF_23 = 0x84a236ff   # enc[2] - enc[3]
SUM_34  = 0xfa6cb703   # enc[3] + enc[4]
DIFF_24 = 0x42d731a8   # enc[2] - enc[4]


def solve_enc_2_3_4():
    """
    Solve:
        enc2 - enc3 = DIFF_23
        enc3 + enc4 = SUM_34
        enc2 - enc4 = DIFF_24
    over Z / 2^32 Z.

    Adding the first two eliminates enc3:  enc2 + enc4 = DIFF_23 + SUM_34
    Combined with enc2 - enc4 = DIFF_24:   2*enc2 = (DIFF_23 + SUM_34) + DIFF_24

    Dividing by 2 under mod 2^32 has exactly two roots whenever the
    dividend is even (always true here, since the LHS is literally "2 *
    something"): the naive integer-division result, and that value plus
    0x80000000 (since 2 * 0x80000000 == 0, mod 2^32). Both candidates
    satisfy the equations equally well algebraically -- only decrypting
    and checking for ASCII tells you which is the real one.
    """
    two_enc2 = (DIFF_23 + SUM_34 + DIFF_24) & MASK

    candidates = []
    for guess_bit in (0x0, 0x80000000):
        enc2 = ((two_enc2 // 2) + guess_bit) & MASK
        enc4 = (enc2 - DIFF_24) & MASK
        enc3 = (enc2 - DIFF_23) & MASK

        # sanity-check all three original equations before accepting a candidate
        assert (enc2 - enc3) & MASK == DIFF_23
        assert (enc3 + enc4) & MASK == SUM_34
        assert (enc2 - enc4) & MASK == DIFF_24

        candidates.append((enc2, enc3, enc4))

    return candidates


def try_decode(enc_values, key):
    """Decrypt all three (v0, v1) pairs and attempt to build an ASCII flag."""
    enc0, enc1, enc2, enc3, enc4, enc5 = enc_values

    in0, in1 = decrypt_block(enc0, enc1, key)
    in2, in3 = decrypt_block(enc2, enc3, key)
    in4, in5 = decrypt_block(enc4, enc5, key)

    inputs = (in0, in1, in2, in3, in4, in5)

    try:
        flag_bytes = b"".join(struct.pack('>I', v).lstrip(b'\x00') for v in inputs)
        flag_str = flag_bytes.decode('ascii')
        is_printable = flag_str.isprintable()
    except (UnicodeDecodeError, ValueError):
        flag_str = None
        is_printable = False

    return inputs, flag_str, is_printable


def main():
    self_test(KEY)

    print("[*] Solving modular system for enc[2], enc[3], enc[4] ...")
    candidates = solve_enc_2_3_4()

    for idx, (enc2, enc3, enc4) in enumerate(candidates):
        enc_values = (ENC0, ENC1, enc2, enc3, enc4, ENC5)
        inputs, flag_str, is_printable = try_decode(enc_values, KEY)

        print(f"\n--- Candidate #{idx} (enc2={hex(enc2)}, enc3={hex(enc3)}, enc4={hex(enc4)}) ---")
        print("    Recovered input[] words:")
        for i, val in enumerate(inputs):
            signed_val = struct.unpack('<i', struct.pack('<I', val))[0]
            print(f"      input[{i}] = {signed_val}  (0x{val:08x})")

        if is_printable:
            print(f"    [+] ASCII-printable result -> FLAG: {flag_str}")
        else:
            print(f"    [-] Not printable ASCII, discarding this candidate.")


if __name__ == '__main__':
    main()
