#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# [GUET-CTF 2019] re - Method 1: Direct Algebraic Inversion
#
# Every check() comparison has the form  flag[i] * MULTIPLIER[i] == TARGET[i].
# Since multiplication by a nonzero constant is invertible over the integers
# (not just modular arithmetic) for these specific values, each character can
# be recovered directly via integer division -- no solver needed at all.
#
# Index 6 is never checked by the binary (see write-up section 5.1), so it's
# left as an open position; the real flag restricts it to one of 16 hex
# digits, so all 16 candidates are enumerated at the end.

# (multiplier, target) extracted directly from each `imul`/`cmp` pair in
# check()'s disassembly, one entry per character index actually tested.
CHECKS = {
    0:  (0x18db80, 0x09e77500),  1:  (0x675390, 0x2b9740c0),  2:  (0x383280, 0x154b2280),
    3:  (0x9f2a18, 0x4009efa8),  4:  (0x3cb070, 0x1d28c5d0),  5:  (0x4e67a0, 0x1eeee220),
    7:  (0x72eeda, 0x183e61fc),  8:  (0x54b610, 0x1189b150),  9:  (0x340740, 0x0a917900),
    10: (0xc692a6, 0x26c8a46c),  11: (0x5ce85d, 0x11c879cd),  12: (0x784f77, 0x170735c7),
    13: (0x8879b5, 0x1a1f4ba5),  14: (0x4f529a, 0x0edf7ce0),  15: (0x455806, 0x1a8bb24c),
    16: (0x9a58d0, 0x3a7ba6d0),  17: (0x37a0a0, 0x0a6e1e00),  18: (0x9383b0, 0x1d633c10),
    19: (0x51dae2, 0x0f590a60),  20: (0xcd73dc, 0x2dbecbfc),  21: (0x53bf30, 0x12a591b0),
    22: (0xdcf08c, 0x53b7250c),  23: (0x627276, 0x12d7e896),  24: (0x5f6820, 0x24e54460),
    25: (0x7675a4, 0x16360ec0),  26: (0x6fce58, 0x16461b88),  27: (0x856290, 0x1db2f210),
    28: (0x875fc4, 0x1af8140c),  29: (0x3e5bc0, 0x0c6c4740),  30: (0x8f0ac0, 0x1ebb4f40),
    31: (0x57e094, 0x2ae8a844),
}

FLAG_LENGTH = 32
UNCHECKED_INDEX = 6   # see write-up section 5.1


def recover_checked_characters():
    """
    Invert every exactly-checked index directly. Each result is verified by
    re-multiplying before being accepted, rather than trusting the division
    blindly -- a cheap sanity check that would immediately flag a transcription
    error in any of the extracted constants.
    """
    recovered = {}

    for index, (multiplier, target) in CHECKS.items():
        if target % multiplier != 0:
            raise ValueError(
                f"index {index}: target {hex(target)} is not evenly divisible "
                f"by multiplier {hex(multiplier)} -- check the extracted constants"
            )

        value = target // multiplier

        # Verify the forward direction too, not just that division was exact.
        assert value * multiplier == target

        recovered[index] = chr(value)

    return recovered


def build_candidate_flags(recovered):
    """
    Assemble the full 32-character flag, trying every printable hex digit
    (0-9, a-f) in the one position the binary's check() never actually tests.
    """
    candidates = []

    for hex_digit in "0123456789abcdef":
        chars = ["?"] * FLAG_LENGTH

        for index, char in recovered.items():
            chars[index] = char

        chars[UNCHECKED_INDEX] = hex_digit
        candidates.append("".join(chars))

    return candidates


def main():
    recovered = recover_checked_characters()

    print(f"[+] Recovered {len(recovered)} of {FLAG_LENGTH} characters directly.")
    print(f"[+] Index {UNCHECKED_INDEX} is never checked by the binary -- ")
    print(f"    any of the 16 candidates below makes the LOCAL binary print 'Correct!'")
    print()

    for candidate in build_candidate_flags(recovered):
        print(candidate)


if __name__ == "__main__":
    main()