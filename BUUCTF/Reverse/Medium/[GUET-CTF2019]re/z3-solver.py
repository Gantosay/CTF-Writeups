#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# [GUET-CTF 2019] re - Method 2: Constraint Solving with Z3
#
# Same extracted constants as Method 1, but expressed as SMT constraints
# instead of inverted by hand. This generalizes to checks involving bitwise
# operations, modular wraparound, or inter-character dependencies that plain
# algebraic inversion couldn't handle directly.

from z3 import BitVec, Solver, sat

FLAG_LENGTH = 32

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


def build_solver():
    solver = Solver()

    # One 32-bit symbolic variable per character, matching the width `eax`
    # actually operates in within check()'s disassembly.
    flag_vars = [BitVec(f"flag_{i}", 32) for i in range(FLAG_LENGTH)]

    # Constrain every character to the printable ASCII range. This also
    # implicitly tells Z3 what to do about the never-checked index 6: with
    # no multiplication constraint at all on that variable, Z3 is free to
    # pick ANY value in [0x20, 0x7e] for it -- it will simply choose
    # whatever satisfies the range constraint with the least search effort,
    # which is not guaranteed to be the scoreboard's real value.
    for var in flag_vars:
        solver.add(var >= 0x20, var <= 0x7e)

    for index, (multiplier, target) in CHECKS.items():
        solver.add(flag_vars[index] * multiplier == target)

    return solver, flag_vars


def main():
    solver, flag_vars = build_solver()

    if solver.check() != sat:
        print("[-] No satisfying assignment found.")
        return

    model = solver.model()
    flag_bytes = bytes(model[var].as_long() for var in flag_vars)

    print("[+] Z3 found a satisfying assignment:")
    print(flag_bytes.decode())
    print()
    print("[!] Index 6 was unconstrained -- Z3 picked the lowest value in")
    print("    range that satisfies 0x20 <= x <= 0x7e, which is a SPACE")
    print("    character (0x20), not necessarily the real flag's '1'.")


if __name__ == "__main__":
    main()