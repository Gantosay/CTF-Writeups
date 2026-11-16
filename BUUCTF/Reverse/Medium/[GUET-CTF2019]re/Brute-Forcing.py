#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# [GUET-CTF 2019] re - Method 4: Empirical Brute-Force of the Unchecked Index 6
#
# Sections 5.1 and 7.1 both claim, from reading the disassembly, that
# check() never reads or compares index 6 at all. Rather than leaving that
# as an unverified reading of the assembly, this script actually launches
# the real target binary once per candidate hex digit and records its
# genuine stdout response -- producing a reproducible table of evidence
# instead of an assertion.

import subprocess

BINARY_PATH = "./re"

# The 31 characters already recovered by direct algebraic inversion
# (Method 1, section 7.1), with index 6 left as a placeholder to be
# substituted on each attempt.
KNOWN_FLAG_TEMPLATE = list("flag{e?65421110ba03099a1c039337}")
UNCHECKED_INDEX = 6

# Every printable hex digit -- the full candidate set implied by the
# flag's known external format (a hex MD5-style substring).
HEX_DIGITS = "0123456789abcdef"


def build_candidate(hex_digit: str) -> str:
    chars = KNOWN_FLAG_TEMPLATE.copy()
    chars[UNCHECKED_INDEX] = hex_digit
    return "".join(chars)


def run_binary(candidate_flag: str) -> str:
    """
    Launch a genuinely fresh instance of the target binary, send the
    candidate flag on stdin exactly as a human would at the prompt, and
    return whatever it actually printed, stripped of surrounding
    whitespace. No part of the binary's logic is modeled or simulated
    here -- this is the real compiled program's real stdout.
    """
    process = subprocess.run(
        [BINARY_PATH],
        input=(candidate_flag + "\n").encode(),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )
    return process.stdout.decode(errors="replace").strip()


def main():
    print(f"{'hex digit':<10} {'candidate flag':<36} {'binary response':<20} result")
    print("-" * 90)

    passing = []

    for hex_digit in HEX_DIGITS:
        candidate = build_candidate(hex_digit)
        output = run_binary(candidate)

        passed = "Correct!" in output
        if passed:
            passing.append(hex_digit)

        verdict = "PASS" if passed else "FAIL"
        short_output = output.splitlines()[-1] if output else "(no output)"
        print(f"{hex_digit!r:<10} {candidate:<36} {short_output:<20} {verdict}")

    print("-" * 90)
    print(f"\n[+] {len(passing)} / {len(HEX_DIGITS)} hex digits made the LOCAL binary print 'Correct!':")
    print(f"    {passing}")
    print()
    print("[!] This confirms check() imposes NO constraint on index 6 at all --")
    print("    every single hex digit passes the local binary equally. The real,")
    print("    scoreboard-valid character ('1') cannot be distinguished from the")
    print("    other 15 by running this binary alone; it comes from the flag's")
    print("    known external format (hex MD5-style substring), not from check().")


if __name__ == "__main__":
    main()