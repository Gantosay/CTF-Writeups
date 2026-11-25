#!/usr/bin/env python3
"""
unpack.py - turn debugme.exe into a file that static tools understand.

debugme hides _main (0x401620 .. 0x401791, 370 bytes) under a 1-byte XOR
(key 0x5c) and hijacks the entry point (0x4010f9) so that a stub in .text
padding decrypts it at start-up.  This script:

  1. XORs the 370 bytes back with 0x5c, and
  2. restores the 6 bytes the entry-point hijack overwrote
     (push ebp / mov ebp,esp / sub esp,0x18  ->  55 89 e5 83 ec 18).

Usage: python3 unpack.py debugme.exe [debugme_unpacked.exe]
"""
import sys

# .text: VA 0x401000 -> file offset 0x400 (see `iS` in rizin)
va2off = lambda va: 0x400 + (va - 0x401000)

src = sys.argv[1] if len(sys.argv) > 1 else "debugme.exe"
dst = sys.argv[2] if len(sys.argv) > 2 else "debugme_unpacked.exe"
d = bytearray(open(src, "rb").read())

for va in range(0x401620, 0x401791 + 1):      # inclusive: the stub uses `jle`
    d[va2off(va)] ^= 0x5C

entry = va2off(0x4010F9)
assert d[entry] == 0xE9, "entry point does not start with the expected jmp"
d[entry:entry + 6] = bytes.fromhex("55 89 e5 83 ec 18")

open(dst, "wb").write(d)
print(f"[+] wrote {dst}")
