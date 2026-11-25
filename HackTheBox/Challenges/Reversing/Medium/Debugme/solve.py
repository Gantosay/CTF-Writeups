#!/usr/bin/env python3
"""
debugme (Hack The Box, Reverse Engineering) - static solver.

The flag is never printed by the program; it is rebuilt on the stack at
run time and then decoded in place.  This script reproduces that logic
WITHOUT running the binary (so none of the anti-debug tricks matter):

  1. Parse the PE header and map virtual addresses to file offsets.
  2. Undo the 1-byte XOR (key 0x5c) that hides _main on disk.
  3. Walk the decrypted code with a tiny emulator that understands only
     the handful of opcodes the author used, and record every `push eax`.
  4. Lay the pushed dwords out the way the stack would hold them
     (stack grows DOWN, so the last push sits at the lowest address).
  5. XOR the 36 bytes with 0x4b - exactly what the lodsb/xor/stosb loop does.

Usage:  python3 solve.py [path/to/debugme.exe]
"""
import struct
import sys

MAIN_START = 0x401620      # first byte hidden by the XOR stub
MAIN_END   = 0x401791      # last byte (inclusive) - the final `ret`
XOR_KEY_1  = 0x5C          # key of the on-disk "packer"
MASK32     = 0xFFFFFFFF


# --------------------------------------------------------------------------
# PE helpers
# --------------------------------------------------------------------------
class PE:
    def __init__(self, data: bytearray):
        self.data = data
        pe = struct.unpack_from("<I", data, 0x3C)[0]
        nsec = struct.unpack_from("<H", data, pe + 6)[0]
        opt_size = struct.unpack_from("<H", data, pe + 20)[0]
        opt = pe + 24
        self.image_base = struct.unpack_from("<I", data, opt + 28)[0]
        self.sections = []
        off = opt + opt_size
        for _ in range(nsec):
            vsize, rva, rsize, roff = struct.unpack_from("<IIII", data, off + 8)
            self.sections.append((rva, max(vsize, rsize), roff))
            off += 40

    def va_to_off(self, va: int) -> int:
        rva = va - self.image_base
        for s_rva, s_size, s_off in self.sections:
            if s_rva <= rva < s_rva + s_size:
                return s_off + (rva - s_rva)
        raise ValueError(f"VA {va:#x} is not inside any section")


# --------------------------------------------------------------------------
# Step 2: remove the XOR layer that hides _main
# --------------------------------------------------------------------------
def unpack_main(pe: PE) -> bytes:
    start = pe.va_to_off(MAIN_START)
    length = MAIN_END - MAIN_START + 1                 # 0x172 = 370 bytes
    for i in range(length):
        pe.data[start + i] ^= XOR_KEY_1
    return bytes(pe.data[start:start + length])


# --------------------------------------------------------------------------
# Step 3: mini-emulator for the flag-building block (0x4016b4 .. 0x401772)
# --------------------------------------------------------------------------
def emulate_pushes(code: bytes):
    """Return the list of dwords pushed, in push order."""
    pc = 0x4016B4 - MAIN_START
    stop = 0x401772 - MAIN_START
    eax, pushes = 0, []
    while pc < stop:
        op = code[pc]
        if op == 0xB8:                                 # mov eax, imm32
            eax = struct.unpack_from("<I", code, pc + 1)[0]; pc += 5
        elif op == 0x2D:                               # sub eax, imm32
            eax = (eax - struct.unpack_from("<I", code, pc + 1)[0]) & MASK32; pc += 5
        elif op == 0x05:                               # add eax, imm32
            eax = (eax + struct.unpack_from("<I", code, pc + 1)[0]) & MASK32; pc += 5
        elif op == 0x25:                               # and eax, imm32
            eax &= struct.unpack_from("<I", code, pc + 1)[0]; pc += 5
        elif code[pc:pc + 2] == b"\x31\xc0":           # xor eax, eax
            eax = 0; pc += 2
        elif op == 0x50:                               # push eax
            pushes.append(eax); pc += 1
        elif op == 0xE9:                               # jmp rel32 (always +0 here)
            pc += 5 + struct.unpack_from("<i", code, pc + 1)[0]
        else:
            raise ValueError(f"unexpected opcode {op:#04x} at {MAIN_START + pc:#x}")
    return pushes


# --------------------------------------------------------------------------
# Steps 4 + 5: stack layout and in-place XOR decode
# --------------------------------------------------------------------------
def decode(pushes, key: int, length: int) -> bytes:
    # last push = lowest address, and ESI starts at ESP, so reading goes
    # push_9 -> push_8 -> ... -> push_1 (each dword little-endian).
    stack = b"".join(struct.pack("<I", v) for v in reversed(pushes))
    return bytes(b ^ key for b in stack[:length])


def main() -> None:
    path = sys.argv[1] if len(sys.argv) > 1 else "debugme.exe"
    pe = PE(bytearray(open(path, "rb").read()))
    code = unpack_main(pe)

    # Pull the loop parameters straight out of the decrypted code
    length = struct.unpack_from("<I", code, 0x40177C - MAIN_START)[0]   # mov ecx, 0x24
    key = struct.unpack_from("<I", code, 0x401781 - MAIN_START)[0]      # mov ebx, 0x4b
    pushes = emulate_pushes(code)

    print(f"[+] decoded loop: {length} bytes, XOR key {key:#04x}")
    for i, v in enumerate(pushes, 1):
        print(f"    push {i}: {v:#010x}")
    flag = decode(pushes, key, length).decode()
    print(f"[+] flag body : {flag}")
    print(f"[+] flag      : HTB{{{flag}}}")


if __name__ == "__main__":
    main()
