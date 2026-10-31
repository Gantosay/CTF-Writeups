#!/usr/bin/env python3
table  = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm"
target = "TOiZiZtOrYaToUwPnToBsOaOapsyS"          # 29 bytes
LETTERS = ("abcdefghijklmnopqrstuvwxyz"
           "ABCDEFGHIJKLMNOPQRSTUVWXYZ")

def enc(c: str) -> str:
    """Python port of 0x411940."""
    if 'a' <= c <= 'z':
        return table[ord(c) - 0x60]
    if 'A' <= c <= 'Z':
        i = ord(c) - 0x26
        return table[i] if i < len(table) else '\0'   # 'Z' -> C NUL terminator
    raise SystemExit("exit(0): non-letter reached transform")

inv = {enc(c): c for c in LETTERS}
assert len(inv) == 52                              # the map is injective

def solve(parity: int) -> str:
    return "".join(inv.get(ch, ch) if i % 2 == parity else ch
                   for i, ch in enumerate(target))

for parity in (0, 1):
    cand = solve(parity)
    # round-trip holds for BOTH parities, so it does not select the right one
    fwd = "".join(enc(c) if i % 2 == parity else c for i, c in enumerate(cand))
    print(parity, cand, fwd == target)

head = solve(1)                                    # odd indices encrypted
flag = head + "E"                                  # 30th letter: needed, unchecked
print(f"flag{{{flag}}}")