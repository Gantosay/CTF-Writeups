#!/usr/bin/env python3
"""Solver for BUUCTF "Scratch and Win" (刮开有奖)."""
import base64

# 1) Constants the binary pushes on the stack, then sorts with fcn.004010f0
RAW = [90, 74, 83, 69, 67, 97, 78, 72, 51, 110, 103]   # Z J S E C a N H 3 n g
s = sorted(RAW)                                         # ascending, like the binary

# stack slots actually referenced by the checks
a0, a2, a4, a7 = s[0], s[2], s[4], s[7]                 # 51, 69, 74, 90

# 2) Algebraic gates
c0 = chr(a0 + 34)                                       # 'U'
c1 = chr(a4)                                            # 'J'
c2 = chr((3 * a2 + 141) // 4)                           # 'W'
c3_candidates = [chr(x) for x in range(256) if x // 4 == 2 * (a7 // 9)]  # 'P'..'S'

# 3) Base64 gates
idx_234 = base64.b64decode("V1Ax").decode()             # "WP1" -> input[2:5]
idx_567 = base64.b64decode("ak1w").decode()             # "jMp" -> input[5:8]

# 4) Cross-check: Base64 pins down the ambiguous index 3
assert idx_234[0] == c2, "index 2 mismatch"
assert idx_234[1] in c3_candidates, "index 3 not allowed by the algebra"

flag = c0 + c1 + idx_234 + idx_567
print(f"[+] algebra allows index 3 in : {''.join(c3_candidates)}")
print(f"[+] base64 pins index 3 to    : {idx_234[1]}")
print(f"[+] key  : {flag}")
print(f"[+] flag : flag{{{flag}}}")