import base64

target = b"e3nifIH9b_C@n@dH"

# Step 1: undo "dest[j] += j"
b64 = bytes((c - j) & 0xFF for j, c in enumerate(target))
print("after undoing the shift:", b64)          # b'e2lfbDB2ZV95b3V9'

# Step 2: undo Base64
answer = base64.b64decode(b64)
print("answer:", answer.decode())               # {i_l0ve_you}