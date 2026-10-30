key = [37, 43, 32, 38, 58, 40, 37, 30, 40, 30, 50, 52, 33, 44, 40, 51,
       30, 51, 39, 40, 50, 30, 37, 43, 32, 38, 30, 51, 39, 36, 45, 30,
       40, 30, 54, 40, 43, 43, 30, 38, 36, 51, 30, 47, 46, 40, 45, 51,
       50, 60, -65]

buf = bytearray(b"A" * 51)
for i in range(51):
    buf[i] = (buf[i] + key[i]) & 0xFF   # same as writing the low byte (cl)

print(buf.split(b"\x00")[0].decode())
