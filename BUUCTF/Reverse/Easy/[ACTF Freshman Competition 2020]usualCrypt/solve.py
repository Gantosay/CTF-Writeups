import string

std = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
t = list(std)
for i in range(6, 15):
    t[i], t[i+10] = t[i+10], t[i]
table = "".join(t)

target = "zMXHz3TIgnxLxJhFAdtZn2fFk3lYCrtPC2l9"
s = target.swapcase()

bits = "".join(f"{table.index(c):06b}" for c in s)
flag = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
print(flag.decode())