#!/usr/bin/env python3
"""
Break a 256-bit RSA key and decrypt flag.enc. Gantosay

Requires: pip install cryptography
(only used to parse the PEM public key — the actual cryptographic break
and decryption below use nothing but Python's built-in integer arithmetic)
"""

from cryptography.hazmat.primitives import serialization

# ---------------------------------------------------------------
# Step 1: extract n and e directly from the public key file
# ---------------------------------------------------------------
with open("pub.key", "rb") as f:
    pub = serialization.load_pem_public_key(f.read())

numbers = pub.public_numbers()
n = numbers.n
e = numbers.e

print(f"[*] n = {n}")
print(f"[*] e = {e}")
print(f"[*] n is {n.bit_length()} bits  <-- the entire vulnerability, in one number")

# ---------------------------------------------------------------
# Step 2: factor n = p * q
#
# n is only 256 bits (77 decimal digits), which is comfortably within
# range for the Quadratic Sieve. This step was performed externally
# with a dedicated factoring tool (msieve/yafu) / FactorDB — a 256-bit
# balanced semiprime is not something a generic, non-sieve factorer
# (trial division, naive Pollard's rho) finishes in reasonable time.
# ---------------------------------------------------------------
p = 304008741604601924494328155975272418463
q = 285960468890451637935629440372639283459

assert p * q == n, "Factorization is wrong — p*q must equal n"
print(f"[+] Verified: p * q == n")

# ---------------------------------------------------------------
# Step 3: rebuild the private exponent d
# ---------------------------------------------------------------
phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)               # modular inverse of e mod phi(n)

print(f"[+] Recovered private exponent d")

# ---------------------------------------------------------------
# Step 4: decrypt flag.enc
# ---------------------------------------------------------------
with open("flag.enc", "rb") as f:
    c = int.from_bytes(f.read(), "big")

m = pow(c, d, n)                  # m = c^d mod n

# ---------------------------------------------------------------
# Step 5: strip PKCS#1 v1.5 padding (00 || 02 || PS || 00 || M)
# ---------------------------------------------------------------
decrypted_bytes = m.to_bytes((m.bit_length() + 7) // 8, "big")
flag = decrypted_bytes.split(b"\x00")[-1].decode("utf-8").strip()

print(f"[+] Recovered Flag: {flag}")
