#!/usr/bin/env python3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

p = 304008741604601924494328155975272418463
q = 285960468890451637935629440372639283459
e = 65537
n = p * q
d = pow(e, -1, (p - 1) * (q - 1))

private_numbers = rsa.RSAPrivateNumbers(
    p=p,
    q=q,
    d=d,
    dmp1=d % (p - 1),             # CRT exponent for p — a standard RSA optimization field
    dmq1=d % (q - 1),             # CRT exponent for q
    iqmp=pow(q, -1, p),           # CRT coefficient — q's inverse mod p
    public_numbers=rsa.RSAPublicNumbers(e=e, n=n)
)

private_key = private_numbers.private_key()

with open("priv.key", "wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ))

print("[+] Private key saved to priv.key")