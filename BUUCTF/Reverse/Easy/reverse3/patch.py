import shutil, sys

src, dst = "reverse_3.exe", "reverse_3_patched.exe"
offset   = 0x4C40                    # file offset of the `jz` (VA 0x415840)
original = bytes.fromhex("740f")     # jz  0x415851
patched  = bytes.fromhex("eb0f")     # jmp 0x415851

shutil.copyfile(src, dst)
with open(dst, "r+b") as f:
    f.seek(offset)
    if f.read(2) != original:
        sys.exit("bytes at offset don't match; wrong file or wrong offset")
    f.seek(offset)
    f.write(patched)
print("patched OK")