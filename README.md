# 🗺️ CTF Writeups Repository

Welcome to my central archive of weaponized exploits and detailed write-ups from various Capture The Flag (CTF) competitions. This repository focuses heavily on **Binary Exploitation (Pwn)** and **Reverse Engineering**.

---

## 🎯 Exploitation Matrix & Categorization

Instead of just listing dates, these write-ups are organized by core vulnerabilities, memory corruption primitives, and architectures:

### 🧠 1. Userland Heap Exploitation
*Advanced glibc heap manipulation, feng shui, and structure hijacking.*
*   📂 **Soon.
*   📂 **Soon.

### 🛡️ 2. Stack & Format String Restrictions
*Bypassing modern mitigations (ASLR, PIE, Canary, CET) through raw memory corruption.*
*   📂 **[PicoCTF]**: Leakless ROP chain building via partial overwrites under strict ASLR constraints.
*   📂 **[BUUCTF]**: Arbitrary read/write using positional format string specifiers to overwrite dynamic relocations.

### 🐧 3. Kernel Land & Hypervisor Escapes
*Low-level exploitation focusing on ring-0 execution and isolation bypasses.*
*   📂 **[Private]**: Linux Kernel Pwn involving a Use-After-Free (UAF) in a custom driver to overwrite `cred` structures.

---

## 🛠️ My Weaponization Workflow

Every write-up in this repository follows a strict, repeatable engineering workflow:
1.  **Recon & Mitigations:** Documenting `checksec` outputs, `libc` versions, and sandbox constraints (`seccomp`).
2.  **Primitive Discovery:** Pinpointing logic flaws and memory corruption bugs in decompiled code (IDA Pro / Ghidra).
3.  **Local Emulation:** Reliable local proof-of-concept (PoC) using `pwntools` and debugging with `GDB+GEF`.
4.  **Remote Weaponization:** Crafting stable exploit chains to catch the remote flag.

---

## 📊 Repository Roadmap
- [x] Migrate all legacy historical write-ups with full Git history.
- [ ] Document upcoming kernel-pwn and browser exploitation targets.
- [ ] Automate dynamic analysis scaffolding for newly discovered binaries.

---
*If it runs, it can be exploited. Happy Pwning! 💀*
