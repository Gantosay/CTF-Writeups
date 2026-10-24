# Warmup — libc-less ROP with an `alarm()` eax-control trick

> **Category:** Pwn / Binary Exploitation
> **Platform:** DASCTF
> **Difficulty:** 🔴 Hard
> **Solves:** Only **130** out of all participants solved this one.

---

## 🔒 Why this writeup is locked

This challenge is still **live and scored** on the DASCTF platform. To respect the
platform's point system — and to avoid the flag (or an easy path to it) leaking to
people who haven't earned it — the full writeup, exploit code, and flag are kept in
a **password-protected archive**.

**Want the full technical breakdown?**
DM me your DASCTF username/profile and I'll send you the password.

---

## What this challenge actually involved

No spoilers below — just an honest look at what made this one genuinely hard, and
what it took to solve it.

### The binary

A **724-byte**, statically linked, stripped, 32-bit ELF with **no libc**, **No PIE**,
and **NX enabled**. Every syscall is invoked manually via `int 0x80` — there is no
`libc`, no `system()`, no convenient one-gadget shell. The entire attack surface is
a handful of hand-rolled syscall wrappers totaling well under a thousand bytes of code.

### Why it's rated Hard, not Medium

A few things stack on top of each other here, and each one closes off the "obvious"
path:

- **No gadget sets `eax` to an arbitrary syscall number.** The usual ROP toolkit
  (`pop eax; ret`, one-gadgets, `execve` shortcuts) simply doesn't exist in a binary
  this small. Getting a specific syscall number into `eax` requires finding an
  *indirect* side-channel — nothing about this is handed to you.
- **The overflow only buys ~52 bytes per packet** — just enough for a 2-gadget ROP
  chain. This forces the whole exploit to be broken into multiple stateful,
  sequential stages instead of one clean chain.
- **The binary actively fights back.** After each stage, it deliberately poisons
  every general-purpose register with a recognizable garbage value before
  returning — a conscious anti-exploitation measure by the author that specifically
  blocks the "obvious" way of chaining `open()` → `read()` → `write()` together.
- **It's a remote, SSL-wrapped service with real timing constraints**, which means
  debugging isn't just "run it in gdb" — a misdiagnosed timing or protocol issue
  can easily masquerade as a server-side problem (rate-limiting, connection drops,
  etc.) and send you chasing the wrong thing for a long time. It did, for me.

### Techniques used

- **Return-Oriented Programming (ROP)** from scratch, with zero pre-built gadget
  catalog (no `ROPgadget`/`one_gadget` shortcuts apply to a hand-written,
  libc-less binary this size) — every gadget had to be found and understood
  instruction-by-instruction via manual disassembly.
- **An indirect side-channel to control `eax`**, exploiting a quirk of a specific
  Linux syscall's return-value semantics rather than any direct register-setting
  gadget.
- **Deliberate byte-level gadget overlap** — one legitimate gadget address turned
  out to sit in the *middle* of another gadget's instruction bytes, which is the
  only reason a register-preserving syscall was possible at all.
- **Multi-stage, stateful exploitation** against a tight per-packet byte budget,
  with careful accounting of exactly which registers remain attacker-controlled
  after each hop in a gadget chain (and which ones silently stop being
  controllable once the stack pointer shifts).
- **Systematic remote debugging** over an SSL connection with real network
  timing sensitivity — including catching a misleading "success" signal in the
  service's own protocol that made failed exploitation attempts look identical
  to successful ones at a glance.
- **Reverse-engineering the design intent of the binary itself**, down to
  recognizing a deliberate anti-exploitation trick the author built in on purpose.

### The debugging story (briefly)

My first several attempts failed uniformly, and the natural assumption was
server-side rate-limiting. It wasn't. The real issue took a careful, from-scratch
re-examination of the raw protocol responses to uncover — the service was printing
a reassuring message *unconditionally*, regardless of whether the exploit chain
that followed actually succeeded. Once that was caught and the success criteria
were fixed, the exploit worked on the very first real attempt. The full writeup
walks through this debugging process in detail, because I think it's as valuable
as the final solve itself.

---

## 📬 Interested in the full writeup?

Send me a DM with your **DASCTF username/profile**, and I'll send you the password
to the archive. The full writeup includes:

- Complete instruction-by-instruction disassembly and gadget analysis
- The exact `eax`-control technique, explained step by step
- The full multi-stage exploit script
- A verified, author-faithful assembly reconstruction of the binary
- The complete debugging journey, including the dead ends

---

*Solved and written up independently — this remains the only public writeup for
this challenge at the time of publishing.*
