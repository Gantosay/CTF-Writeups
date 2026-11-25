# Hack The Box – `debugme` (Reverse Engineering) – Full Write-up

> *"I heard you like bugs so I put bugs in your debugger so you can have bugs while you debug!!!"*

`debugme` is an old (≈ 2012-era) Hack The Box reverse-engineering challenge, and a lovely one: a tiny 32-bit
Windows program that

1. **hides its own `main()`** under a one-byte XOR so that static disassemblers show garbage,
2. **hijacks the entry point** so a stub in unused `.text` padding decrypts `main()` before it runs,
3. **detects debuggers three different ways** (twice – once in the stub and once in `main`),
4. and finally **builds the flag on the stack, decodes it in place, and never prints it**.

Most write-ups online just say "patch the checks and look at the stack". This one explains **every
instruction** so you can see *why* it works.

**Flag:** `HTB{Tr0lling_Ant1_D3buGGeR_trickz_R_fun!}`
(body: `Tr0lling_Ant1_D3buGGeR_trickz_R_fun!`)

---

## Table of contents

1. [Files in this repo](#1-files-in-this-repo)
2. [Challenge overview & tooling](#2-challenge-overview--tooling)
3. [Step 1 – Triage](#3-step-1--triage)
4. [Step 2 – `main` is garbage: spotting the XOR layer](#4-step-2--main-is-garbage-spotting-the-xor-layer)
5. [Step 3 – Following the entry point to the decryptor stub](#5-step-3--following-the-entry-point-to-the-decryptor-stub)
6. [Step 4 – Decrypting `main` inside Rizin](#6-step-4--decrypting-main-inside-rizin)
7. [Step 5 – Reading the real `main`, instruction by instruction](#7-step-5--reading-the-real-main-instruction-by-instruction)
   - 7.1 [Anti-debugging](#71-anti-debugging-three-tricks)
   - 7.2 [Building the flag on the stack](#72-building-the-flag-on-the-stack)
   - 7.3 [The decode loop](#73-the-decode-loop)
8. [Step 6 – Getting the flag](#8-step-6--getting-the-flag)
   - 8.1 [Static: no debugger needed](#81-static-no-debugger-needed)
   - 8.2 [Dynamic: the intended way](#82-dynamic-the-intended-way)
9. [How the author built it (reconstructed source)](#9-how-the-author-built-it-reconstructed-source)
10. [Summary of the protection layers](#10-summary-of-the-protection-layers)
11. [Lessons learned](#11-lessons-learned)

---

## 1. Files in this repo

| File | Purpose |
|---|---|
| `README.md` | This write-up |
| `solve.py` | Self-contained static solver: unpacks `main`, emulates the push sequence, decodes the flag |
| `unpack.py` | Undoes the XOR layer and the entry-point hijack, producing a clean `.exe` for static tools |
| `mash.asm` | Reconstructed original source (NASM, standalone assembly file) |
| `debugme_reconstructed.c` | Same code wrapped in a C file (`__asm__` block), so plain `gcc` can build it |
| `debugme_model.c` | Portable C model of the flag logic – compile and run it on any OS |
| `debugme.exe` | The challenge binary (not included here – download it from Hack The Box) |

---

## 2. Challenge overview & tooling

| Property | Value |
|---|---|
| Format | PE32 console executable, Intel 80386 |
| Size | 81,377 bytes |
| Compiler | MinGW-w64 GCC 4.7.0 (from the DWARF strings) |
| Image base | `0x00400000` |
| Entry point | `0x004010f9` |
| Sections | `.text .data .rdata .bss .idata .CRT .tls` + 7 DWARF `.debug_*` sections (14 total) |

**Tools:** [Rizin](https://rizin.re) (static analysis + the cached-write trick), Python 3 (solver),
`objdump` (cross-checking).

---

## 3. Step 1 – Triage

```console
$ file debugme.exe
debugme.exe: PE32 executable (console) Intel 80386, for MS Windows, 14 sections

$ strings debugme.exe | grep -iE "naughty|bugs|flag"
Looks like your doing something naughty. Stop it!!!
I heard you like bugs so I put bugs in your debugger so you can have bugs while you debug!!!
Seriously though try and find the flag, you will find it in your debugger!!!
```

Three observations:

* **No flag in `strings`.** The program tells us outright that the flag will only exist *in the debugger*.
* The imports are the plain MinGW CRT set (`printf`, `strlen`, `Sleep`, …) – nothing exotic like
  `IsDebuggerPresent`. Whatever anti-debugging exists is done by hand.
* Near the end of the symbol table there is something unusual for a MinGW binary:

  ```
  .file   mash.asm
  _lol  _yaya  _lala  _dsfghtgf  _ertrwe  _kjnjk  _qsacb  _tftrtftc  _sup
  ```

  So `main` was **hand-written in assembly** (`mash.asm`), and those silly names are jump labels inside it.

Load it in Rizin and list the strings with their addresses:

```console
$ rizin -A debugme.exe
[0x004010f9]> iz~naughty,bugs,Seriously
```

The three messages live in `.data` at `0x409000`, `0x409035` and `0x409093`.

---

## 4. Step 2 – `main` is garbage: spotting the XOR layer

`afl~main` finds `sym._main` at `0x00401620`. Disassembling it should show a function prologue.
It doesn't:

```
[0x004010f9]> pdf @ sym._main
┌ int sym._main(int argc, char **argv, char **envp);
│   0x00401620      or    ebp, edx
│   0x00401622      mov   ecx, 0x8e6d9c6d
│   0x00401627      cmp   ch, bh
│   0x00401629      insb
│   0x0040162a      pop   esp
│   0x0040162b      pop   esp
│   0x0040162c      pop   esp
│   0x0040162d      salc
│   ...
```

Nonsense instructions (`salc`, `insb`, `aam`…), and a function that Rizin thinks is only 30 bytes long
(`afl` size column). Now look at the raw bytes:

```
[0x004010f9]> px 372 @ 0x00401620
0x00401620  09d5 b96d 9c6d 8e38 fd6c 5c5c 5cd6 1c5e  ...m.m.8.l\\\..^
0x00401630  d49e 605c 2916 b55c 5c5c 5c6d 9c6d 8e38  ..`\)..\\\\m.m.8
0x00401640  fd6c 5c5c 5cd6 1c34 d49e 605c 296e 536d  .l\\\..4..`\)nSm
...
```

**The ASCII column is full of backslashes – byte `0x5c`.** x86 code contains lots of `00` bytes
(32-bit immediates, `rel32` jump offsets, padding). `00 ^ 5c = 5c`, so a long run of `5c 5c 5c` is the
fingerprint of **"this code was XORed with a single-byte key `0x5c`"**. 

(Also notice the very first byte: `09`. The real function starts with `push ebp` = `55`, and
`0x55 ^ 0x5c = 0x09`. ✔ Key confirmed.)

---

## 5. Step 3 – Following the entry point to the decryptor stub

Something must decrypt `main` at run time, so *someone* touches those bytes before `main` is called.
Ask Rizin who references `main`:

```
[0x004010f9]> axt @ sym._main
sym.___tmainCRTStartup 0x4013e5 [CALL] call sym._main      ← the normal CRT call
entry0                 0x40896e [DATA] mov eax, sym._main  ← what is THIS doing in "entry0"?
```

The second reference is odd: a `mov eax, main` at `0x40896e`, far away from the real code, and Rizin
attributes it to `entry0`. (Another hint: `afl` reports `entry0` as a function of **30877 bytes** –
analysis has followed a jump into a different region.)

Look at the entry point itself:

```
[0x004010f9]> pd 2 @ 0x004010f9
  0x004010f9  e9 06 78 00 00    jmp   0x408904
  0x004010fe  90              nop
```

The compiler's real prologue at `0x4010f9` has been overwritten with `jmp 0x408904`. The jump lands in
**a code cave** at the very end of `.text`, in padding after the compiler's last function. Here is the
stub, reconstructed:

```asm
; ---- 0x408904: entry-point stub (anti-debug part, identical to the one in main) ----
408904  mov   eax, fs:[0x30]            ; eax = PEB
40890a  mov   al,  [eax+0x02]           ; PEB.BeingDebugged
40890d  mov   dl,  al
40890f  cmp   al,  0
408911  jne   0x408992                  ; -> debugger found: bail out
408913  jmp   0x408918
408918  xor   eax, eax
40891a  xor   edx, edx
40891c  mov   eax, fs:[0x30]
408922  mov   al,  [eax+0x68]           ; PEB.NtGlobalFlag
408925  mov   dl,  al
408927  cmp   al,  0
408929  jne   0x408992                  ; -> debugger found: bail out
40892b  rdtsc                           ; \
40892d  mov   ebx, eax                  ;  |
 ...    (10 pairs of do-nothing instructions)   ;  |  timing window
40894d  rdtsc                           ;  |
40894f  sub   eax, ebx                  ; /
408951  cmp   eax, 0x3e8               ; > 1000 cycles?
408956  jg    0x408992                  ; -> debugger found: bail out
408958  nop  x 22                       ; NOP-slide into the decryptor
; ---- 0x40896e: the decryptor ----
40896e  mov   eax, 0x401620             ; eax = &main
408973  xor   byte [eax], 0x5c           ; <---- decrypt one byte
408976  inc   eax
408977  cmp   eax, 0x401791
40897c  jle   0x408973                  ; loop while eax <= 0x401791  (INCLUSIVE!)
; ---- 0x40897e: give control back to the normal startup code ----
40897e  mov   esi, 0x414015              ; (harmless leftover)
408983  push  ebp                       ; \
408984  mov   ebp, esp                  ;  | the 3 instructions the "jmp" overwrote
408986  sub   esp, 0x18                 ; /
408989  jmp   0x4010ff                  ; resume right after the patched bytes
408992  mov   esp, ebp                  ; "debugger found" exit: a bogus epilogue
408994  pop   esp                       ;  that derails the stack and kills the process
408995  ret
```

So the program is **protected twice**: the checks run in the stub *before* `main` is even decrypted, and
the same checks run again inside `main`. This matters for the dynamic route (§8.2): hiding the debugger
only at `main` is too late.

Two details worth noting:

* The loop is `cmp eax, 0x401791 / jle`, so the last byte decrypted is **`0x401791` itself** (the final
  `ret` of `main`). The encrypted region is therefore `0x401791 − 0x401620 + 1 = 0x172 = 370` bytes.
* Stolen bytes: the `jmp` hijack is 5 bytes plus a `nop`, i.e. it overwrote exactly the original
  `push ebp / mov ebp,esp / sub esp,0x18`. The stub re-executes them and jumps back to `0x4010ff`.

---

## 6. Step 4 – Decrypting `main` inside Rizin

Rizin can apply the XOR for us **in memory only** (the file on disk is never modified) with its
write-cache:

```
[0x004010f9]> e io.cache=true       # all writes go to a cache, not the file
[0x004010f9]> s 0x00401620          # seek to main
[0x00401620]> b 370                 # block size = 0x172 bytes
[0x00401620]> wox 5c                # write-operation XOR: XOR the whole block with 0x5c
[0x00401620]> af-                   # forget the old (garbage) analysis of main
[0x00401620]> af sym._main          # re-analyse
[0x00401620]> pd 130 @ 0x00401620   # disassemble
```

Gotchas I hit (and you probably will too):

| Mistake | Symptom | Fix |
|---|---|---|
| `wox 5c 370 @ 0x401620` | wrong argument order → nothing/garbage decrypted | set the block size with `b 370`, then `wox 5c` |
| Block size **372** | two extra bytes past `0x401791` get XORed and corrupted | the region is exactly **370** bytes (see the inclusive `jle` above) |
| Running `wox` twice | XOR is its own inverse → you re-encrypt it | `wc- *` to clear the write cache, then redo once |
| `pdf` → *"Linear size differs too much from the bbsum"* | the function was analysed while still encrypted | `af-` + `af`, or just use `pd N` / `pdr` |

If you would rather have a clean file for IDA/Ghidra/Binary Ninja, run `python3 unpack.py debugme.exe`:
it XORs the 370 bytes and restores the six entry-point bytes (`55 89 e5 83 ec 18`), and the result is
a perfectly ordinary MinGW executable.

---

## 7. Step 5 – Reading the real `main`, instruction by instruction

This is the decrypted `main` (`0x401620 – 0x401791`). I split it into logical blocks.

### 7.1 Anti-debugging: three tricks

```asm
401620  push  ebp
401621  mov   ebp, esp
```
Standard prologue.

#### Trick 1 – `PEB.BeingDebugged`

```asm
401623  xor   eax, eax
401625  xor   edx, edx
401627  mov   eax, dword fs:[0x30]      ; FS:[0x30] = pointer to the PEB (32-bit Windows)
40162d  mov   al, byte [eax+0x02]       ; PEB+0x02 = BeingDebugged (1 if a debugger is attached)
401630  mov   dl, al                     ; (dead store – dl is never read)
401632  cmp   al, 0x00
401634  jnz   0x401680                  ; != 0  →  "naughty" branch
401636  jmp   0x40163b                  ; (jmp +0, just a label separator: `_G`)
```

`kernel32!IsDebuggerPresent()` is literally this check. The author inlined it to avoid an import that
anyone could hook or breakpoint.

#### Trick 2 – `PEB.NtGlobalFlag`

```asm
40163b  xor   eax, eax
40163d  xor   edx, edx
40163f  mov   eax, dword fs:[0x30]
401645  mov   al, byte [eax+0x68]       ; PEB+0x68 = NtGlobalFlag
401648  mov   dl, al
40164a  cmp   al, 0x00
40164c  jnz   0x401680
```

When a process is **created by a debugger** (not merely attached later), Windows sets three heap-debug
bits in `NtGlobalFlag`: `FLG_HEAP_ENABLE_TAIL_CHECK (0x10) | FLG_HEAP_ENABLE_FREE_CHECK (0x20) |
FLG_HEAP_VALIDATE_PARAMETERS (0x40) = 0x70`. A clean run has `0`. This catches debuggers that clear
`BeingDebugged` but forget about this field – a classic.

#### Trick 3 – `rdtsc` timing

```asm
40164e  rdtsc                           ; edx:eax = CPU time-stamp counter
401650  mov   ebx, eax                  ; remember the "before" value
401652  push ecx    / 401653 pop ecx    ; ┐
401654  add  edi,edi / 401656 sub edi,edi  ; │  ten pairs of instructions that cancel
401658  push esi    / 401659 pop esi    ; │  each other out (net effect: nothing)
40165a  add  ecx,ecx / 40165c sub ecx,ecx  ; │  20 instructions in total – a tiny,
...                                     ; │  fixed amount of work
40166e  push esi    / 40166f pop esi    ; ┘
401670  rdtsc                           ; "after"
401672  sub   eax, ebx                  ; elapsed ticks
401674  cmp   eax, 0x3e8                ; 1000
401679  jnle  0x401680                  ; > 1000 ticks  →  "naughty" branch
40167b  jmp   0x401694                  ; otherwise: the clean path
```

Twenty trivial instructions take a few dozen cycles on a real CPU. If you are **single-stepping** them in
a debugger, every step costs an exception round-trip (thousands of cycles), so the difference blows past 1000.
(Side effect worth knowing: under some hypervisors `rdtsc` itself traps and is slow, so this check can
fire in a VM even without a debugger.)

> Note: a software breakpoint *between* the two `rdtsc` also trips it. Put breakpoints before the first
> or after the second.

#### The two exits

```asm
; "debugger detected"
401680  push  0x409000                  ; "Looks like your doing something naughty. Stop it!!!\n"
401685  call  0x4085ec                  ; printf
40168a  add   esp, 4
401690  mov   esp, ebp
401692  pop   ebp
401693  ret                             ; return from main without ever touching the flag

; "clean"
401694  push  0x409035                  ; "I heard you like bugs so I put bugs in your debugger…"
401699  call  0x4085ec                  ; printf
40169e  add   esp, 4
4016a4  push  0x409093                  ; "Seriously though try and find the flag, you will find it in your debugger!!!"
4016a9  call  0x4085ec                  ; printf
4016ae  add   esp, 4
```

Run it normally and you get two taunting lines and an exit. The interesting part is what comes next.

### 7.2 Building the flag on the stack

After the taunts, `main` executes **nine `push eax`** instructions. Each pushes the dword
`0x6a253e2d ± constant`. Between the pushes you will see junk, so let me show the raw code, then
strip it:

```asm
4016b4  xor   eax, eax
4016b6  mov   eax, 0x6a253e2d           ; K
4016bb  push  eax                       ; push 1   = K
4016bc  jmp   0x4016c1                  ; (jmp +0)
4016c1  sub   eax, 0x560c29fc           ; NOTE: eax still holds K here – no re-load
4016c6  push  eax                       ; push 2   = K - 0x560c29fc
4016c7  jmp   0x4016cc
4016cc  and   eax, 0x41414141           ; ┐ junk: 0x41 & 0x3e == 0 for every byte,
4016d1  and   eax, 0x3e3e3e3e           ; ┘ so eax becomes 0 (and is overwritten next line anyway)
4016d6  mov   eax, 0x6a253e2d           ; K again
4016db  sub   eax, 0x49fd1bf4
4016e0  push  eax                       ; push 3   = K - 0x49fd1bf4
4016e1  jmp   0x4016e6
4016e6  xor   eax, eax                  ; junk
4016e8  mov   eax, 0x6a253e2d
4016ed  sub   eax, 0x2b1124ff
4016f2  push  eax                       ; push 4   = K - 0x2b1124ff
4016f3  jmp   0x4016f8
4016f8  and   eax, 0x41414141           ; junk
4016fd  and   eax, 0x3e3e3e3e           ; junk
401702  mov   eax, 0x6a253e2d
401707  sub   eax, 0x5e190004
40170c  push  eax                       ; push 5   = K - 0x5e190004
40170d  jmp   0x401712
401712  and   eax, 0x41414141           ; junk
401717  and   eax, 0x3e3e3e3e           ; junk
40171c  mov   eax, 0x6a253e2d
401721  add   eax, 0x0de9d64d           ; <-- the only ADD in the whole sequence
401726  push  eax                       ; push 6   = K + 0x0de9d64d
401727  jmp   0x40172c
40172c  xor   eax, eax                  ; junk
40172e  mov   eax, 0x6a253e2d
401733  sub   eax, 0x2b003419
401738  push  eax                       ; push 7   = K - 0x2b003419
401739  jmp   0x40173e
40173e  and   eax, 0x41414141           ; junk
401743  and   eax, 0x3e3e3e3e           ; junk
401748  mov   eax, 0x6a253e2d
40174d  sub   eax, 0x3e001c06
401752  push  eax                       ; push 8   = K - 0x3e001c06
401753  jmp   0x401758
401758  and   eax, 0x41414141           ; junk
40175d  and   eax, 0x3e3e3e3e           ; junk
401762  mov   eax, 0x6a253e2d
401767  sub   eax, 0x42aa050e
40176c  push  eax                       ; push 9   = K - 0x42aa050e
40176d  jmp   0x401772
```

What the obfuscation does and does not do:

* **Every `jmp` is `jmp +0`** (`e9 00 00 00 00`, a jump to the very next instruction). They split the
  code into tiny basic blocks (the labels `_lol`, `_yaya`, … ), which makes graph views look busy and
  stops simple linear pattern-matching, but adds no real control flow.
* **The `and … and …` and `xor eax,eax` lines are dead code.** `0x41414141 & 0x3e3e3e3e = 0`, so they
  just zero `eax`, which is reloaded immediately afterwards.
* **Dword constants are stored as `K ± c`, never directly**, so the encrypted flag does not appear in the
  file as one recognisable blob. The only subtle spot is *push 2*, which has no `mov eax, K` of its own:
  it relies on `eax` still being `K` from push 1.

Evaluating the nine values (all arithmetic mod 2³²):

| # | Expression | Dword (hex) | Little-endian bytes | `^ 0x4b` → ASCII |
|--:|---|---|---|---|
| 1 | `K` | `0x6a253e2d` | `2d 3e 25 6a` | `fun!` |
| 2 | `K − 0x560c29fc` | `0x14191431` | `31 14 19 14` | `z_R_` |
| 3 | `K − 0x49fd1bf4` | `0x20282239` | `39 22 28 20` | `rick` |
| 4 | `K − 0x2b1124ff` | `0x3f14192e` | `2e 19 14 3f` | `eR_t` |
| 5 | `K − 0x5e190004` | `0x0c0c3e29` | `29 3e 0c 0c` | `buGG` |
| 6 | `K + 0x0de9d64d` | `0x780f147a` | `7a 14 0f 78` | `1_D3` |
| 7 | `K − 0x2b003419` | `0x3f250a14` | `14 0a 25 3f` | `_Ant` |
| 8 | `K − 0x3e001c06` | `0x2c252227` | `27 22 25 2c` | `ling` |
| 9 | `K − 0x42aa050e` | `0x277b391f` | `1f 39 7b 27` | `Tr0l` |

Worked example for push 1: `2d 3e 25 6a` XOR `4b` per byte = `66 75 6e 21` = `"fun!"`.

**The stack grows downward**, so the last value pushed sits at the lowest address. In memory, from
`ESP` upward, the nine dwords are in *reverse* push order:

```
low address ──────────────────────────────────────────────────────► high address
 +0    +4    +8    +12   +16   +20   +24   +28   +32
┌─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┬─────┐
│push9│push8│push7│push6│push5│push4│push3│push2│push1│   (each dword little-endian)
│Tr0l │ling │_Ant │1_D3 │buGG │eR_t │rick │z_R_ │fun! │   (after XOR 0x4b)
└─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┴─────┘
```

That is why the flag *reads* correctly from low to high address even though `fun!` was pushed first.

### 7.3 The decode loop

```asm
401772  push  esp
401773  pop   esi                       ; esi = esp  (→ points at push 9's dword = flag[0])
401774  xor   edx, edx                  ; junk
401776  mov   edi, esi                  ; edi = esi  (decode in place)
401778  mov   edx, edi                  ; junk
40177a  cld                             ; direction flag = 0 → string ops go forward
40177b  mov   ecx, 0x24                 ; 36 = 9 dwords × 4 bytes
401780  mov   ebx, 0x4b                 ; 'K' – the XOR key
401785  xor   eax, eax
401787  push  eax                       ; esp -= 4  (see the note below)
401788  lodsb                           ; al = [esi++]
401789  xor   eax, ebx                  ; al ^= 0x4b   (upper bits of eax are 0)
40178b  stosb                           ; [edi++] = al
40178c  loop  0x401788                  ; ecx--, repeat until ecx == 0
40178e  mov   esp, ebp                  ; epilogue – the stack is thrown away
401790  pop   ebp
401791  ret
```

In C:

```c
for (int i = 0; i < 36; i++)
    flag[i] ^= 0x4b;          // flag == (char*)(old_esp), decoded in place
```

> **Subtle detail for the debugger route:** `esi` is captured *before* the `push eax` at `0x401787`.
> That push moves `ESP` down by four, so **the decoded flag starts at `ESP+4`** at the breakpoint, not at
> `ESP`. After the loop finishes, `ESI` and `EDI` both point one past the end, so the flag is also at
> `[EDI − 0x24]`. The code never writes a NUL terminator, so dump exactly 36 bytes.

And that is the end of the program. After `loop`, the plaintext flag is sitting in stack memory for
exactly one instruction – then `mov esp, ebp` abandons it. **Nothing ever prints it.** The challenge
literally means "you must be in the debugger at the right moment", just as the string says.

---

## 8. Step 6 – Getting the flag

### 8.1 Static: no debugger needed

Because the whole thing is straight-line arithmetic on constants, we can compute the flag offline
and every anti-debug check becomes irrelevant. `solve.py` does it by:

1. parsing the PE header and mapping VA → file offset,
2. undoing the `0x5c` XOR on `0x401620–0x401791`,
3. running a tiny emulator over `0x4016b4–0x401772` that understands only the opcodes the author used
   (`mov/sub/add/and eax,imm32`, `xor eax,eax`, `push eax`, `jmp rel32`) and recording every `push eax`,
4. laying the pushes out in stack order and XORing with the key read from the `mov ebx, 0x4b` instruction.

```console
$ python3 solve.py debugme.exe
[+] decoded loop: 36 bytes, XOR key 0x4b
    push 1: 0x6a253e2d
    push 2: 0x14191431
    push 3: 0x20282239
    push 4: 0x3f14192e
    push 5: 0x0c0c3e29
    push 6: 0x780f147a
    push 7: 0x3f250a14
    push 8: 0x2c252227
    push 9: 0x277b391f
[+] flag body : Tr0lling_Ant1_D3buGGeR_trickz_R_fun!
[+] flag      : HTB{Tr0lling_Ant1_D3buGGeR_trickz_R_fun!}
```

The core of the solver is just this (the full script derives every constant from the binary):

```python
import struct

K = 0x6a253e2d
pushes = [K,
          (K - 0x560c29fc) & 0xffffffff, (K - 0x49fd1bf4) & 0xffffffff,
          (K - 0x2b1124ff) & 0xffffffff, (K - 0x5e190004) & 0xffffffff,
          (K + 0x0de9d64d) & 0xffffffff,                       # the only ADD
          (K - 0x2b003419) & 0xffffffff, (K - 0x3e001c06) & 0xffffffff,
          (K - 0x42aa050e) & 0xffffffff]

stack = b"".join(struct.pack("<I", v) for v in reversed(pushes))   # stack grows down
print("".join(chr(b ^ 0x4b) for b in stack))                       # lodsb / xor / stosb
```

There is also `debugme_model.c`, the same logic in portable C, if you prefer to verify it that way.

### 8.2 Dynamic: the intended way

1. **Load in a 32-bit debugger** (x32dbg, OllyDbg). The process is created by the debugger, so
   `BeingDebugged = 1` and `NtGlobalFlag = 0x70`.
2. **Defeat the three checks – at the entry stub, not just in `main`** (they run at `0x408904`, before
   `main` is even decrypted):
   * easiest: enable **ScyllaHide** (or the debugger's built-in "hide debugger"), which zeroes
     `BeingDebugged` / `NtGlobalFlag` and virtualises `rdtsc`; or
   * by hand: set `PEB+0x02 = 0` and `PEB+0x68 = 0` in the dump window (PEB address = `fs:[0x30]`), and
     never single-step or put a breakpoint between the two `rdtsc`.
3. **Set a breakpoint at `0x0040178e`** (the `mov esp, ebp` right after the `loop`) and run (F9).
4. At the breakpoint, **dump 36 bytes at `ESP+4`** (or `EDI−0x24`):

   ```
   Tr0lling_Ant1_D3buGGeR_trickz_R_fun!
   ```

Alternative: after unpacking (`unpack.py`), patch the three conditional jumps
(`0x401634`, `0x40164c`, `0x401679`) to `nop`/`jmp` and the stub equivalents, and debug as usual.

> The static route was verified directly against the binary. The debugger steps above follow from the
> disassembly; if you reproduce them, a screenshot of the stack at `0x40178e` makes a nice addition here.

---

## 9. How the author built it (reconstructed source)

The original source was never published, so `debugme_reconstructed.c` is **reconstructed from the binary**:

* the symbol table contains `.file mash.asm` and the jump labels, so `main` was a standalone assembly
  file. `mash.asm` (NASM) is the closest reconstruction; it writes `jmp near` and `dword` explicitly
  because the original uses those long encodings (`e9 00 00 00 00`, `81 c4 04 00 00 00`).
  Build: `nasm -f win32 mash.asm -o mash.obj && i686-w64-mingw32-gcc mash.obj -o debugme_rebuilt.exe`.
  `debugme_reconstructed.c` is the same code as a global `__asm__` block, for people without NASM;
* the three message strings, every constant, every junk instruction and the label names
  (`_G`, `_d`, `_n`, `_lol`, `_yaya`, `_lala`, `_dsfghtgf`, `_ertrwe`, `_kjnjk`, `_qsacb`, `_tftrtftc`,
  `_sup`, `_l`, as found in the COFF symbol table) are taken from the unpacked binary;
* the **XOR-0x5c packing and the entry-point hijack are not part of the source** – they are
  post-build binary patching (that is why `mash.asm` and the stub live in separate places and why the
  stub sits in padding). `unpack.py` is the inverse of that step.

The reconstruction assembles cleanly with `gcc -m32 -c` and the instruction stream matches the original
(it differs only where `gas` chooses short jumps / imm8 encodings and the original used `jmp rel32` /
imm32 forms).

How the author most likely **generated the constants** – pick `K`, then derive the rest:

```python
import struct
flag = b"Tr0lling_Ant1_D3buGGeR_trickz_R_fun!"          # 36 bytes = 9 dwords
chunks = [flag[i:i+4] for i in range(0, 36, 4)]         # "Tr0l","ling",...,"fun!"
dwords = [struct.unpack("<I", bytes(b ^ 0x4b for b in c))[0] for c in reversed(chunks)]
K = dwords[0]                                           # 0x6a253e2d  ("fun!" ^ 4b)
for i, d in enumerate(dwords[1:], 2):
    print(f"push {i}: sub K, {(K - d) & 0xffffffff:#010x}   (or add K, {(d - K) & 0xffffffff:#010x})")
```

---

## 10. Summary of the protection layers

| Layer | Mechanism | How we beat it |
|---|---|---|
| 1. Packed `main` | `0x401620–0x401791` XORed with `0x5c` on disk | Spot the `5c 5c 5c` runs; `wox 5c` with block size 370 (or `unpack.py`) |
| 2. Entry-point hijack | `jmp 0x408904` into a code cave in `.text` padding | `axt @ sym._main` → odd DATA xref from `entry0` |
| 3. Debugger checks | `PEB.BeingDebugged`, `PEB.NtGlobalFlag`, `rdtsc` delta (>1000) – in the stub **and** in `main` | Don't run it (static), or hide the debugger from the very first instruction |
| 4. Control-flow noise | A dozen `jmp +0`, dead `and/xor` instructions, cancelling `push/pop` and `add/sub` pairs | Recognise them as no-ops |
| 5. Hidden constants | Flag stored as `K ± c` dwords, assembled on the stack | Evaluate the arithmetic |
| 6. Ephemeral flag | Decoded in place, never printed, stack abandoned | Break right after the `loop` (`0x40178e`) or compute it offline |

---

## 11. Lessons learned

* **A wall of the same byte in a hex dump is a key.** Runs of `5c` where zeros should be are the
  signature of single-byte XOR; the first byte (`55 ^ 5c = 09`) confirms it.
* **"Who references this function?" (`axt`) is the quickest way to find a hidden decryptor** – an
  unexpected reference from the entry point is a red flag.
* **Check the loop bounds in the decryptor.** `jle` against `0x401791` means *inclusive*; getting the
  length wrong by two bytes (372 instead of 370) silently corrupts the tail.
* **Anti-debugging in the stub means "hide before `main`".** The same three checks guard both stages.
* **When the flag is computed, you don't need to run the program.** Reading the arithmetic is often
  faster and more reliable than fighting the anti-debug tricks.

---

* **Shoutout to mprox, who drew first blood on this challenge 8 years ago. Truly an absolute legend and a top-tier professional.
