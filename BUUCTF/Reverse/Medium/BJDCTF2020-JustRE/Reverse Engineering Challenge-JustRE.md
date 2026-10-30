# Reverse Engineering Challenge: "JustRE" Writeup

> **Category:** Reverse Engineering (Windows PE32, GUI)
> **Tools:** Rizin (`rizin`, `rz-ghidra`), AutoHotkey (optional)
> **Difficulty:** Medium 
> **Author:**Gantosay

---

## Table of contents

1. [Overview](#1-overview)
2. [Step 1: Strings (`iz`)](#2-step-1-strings-iz)
3. [Step 2: Function analysis (`aa`, `afl`)](#3-step-2-function-analysis-aa-afl)
4. [Step 3: Following the xrefs](#4-step-3-following-the-xrefs)
5. [Step 4: A red herring, the CRT `_output` function](#5-step-4-a-red-herring-the-crt-_output-function)
6. [Step 5: The real logic, the DialogProc at `0x401350`](#6-step-5-the-real-logic-the-dialogproc-at-0x401350)
7. [Step 6: Computing the flag](#7-step-6-computing-the-flag)
8. [Solution A: Click 19999 times (AutoHotkey)](#8-solution-a-click-19999-times-autohotkey)
9. [Solution B: Patching the binary](#9-solution-b-patching-the-binary)
10. [C reconstruction of the challenge](#10-c-reconstruction-of-the-challenge)
11. [Lessons learned](#11-lessons-learned)

---

## 1. Overview

The challenge is a small Windows GUI program (`re.exe`), compiled with an old
Visual C++ toolchain (VC6-era CRT). It shows a dialog with a button and a
Chinese-language menu. Nothing obviously prints a flag, so we need to find
out *when* the program builds one.

## 2. Step 1: Strings (`iz`)

Open the binary in Rizin and list the data-section strings:

```
$ rizin re.exe
[0x00401462]> iz
```

Interesting results:

```
paddr      vaddr      len size section type    string
0x00005c30 0x00407030  26   27 .data   ascii    BJD{%d%d2069a45792d233ac}
0x00005c56 0x00407056   4    4 .data   ascii    %d
0x00009d66 0x0040c766   7   16 .rsrc   utf16le getflag
0x00009eb2 0x0040c8b2   8   18 .rsrc   utf16le click it
0x00009ef6 0x0040c8f6   4   10 .rsrc   utf16le flag
0x00009f20 0x0040c920  21   44 .rsrc   utf16le Flag will not be here
0x00009e12 0x0040c812   5   12 .rsrc   utf16le BJD万岁
```

Observations:

- `BJD{%d%d2069a45792d233ac}` is a **format string**, not a finished flag.
  The two `%d` placeholders must be filled with numbers at runtime.
- `click it` and `getflag` are resources: a dialog with a button.
- `Flag will not be here` is a joke / distraction. The flag is not stored in
  the resources.
- The imports include `CreateWindowExA`, `DialogBoxParamA`, `SetWindowTextA`,
  `EndDialog`, so this is a standard Win32 dialog application.
  There are no anti-debug imports (`IsDebuggerPresent` etc.).

## 3. Step 2: Function analysis (`aa`, `afl`)

```
[0x00401462]> aa
[x] Analyze all flags starting with sym. and entry0 (aa)
[0x00401462]> afl
0x00401000    9 185          fcn.00401000
0x004010c0    1 137          fcn.004010c0
0x00401150    3 97           fcn.00401150
0x00401410    4 82           fcn.00401410
0x00401462   18 5891 -> 424  entry0
...
0x004016b6  193 1918         fcn.004016b6
...
```

Two things stand out:

- `fcn.004016b6` is the biggest non-startup function (1918 bytes, 193 basic
  blocks). It is tempting to start there.
- There is a **gap** between `fcn.00401150` and `fcn.00401410` where Rizin
  did not recognise any function. The program's own code is probably there.

## 4. Step 3: Following the xrefs

```
[0x00401462]> axt @ 0x00407030
(nofunc) 0x4013aa [DATA] push str.BJD__d_d2069a45792d233ac
```

The format string is referenced from `0x4013aa`, in code that Rizin has not
assigned to any function (`nofunc`). That is exactly the gap noticed earlier.

Searching for the raw address bytes (little-endian) is an alternative that
does not depend on analysis. In Rizin, `/c` is *crypto* search, not
"search code", so use `/x`:

```
[0x00407030]> /x 30704000
0x004013ab 4 hit.bytes.0.
```

`30704000` is `0x00407030` in little-endian byte order. The hit at
`0x4013ab` is the 4-byte operand of the `push` at `0x4013aa`.

## 5. Step 4: A red herring, the CRT `_output` function

Before finding the real code, the biggest function was decompiled:

```
[0x00407030]> pdf @ fcn.004016b6
[0x00407030]> pdg @ fcn.004016b6      # rz-ghidra decompiler
```

The decompilation shows a `switch` with **8 cases** that parses `%` format
specifiers: flags (`' '`, `#`, `+`, `-`, `0`), width and precision with `*`,
size prefixes (`h`, `l`, `w`, `I64`), and the conversion characters
(`d i u o x X c C s S e E g G n p Z`). It also calls floating-point helpers
through function pointers and uses a 64-bit divide/modulo helper for number
formatting.

This is Microsoft's CRT **`_output`**, the core of `printf`/`sprintf`.
It is library code, not challenge code. **No logic of the challenge lives
here**, so there is no reason to read it line by line.

> Tip: if a big function contains a state machine over `%`, flags, width,
> precision and size modifiers, it is almost certainly the C runtime's
> `printf` engine. Move on.

`fcn.00401410` (82 bytes), which is called right before and after the flag
code, is the small `sprintf` wrapper that sets up a fake `FILE` and calls
`_output`.

## 6. Step 5: The real logic, the DialogProc at `0x401350`

Disassemble around the xref:

```
[0x00407030]> s 0x00401350
[0x00401350]> pd 60
```

Rizin can be forced to create a function for the unanalysed area:

```
[0x004013aa]> af @ 0x00401200
[0x004013aa]> pd -40       # instructions before the xref
[0x004013aa]> pd 30        # instructions after
[0x004013aa]> pd 80 @ 0x00401340
```

The complete routine (the dialog procedure) looks like this:

```asm
; DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
; 0x401350 (called by the dialog manager, address stored as a DATA xref)

0x00401350      mov   eax, dword [esp+0x08]         ; eax = msg
0x00401354      sub   esp, 0x64                     ; char buf[100]
0x00401357      sub   eax, 0x110                    ; msg - WM_INITDIALOG
0x0040135c      jz    0x4013f9                      ; WM_INITDIALOG -> return TRUE
0x00401362      dec   eax                           ; msg - WM_COMMAND (0x111)
0x00401363      jnz   0x4013e0                      ; other message -> return FALSE
0x00401365      mov   eax, dword [esp+0x70]         ; eax = wParam
0x00401369      cmp   ax, 0x01                      ; LOWORD(wParam) == IDOK ?
0x0040136d      jz    0x4013e8
0x0040136f      cmp   ax, 0x02                      ; LOWORD(wParam) == IDCANCEL ?
0x00401373      jz    0x4013e8

; ---- any other control (the button) ----
0x00401375      mov   eax, dword [0x4099f0]         ; global counter
0x0040137a      inc   eax                           ; counter++
0x0040137b      mov   dword [0x4099f0], eax
0x00401380      push  eax                           ; arg: counter
0x00401381      lea   eax, dword [esp+0x04]         ; buf
0x00401385      push  0x40704c                      ; fmt = "%d "
0x0040138a      push  eax                           ; buf
0x0040138b      call  fcn.00401410                  ; sprintf(buf, "%d ", counter)
0x00401390      mov   eax, dword [0x4099f0]
0x00401395      add   esp, 0x0c
0x00401398      cmp   eax, 0x4e1f                   ; counter == 19999 ?
0x0040139d      jnz   0x4013d0                      ; no -> just show the counter

; ---- counter == 0x4e1f: build the flag ----
0x0040139f      push  0x00                          ; 3rd vararg -> second %d
0x004013a1      push  0x4e1f                        ; 2nd vararg -> first  %d
0x004013a6      lea   ecx, dword [esp+0x08]         ; buf
0x004013aa      push  str.BJD__d_d2069a45792d233ac  ; fmt (0x407030)
0x004013af      push  ecx                           ; buf
0x004013b0      call  fcn.00401410                  ; sprintf(buf, fmt, 0x4e1f, 0)
0x004013b5      mov   eax, dword [esp+0x78]         ; hDlg
0x004013b9      add   esp, 0x10
0x004013bc      lea   edx, dword [esp]              ; buf
0x004013c0      push  edx
0x004013c1      push  eax
0x004013c2      call  dword [SetWindowTextA]        ; SetWindowTextA(hDlg, buf)
0x004013c8      xor   eax, eax
0x004013ca      add   esp, 0x64
0x004013cd      ret   0x10

; ---- normal path: display the counter ----
0x004013d0      mov   edx, dword [esp+0x68]         ; hDlg
0x004013d4      lea   ecx, dword [esp]              ; buf
0x004013d8      push  ecx
0x004013d9      push  edx
0x004013da      call  dword [SetWindowTextA]        ; SetWindowTextA(hDlg, buf)
0x004013e0      xor   eax, eax                      ; return FALSE
0x004013e2      add   esp, 0x64
0x004013e5      ret   0x10

; ---- IDOK / IDCANCEL ----
0x004013e8      and   eax, 0xffff
0x004013ed      push  eax
0x004013ee      mov   eax, dword [esp+0x6c]         ; hDlg
0x004013f2      push  eax
0x004013f3      call  dword [EndDialog]             ; EndDialog(hDlg, LOWORD(wParam))
0x004013f9      mov   eax, 0x01                     ; return TRUE
0x004013fe      add   esp, 0x64
0x00401401      ret   0x10
```

### What it does

| Address / value      | Meaning                                                    |
|----------------------|------------------------------------------------------------|
| `0x4099f0`           | global click counter, initially `0`                        |
| `0x40704c`           | format string `"%d "`                                      |
| `0x407030`           | flag format string `" BJD{%d%d2069a45792d233ac}"`          |
| `0x110` / `0x111`    | `WM_INITDIALOG` / `WM_COMMAND`                             |
| `0x4e1f`             | the magic click count                                      |
| `SetWindowTextA(hDlg, ...)` | output goes to the **dialog's title bar**           |

Flow:

1. Every click on the button (a `WM_COMMAND` that is not ID 1 or 2) increments
   the counter and shows it in the title bar with `sprintf(buf, "%d ", counter)`.
2. When the counter equals `0x4e1f`, it instead runs
   `sprintf(buf, "BJD{%d%d2069a45792d233ac}", 0x4e1f, 0)` and shows *that* in
   the title bar.

### Reading the argument order (cdecl)

Arguments are pushed right-to-left, so the **last push is the first argument**:

```
push 0x00                ; vararg #2  -> second %d
push 0x4e1f              ; vararg #1  -> first  %d
push fmt                 ; format
push buf                 ; destination
call sprintf
```

So the first `%d` is `0x4e1f` and the second `%d` is `0`.

## 7. Step 6: Computing the flag

```
0x4e1f = 4*4096 + 14*256 + 1*16 + 15
       = 16384 + 3584 + 16 + 15
       = 19999
```

You can also let Rizin do it:

```
[0x00401350]> ? 0x4e1f
int32   19999
```

Substituting into `BJD{%d%d2069a45792d233ac}`:

```
%d (first)  -> 19999
%d (second) -> 0
BJD{ 19999 0 2069a45792d233ac }
```


(The string in the binary starts with a space; that is not part of the
flag.)

The designer hid the two numbers behind a counter so that `strings` only
shows an incomplete flag, and a "click it" button must be clicked 19999 times
(or the program must be patched) to see it.

---

## 8. Solution A: Click 19999 times (AutoHotkey)

The menu is in Chinese, but this is not a problem. The script identifies the
button by class name (`ClassNN`), not by its text.

1. Run `re.exe`.
2. Open **Window Spy** (AutoHotkey tray icon -> Window Spy) and hover over the
   button to get its `ClassNN` (usually `Button1`).
3. Run the script:

**AutoHotkey v2**

```autohotkey
#Requires AutoHotkey v2.0
SetControlDelay -1

exe := "re.exe"
btn := "Button1"          ; ClassNN from Window Spy

if !WinExist("ahk_exe " exe) {
    MsgBox "Start the program first"
    ExitApp
}

Loop 19999 {
    ControlClick btn, "ahk_exe " exe,,,, "NA"
}

Sleep 200
MsgBox WinGetTitle("ahk_exe " exe)     ; the flag is in the title bar
```

**AutoHotkey v1**

```autohotkey
SetControlDelay, -1
Loop, 19999
    ControlClick, Button1, ahk_exe re.exe,,,, NA
Sleep, 200
WinGetTitle, t, ahk_exe re.exe
MsgBox, %t%
```

If `ControlClick` is ignored, send `BM_CLICK` (`0xF5`) directly:

```autohotkey
hwnd := ControlGetHwnd("Button1", "ahk_exe re.exe")
Loop 19999
    SendMessage 0xF5, 0, 0, hwnd
```

The `NA` option sends the click without moving the mouse or activating the
window.

---

## 9. Solution B: Patching the binary

Instead of clicking 19999 times, change the comparison so that the first click
triggers the flag.

### The instruction

```
0x00401398      cmp   eax, 0x4e1f
```

Encoded as `3D 1F 4E 00 00` (opcode `3D` = `cmp eax, imm32`, followed by a
4-byte little-endian immediate). The immediate starts at `0x401399`.

### Why not use `wa`?

```
[0x00401398]> wa cmp eax, 1
ERROR: Cannot assemble 'eax,' at line 8
```

Rizin's `wa` parses its argument differently here, and even when it works,
`cmp eax, 1` assembles to the **3-byte** form `83 F8 01`, while the original
instruction is **5 bytes**. A length mismatch would corrupt the following
instruction (it would need NOP padding).

The safest approach is to keep the 5-byte `cmp eax, imm32` and only overwrite
the immediate value.

### Patch procedure

Open the file in write mode:

```
$ rizin -w re.exe
[0x00401462]> s 0x401399
[0x00401399]> wx 01000000          ; new immediate = 1 (little-endian)
```

Verify:

```
[0x00401399]> pd 1 @ 0x401398
            0x00401398      cmp   eax, 0x01                            ; 1
```

Quit (changes are already written, since the file was opened with `-w`):

```
[0x00401399]> q
```

Run the patched `re.exe`, click the button **once**, and the flag appears in
the title bar.

### Important: do not touch `push 0x4e1f`

```
0x004013a1      push  0x4e1f
```

This instruction supplies the value for the first `%d`, so it must stay
`0x4e1f` (19999). Only the **comparison** is patched. If `push 0x4e1f` were
also changed, the printed flag would be wrong.

> Tip: always work on a **copy** of the original binary when patching.

### Alternative: patch the counter's initial value

You could also set the counter at `0x4099f0` to `19998`, so one click reaches
`19999`. This only works if that address is backed by file data. If it lives
in `.bss` (zero-initialised, not stored in the file), the file cannot be
patched there, and the comparison patch above is the way to go.

---

## 10. C reconstruction of the challenge

Rebuilt from the disassembly above.

### `main.c`

```c
#include <windows.h>
#include <stdio.h>

#define IDC_CLICK 1001

static int g_counter = 0;   /* 0x4099f0 */

INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    char buf[100];          /* sub esp, 0x64 */

    switch (msg) {
    case WM_INITDIALOG:     /* 0x110 */
        return TRUE;

    case WM_COMMAND: {      /* 0x111 */
        WORD id = LOWORD(wParam);

        if (id == IDOK || id == IDCANCEL) {      /* 1 and 2 */
            EndDialog(hDlg, id);
            return TRUE;
        }

        g_counter++;
        sprintf(buf, "%d ", g_counter);          /* fmt at 0x40704c */

        if (g_counter == 19999) {                /* 0x4e1f */
            sprintf(buf, "BJD{%d%d2069a45792d233ac}", 19999, 0);
        }
        SetWindowTextA(hDlg, buf);               /* output in the title bar */
        return TRUE;
    }
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    DialogBoxParamA(hInst, MAKEINTRESOURCEA(100), NULL, DlgProc, 0);
    return 0;
}
```

### `re.rc`

```rc
#include <windows.h>

100 DIALOGEX 0, 0, 160, 70
STYLE DS_MODALFRAME | WS_POPUP | WS_CAPTION | WS_SYSMENU
CAPTION "getflag"
FONT 9, "MS Shell Dlg"
BEGIN
    PUSHBUTTON "click it", 1001, 50, 25, 60, 20
END
```

### Build

MinGW:

```
windres re.rc -o re.o
gcc main.c re.o -mwindows -o re.exe
```

MSVC (Developer Command Prompt):

```
rc re.rc
cl main.c re.res user32.lib
```

> This is a functional reconstruction. The original also contains a menu
> (`&Help`, `h&About ...`), an accelerator table and a normal `WndProc`
> window, none of which matter for the challenge logic.

---

## 11. Lessons learned

- **Start from the flag-related string**, then follow xrefs. Do not start from
  the biggest function; it was the CRT `printf` engine.
- **`nofunc` xrefs** mean the analyser missed some code. Use `af @ addr` or
  disassemble manually with `pd`.
- **A format string with `%d` placeholders is an incomplete flag.** Find the
  `sprintf` call and read its arguments.
- **cdecl pushes arguments right to left**: the last `push` before the format
  string (and buffer) is the first vararg.
- **Check instruction length before patching.** `cmp eax, imm32` is 5 bytes;
  patch only the immediate with `wx` instead of re-assembling.
- Static analysis showed the answer; running the program is the final check.
  Compare the flag from the title bar with
  `F14g{XXXXXXXXXXXXXXXXXX}`.

### Rizin commands used

| Command                  | Purpose                                       |
|--------------------------|-----------------------------------------------|
| `iz`                     | list strings in data sections                 |
| `aa`                     | basic analysis                                |
| `afl`                    | list recognised functions                     |
| `axt @ <addr>`           | cross-references to an address                |
| `/x <hexbytes>`          | search for raw bytes                          |
| `s <addr>`               | seek                                          |
| `pd N` / `pd -N`         | disassemble N instructions forward / backward |
| `pdf @ <fcn>`            | disassemble a whole function                  |
| `pdg @ <fcn>`            | decompile (rz-ghidra)                         |
| `af @ <addr>`            | define a function at an address               |
| `? <expr>`               | calculator (hex to decimal)                   |
| `rizin -w file`          | open in write mode                            |
| `wx <hex>`               | write raw bytes                               |

---
