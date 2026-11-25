; ---------------------------------------------------------------------------
; mash.asm - RECONSTRUCTED source of the HTB "debugme" challenge (NASM syntax)
;
; The author never published the source.  This file is rebuilt from the
; unpacked binary:
;   * the COFF symbol table has `.file mash.asm`, so this is the file name,
;   * label names (_G _d _n _lol _yaya _lala _dsfghtgf _ertrwe _kjnjk _qsacb
;     _tftrtftc _sup _l) come from that symbol table,
;   * constants, strings and instruction order are taken from the binary,
;   * `jmp near` and `dword` are written out explicitly because the original
;     uses the long encodings (e9 00 00 00 00 / 81 c4 04 00 00 00), which is
;     what NASM emits for them.
;
; Build (needs nasm + a 32-bit MinGW-w64 gcc to supply the CRT):
;     nasm -f win32 mash.asm -o mash.obj
;     i686-w64-mingw32-gcc mash.obj -o debugme_rebuilt.exe
;
; NOT part of this file: the XOR(0x5c) packing of _main and the entry-point
; hijack.  They were applied to the finished .exe afterwards; unpack.py in
; this repo reverses them.
; ---------------------------------------------------------------------------

bits 32

global _main
extern _printf

section .data
_str_naughty: db "Looks like your doing something naughty. Stop it!!!", 10, 0
_str_bugs:    db "I heard you like bugs so I put bugs in your debugger so you can have bugs while you debug!!!", 10, 0
_str_hint:    db "Seriously though try and find the flag, you will find it in your debugger!!!", 10, 0

section .text

_main:
    push    ebp
    mov     ebp, esp

    ; ---- anti-debug 1: PEB.BeingDebugged ---------------------------------
    xor     eax, eax
    xor     edx, edx
    mov     eax, [fs:0x30]          ; PEB
    mov     al, [eax + 0x02]        ; BeingDebugged
    mov     dl, al
    cmp     al, 0
    jne     _d
    jmp     near _G                 ; jmp +0  (e9 00 00 00 00)

_G:
    ; ---- anti-debug 2: PEB.NtGlobalFlag (0x70 under a debugger) ----------
    xor     eax, eax
    xor     edx, edx
    mov     eax, [fs:0x30]
    mov     al, [eax + 0x68]        ; NtGlobalFlag
    mov     dl, al
    cmp     al, 0
    jne     _d

    ; ---- anti-debug 3: rdtsc timing window --------------------------------
    rdtsc
    mov     ebx, eax
    push    ecx
    pop     ecx
    add     edi, edi
    sub     edi, edi
    push    esi
    pop     esi
    add     ecx, ecx
    sub     ecx, ecx
    push    esi
    pop     esi
    add     edi, edi
    sub     edi, edi
    push    ecx
    pop     ecx
    add     ecx, ecx
    sub     ecx, ecx
    add     edi, edi
    sub     edi, edi
    push    esi
    pop     esi
    rdtsc
    sub     eax, ebx
    cmp     eax, 0x3e8              ; > 1000 ticks => somebody is stepping
    jg      _d
    jmp     near _n

_d: ; ---- debugger detected -------------------------------------------------
    push    dword _str_naughty
    call    _printf
    add     esp, dword 4
    mov     esp, ebp
    pop     ebp
    ret

_n: ; ---- clean path --------------------------------------------------------
    push    dword _str_bugs
    call    _printf
    add     esp, dword 4
    push    dword _str_hint
    call    _printf
    add     esp, dword 4

    ; Build the flag on the stack: nine dwords, each K +/- a constant.
    ; "and eax,0x41414141 / and eax,0x3e3e3e3e" always gives 0 (0x41 & 0x3e
    ; == 0): dead code.  Every jmp is a jmp +0 that only splits basic blocks.
    xor     eax, eax
    mov     eax, 0x6a253e2d         ; K
    push    eax                     ; push 1 = "fun!"  (end of flag)
    jmp     near _lol
_lol:
    sub     eax, 0x560c29fc         ; eax is still K here
    push    eax                     ; push 2 = "z_R_"
    jmp     near _yaya
_yaya:
    and     eax, 0x41414141
    and     eax, 0x3e3e3e3e
    mov     eax, 0x6a253e2d
    sub     eax, 0x49fd1bf4
    push    eax                     ; push 3 = "rick"
    jmp     near _lala
_lala:
    xor     eax, eax
    mov     eax, 0x6a253e2d
    sub     eax, 0x2b1124ff
    push    eax                     ; push 4 = "eR_t"
    jmp     near _dsfghtgf
_dsfghtgf:
    and     eax, 0x41414141
    and     eax, 0x3e3e3e3e
    mov     eax, 0x6a253e2d
    sub     eax, 0x5e190004
    push    eax                     ; push 5 = "buGG"
    jmp     near _ertrwe
_ertrwe:
    and     eax, 0x41414141
    and     eax, 0x3e3e3e3e
    mov     eax, 0x6a253e2d
    add     eax, 0x0de9d64d         ; the only ADD
    push    eax                     ; push 6 = "1_D3"
    jmp     near _kjnjk
_kjnjk:
    xor     eax, eax
    mov     eax, 0x6a253e2d
    sub     eax, 0x2b003419
    push    eax                     ; push 7 = "_Ant"
    jmp     near _qsacb
_qsacb:
    and     eax, 0x41414141
    and     eax, 0x3e3e3e3e
    mov     eax, 0x6a253e2d
    sub     eax, 0x3e001c06
    push    eax                     ; push 8 = "ling"
    jmp     near _tftrtftc
_tftrtftc:
    and     eax, 0x41414141
    and     eax, 0x3e3e3e3e
    mov     eax, 0x6a253e2d
    sub     eax, 0x42aa050e
    push    eax                     ; push 9 = "Tr0l"  (start of flag, at ESP)
    jmp     near _sup
_sup:
    ; ---- decode the 36 bytes in place with XOR 0x4b ----------------------
    push    esp
    pop     esi                     ; esi = esp = &flag[0]
    xor     edx, edx
    mov     edi, esi                ; edi = esi (in place)
    mov     edx, edi
    cld
    mov     ecx, 0x24               ; 36 bytes
    mov     ebx, 0x4b               ; key
    xor     eax, eax
    push    eax                     ; flag is now at ESP+4
_l:
    lodsb                           ; al = [esi++]
    xor     eax, ebx
    stosb                           ; [edi++] = al
    loop    _l

    ; <-- plaintext flag sits on the stack right here (breakpoint: 0x40178e)
    mov     esp, ebp
    pop     ebp
    ret
