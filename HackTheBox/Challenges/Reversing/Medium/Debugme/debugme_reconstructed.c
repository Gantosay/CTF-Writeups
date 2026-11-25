/*
 * debugme - RECONSTRUCTED source (the author never published the original).
 *
 * Everything here is recovered from debugme.exe:
 *   - the symbol table contains `.file "mash.asm"`, so the author wrote
 *     `main` in assembly and linked it with the MinGW CRT; hence the
 *     "C" file below is really a global-asm block,
 *   - instruction order, constants, strings and control flow match the
 *     unpacked binary 1:1 (see README.md for the annotated listing).
 *
 * What is NOT in this file: the XOR(0x5c) "packing" of main and the entry
 * point hijack.  Those were applied AFTER compilation by a patching step;
 * unpack.py (next to this file) reverses both and writes a clean .exe.
 *
 * The label names (_G, _d, _n, _lol, _yaya, _lala, _dsfghtgf, _ertrwe, _kjnjk,
 * _qsacb, _tftrtftc, _sup, _l) are the real ones from the binary's COFF symbol
 * table (all of them are local symbols inside the `mash.asm` object).
 *
 * Build (32-bit MinGW-w64):
 *     i686-w64-mingw32-gcc -o debugme_rebuilt.exe debugme_reconstructed.c
 * The result is functionally identical to the challenge, but NOT byte
 * identical (gas picks short jumps / imm8 forms where the original used
 * near jumps / imm32 forms).
 */

__asm__(
    ".intel_syntax noprefix\n"

    /* ------------------------------------------------------------ data */
    ".data\n"
    "_str_naughty:\n"
    "    .asciz \"Looks like your doing something naughty. Stop it!!!\\n\"\n"
    "_str_bugs:\n"
    "    .asciz \"I heard you like bugs so I put bugs in your debugger "
                "so you can have bugs while you debug!!!\\n\"\n"
    "_str_hint:\n"
    "    .asciz \"Seriously though try and find the flag, you will find "
                "it in your debugger!!!\\n\"\n"

    /* ------------------------------------------------------------ code */
    ".text\n"
    ".globl _main\n"
    "_main:\n"
    "    push ebp\n"
    "    mov  ebp, esp\n"

    /* --- anti-debug #1: PEB.BeingDebugged (fs:[0x30] -> PEB, +0x02) --- */
    "    xor  eax, eax\n"
    "    xor  edx, edx\n"
    "    mov  eax, fs:[0x30]\n"
    "    mov  al, BYTE PTR [eax + 0x02]\n"
    "    mov  dl, al\n"
    "    cmp  al, 0\n"
    "    jne  _d\n"
    "    jmp  _G\n"

    /* --- anti-debug #2: PEB.NtGlobalFlag (+0x68), 0x70 when debugged -- */
    "_G:\n"
    "    xor  eax, eax\n"
    "    xor  edx, edx\n"
    "    mov  eax, fs:[0x30]\n"
    "    mov  al, BYTE PTR [eax + 0x68]\n"
    "    mov  dl, al\n"
    "    cmp  al, 0\n"
    "    jne  _d\n"

    /* --- anti-debug #3: rdtsc timing (single-stepping is slow) --------- */
    "    rdtsc\n"
    "    mov  ebx, eax\n"
    "    push ecx ; pop ecx\n"
    "    add  edi, edi ; sub edi, edi\n"
    "    push esi ; pop esi\n"
    "    add  ecx, ecx ; sub ecx, ecx\n"
    "    push esi ; pop esi\n"
    "    add  edi, edi ; sub edi, edi\n"
    "    push ecx ; pop ecx\n"
    "    add  ecx, ecx ; sub ecx, ecx\n"
    "    add  edi, edi ; sub edi, edi\n"
    "    push esi ; pop esi\n"
    "    rdtsc\n"
    "    sub  eax, ebx\n"
    "    cmp  eax, 1000\n"
    "    jg   _d\n"
    "    jmp  _n\n"

    /* --- debugger detected: taunt and leave ---------------------------- */
    "_d:\n"
    "    push offset _str_naughty\n"
    "    call _printf\n"
    "    add  esp, 4\n"
    "    mov  esp, ebp\n"
    "    pop  ebp\n"
    "    ret\n"

    /* --- clean path: taunt, then build the flag on the stack ----------- */
    "_n:\n"
    "    push offset _str_bugs\n"
    "    call _printf\n"
    "    add  esp, 4\n"
    "    push offset _str_hint\n"
    "    call _printf\n"
    "    add  esp, 4\n"

    /* Nine dwords, each = 0x6a253e2d (+/-) constant.  and-with-0x41414141
       followed by and-with-0x3e3e3e3e always yields 0 (0x41 & 0x3e == 0),
       it is dead code whose only job is to confuse a reader.            */
    "    xor  eax, eax\n"
    "    mov  eax, 0x6a253e2d       /* push 1: \"fun!\" (end)   */\n"
    "    push eax\n"
    "    jmp  _lol\n"
    "_lol:\n"
    "    sub  eax, 0x560c29fc       /* push 2                   */\n"
    "    push eax\n"
    "    jmp  _yaya\n"
    "_yaya:\n"
    "    and  eax, 0x41414141\n"
    "    and  eax, 0x3e3e3e3e\n"
    "    mov  eax, 0x6a253e2d\n"
    "    sub  eax, 0x49fd1bf4       /* push 3                   */\n"
    "    push eax\n"
    "    jmp  _lala\n"
    "_lala:\n"
    "    xor  eax, eax\n"
    "    mov  eax, 0x6a253e2d\n"
    "    sub  eax, 0x2b1124ff       /* push 4                   */\n"
    "    push eax\n"
    "    jmp  _dsfghtgf\n"
    "_dsfghtgf:\n"
    "    and  eax, 0x41414141\n"
    "    and  eax, 0x3e3e3e3e\n"
    "    mov  eax, 0x6a253e2d\n"
    "    sub  eax, 0x5e190004       /* push 5                   */\n"
    "    push eax\n"
    "    jmp  _ertrwe\n"
    "_ertrwe:\n"
    "    and  eax, 0x41414141\n"
    "    and  eax, 0x3e3e3e3e\n"
    "    mov  eax, 0x6a253e2d\n"
    "    add  eax, 0x0de9d64d       /* push 6  (the only ADD)   */\n"
    "    push eax\n"
    "    jmp  _kjnjk\n"
    "_kjnjk:\n"
    "    xor  eax, eax\n"
    "    mov  eax, 0x6a253e2d\n"
    "    sub  eax, 0x2b003419       /* push 7                   */\n"
    "    push eax\n"
    "    jmp  _qsacb\n"
    "_qsacb:\n"
    "    and  eax, 0x41414141\n"
    "    and  eax, 0x3e3e3e3e\n"
    "    mov  eax, 0x6a253e2d\n"
    "    sub  eax, 0x3e001c06       /* push 8                   */\n"
    "    push eax\n"
    "    jmp  _tftrtftc\n"
    "_tftrtftc:\n"
    "    and  eax, 0x41414141\n"
    "    and  eax, 0x3e3e3e3e\n"
    "    mov  eax, 0x6a253e2d\n"
    "    sub  eax, 0x42aa050e       /* push 9: \"Tr0l\" (start) */\n"
    "    push eax\n"
    "    jmp  _sup\n"
    "_sup:\n"

    /* --- in-place decode: ESI = EDI = ESP (lowest address = flag[0]) --- */
    "    push esp\n"
    "    pop  esi\n"
    "    xor  edx, edx\n"
    "    mov  edi, esi\n"
    "    mov  edx, edi\n"
    "    cld\n"
    "    mov  ecx, 36               /* 9 dwords * 4 bytes       */\n"
    "    mov  ebx, 0x4b             /* XOR key                  */\n"
    "    xor  eax, eax\n"
    "    push eax\n"
    "_l:\n"
    "    lodsb                      /* al = *esi++              */\n"
    "    xor  eax, ebx\n"
    "    stosb                      /* *edi++ = al              */\n"
    "    loop _l\n"

    /* The flag is now plaintext on the stack - nobody prints it.
       You have to be sitting here (breakpoint on the `mov esp, ebp`
       below) to see it.  That is the whole challenge.                   */
    "    mov  esp, ebp\n"
    "    pop  ebp\n"
    "    ret\n"

    ".att_syntax prefix\n"
);

/* `main` above is provided by the asm block; nothing else is needed. */
extern int main(void);
