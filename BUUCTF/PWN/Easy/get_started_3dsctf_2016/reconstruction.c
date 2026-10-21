#include <stdio.h>
#include <stdlib.h>

// never called from main() — reachable only via return-address hijack
void get_flag(int a, int b) {
    if (a == 0x308cd64f && b == 0x195719d1) {
        FILE *f = fopen("/path/to/flag", "r");   // literal path recovered from .rodata
        int c;
        while ((c = fgetc(f)) != EOF) {
            putchar(c);
        }
        fclose(f);
    }
    // falls through silently otherwise — no error message, no extra output
}

int main(void) {
    char buf[... ];               // exact declared size unknown; irrelevant — gets() ignores it
    printf("Qual a palavrinha magica? ");   // Portuguese: "What's the magic word?"
    gets(buf);                     // no bounds checking whatsoever
    return 0;
}