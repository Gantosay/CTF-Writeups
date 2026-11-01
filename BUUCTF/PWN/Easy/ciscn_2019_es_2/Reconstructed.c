#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>

void hack() {
    system("echo flag");   // decoy — prints the literal word "flag", not a real flag
}

void init() {
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stdout, 0, 2, 0);
}

void vul() {
    char s[40];
    memset(s, 0, 0x20);

    read(0, s, 0x30);               // read #1 — 48 bytes max
    printf("Hello, %s\n", s);

    read(0, s, 0x30);               // read #2 — 48 bytes max, overwrites same buffer
    printf("Hello, %s\n", s);
}

int main() {
    init();
    puts("Welcome, my friend. What's your name?");
    vul();
    return 0;
}