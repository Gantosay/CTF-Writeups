#include <stdio.h>
#include <unistd.h>

int main(int argc, char **argv) {
    char buf[32];   // at rbp-0x20; frame reserves 0x30 total, rest is padding/alignment

    setvbuf(stdout, 0, _IONBF, 2);
    setvbuf(stdin,  0, _IONBF, 2);
    setvbuf(stderr, 0, _IONBF, 2);

    puts("Welcome to NewStar CTF!!");
    puts("Show me your magic again");

    read(0, buf, 0x100);   // vulnerable: 256-byte read into a 32-byte buffer

    puts("See you next time");
    return 0;
}