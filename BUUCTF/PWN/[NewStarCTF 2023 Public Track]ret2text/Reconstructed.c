#include <stdio.h>
#include <unistd.h>

void backdoor(void)
{
    puts("...");               // banner string, exact text not fully recovered
    execve("/bin/sh", NULL, NULL);
}

int main(void)
{
    char buf[32];

    puts("Welcome to NewStar CTF!!");
    puts("Show me your magic");

    read(0, buf, 0x100);       // bug: allows up to 256 bytes into a 32-byte buffer

    return 0;
}