#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void vulnerable_function(void)
{
    char buf[128];

    system("echo Input:");   // unusual choice of prompt, but resolves system@plt early
    read(0, buf, 0x200);     // bug: allows up to 512 bytes into a 128-byte buffer
}

int main(void)
{
    vulnerable_function();
    return 0;
}