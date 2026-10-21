#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void backdoor(void)
{
    system("/bin/sh");
}

int main(void)
{
    int len;
    char buf[16];

    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IOLBF, 0);

    len = 0;

    puts("**********************************");
    puts("*     Welcome to the BJDCTF!     *");
    puts("* And Welcome to the bin world!  *");
    puts("*  Let's try to pwn the world!   *");
    puts("* Please told me u answer loudly!*");
    puts("[+]Are u ready?");
    puts("[+]Please input the length of your name:");

    scanf("%d", &len);

    puts("[+]What's u name?");
    read(0, buf, len);   // len is fully attacker-controlled, never validated
                          // against the real 16-byte size of buf

    return 0;
}