#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

void shell(void)
{
    system("/bbbbbbbbin_what_the_f?ck__--??/sh");
}

void init(void)
{
    alarm(32);

    setvbuf(stdin,  NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    puts("\\ ");
}

void vulnerable(void)
{
    char buf[24];

    read(STDIN_FILENO, buf, 0x24);   // 0x24 = 36 > sizeof(buf) -- the bug
}

int main(void)
{
    init();
    vulnerable();

    return 0;
}