#include <stdio.h>
#include <unistd.h>

int main(void)
{
    char buf[1024];     // 0x400
    int  n;

    setbuf(stdin,  NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);

    puts("Show me your magic!");

    n = read(0, buf, 0x400);
    if (n > 0) {
        void (*shellcode)() = (void (*)())buf;
        shellcode();
    }

    return 0;
}