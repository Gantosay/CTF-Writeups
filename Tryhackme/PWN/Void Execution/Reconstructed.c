#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void setup(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

int forbidden(char *buf) {
    for (size_t i = 0; i <= 0x62; i++) {
        if (buf[i] == 0x0f)
            goto bad;
        if (buf[i] == 0xcd && buf[i + 1] == 0x80)
            goto bad;
    }
    return 0;

bad:
    puts("Forbidden!");
    return 1;
}

int main(void) {
    setup();

    void *page = mmap((void *)0xc0de0000, 0x64,
                       PROT_READ | PROT_WRITE | PROT_EXEC,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    memset(page, 0, 0x64);

    puts("Send to void execution: ");
    read(0, page, 0x64);
    puts("voided!");

    if (forbidden(page))
        exit(1);

    mprotect(page, 0x64, PROT_EXEC);   // write permission removed HERE

    ((void (*)())page)();             // call page  -- see Section 6.1 for why this instruction matters

    return 0;
}