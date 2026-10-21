#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>

int main(void)
{
    char name_buf[0x70];
    char passwd_buf[0xf];
    int fd;
    unsigned int secret;     // global, fixed address 0x804c044

    setvbuf(stdout, NULL, _IONBF, 0);

    srand(time(NULL));       // present in the binary; no clear use found in
                              // the reachable logic — likely leftover/defensive

    fd = open("/dev/urandom", O_RDONLY);
    read(fd, &secret, 4);

    printf("your name:");
    read(0, name_buf, 0x63);     // 99 bytes into a 112-byte buffer — not itself
                                   // an overflow; the real bug is below

    printf("Hello,");
    printf(name_buf);             // BUG: should be printf("%s", name_buf)

    printf("your passwd:");
    read(0, passwd_buf, 0xf);

    if (atoi(passwd_buf) == secret) {
        puts("ok!!");
        system("/bin/sh");
    } else {
        puts("fail");
    }

    return 0;
}