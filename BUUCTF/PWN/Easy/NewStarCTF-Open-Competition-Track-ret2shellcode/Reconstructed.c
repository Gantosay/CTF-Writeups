#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>

int main(void) {
    void *shellcode_page;
    char  buf[0x30];                 // rbp-0x30, but read() allows 0x100 bytes!

    shellcode_page = mmap((void *)0x233000, 0x1000,
                           PROT_READ | PROT_WRITE | PROT_EXEC,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    puts("Hello my friend.Any gift for me?");
    read(0, shellcode_page, 0x100);  // <- our shellcode lands here

    puts("Anything else?");
    read(0, buf, 0x100);             // <- THE BUG: overflows buf (only 0x30 bytes)

    puts("Ok.See you!");
    return 0;
}