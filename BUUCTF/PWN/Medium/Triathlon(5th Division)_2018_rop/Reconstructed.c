// rop.c  (reconstructed from disassembly — see the caveat below)

#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>

void be_nice_to_people(void) {
    gid_t gid = getegid();
    setresgid(gid, gid, gid);
}

void vulnerable_function(void) {
    char buffer[0x88];                  // 136-byte buffer

    read(STDIN_FILENO, buffer, 0x100);  // reads up to 256 bytes -- no bounds check
}

int main(void) {
    be_nice_to_people();
    vulnerable_function();
    write(STDOUT_FILENO, "Hello, World\n", 13);
    return 0;
}