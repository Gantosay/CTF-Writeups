// level3.c — reconstructed challenge source
// Compiled as: gcc -m32 -fno-stack-protector -z execstack=no -no-pie -o level3 level3.c

#include <unistd.h>

void vulnerable_function(void) {
    char buf[136];                     // 0x88 bytes — undersized on purpose

    write(1, "Input:\n", 7);
    read(0, buf, 256);                 // 0x100 bytes read — classic off-by-overflow
    // no bounds check, no canary (-fno-stack-protector), stack smash is trivial
}

int main(void) {
    vulnerable_function();
    write(1, "Hello, World!\n", 14);
    return 0;
}