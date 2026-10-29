#include <unistd.h>

void vulnerable_function(void) {
    char buf[128];                    // rbp-0x80 -> 0x80 = 128 bytes

    write(1, "Input:\n", 7);
    read(0, buf, 0x200);              // BUG: reads up to 512 bytes into a 128-byte buffer
}

int main(int argc, char *argv[]) {
    vulnerable_function();
    write(1, "Hello, World!\n", 14);
    return 0;
}