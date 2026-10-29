#include <unistd.h>
#include <stdlib.h>

void vulnerable_function(void) {
    char buf[136];                  // sub $0x88,%esp -> 0x88 = 136 bytes
    system("echo Input:");          // call system@plt, before the read
    read(0, buf, 0x100);            // read(fd=0, buf, size=0x100=256)
    // buf is only 136 bytes, but up to 256 can be written -> overflow
}

int main(void) {
    vulnerable_function();
    system("echo 'Hello World!'");  // second call system@plt, after return
    return 0;
}