#include <stdio.h>
#include <unistd.h>

void init(void) {
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin,  NULL, _IONBF, 0);
}

void backdooOo0r(void) {
    execve("/bin/sh", NULL, NULL);
}

int main(void) {
    char buf[32];              // rbp-0x20, exactly 0x20 bytes

    init();
    puts("Welcome!May I have your name?");
    scanf("%s", buf);          // <-- THE BUG: no bound on input length
    puts("Ok.See you!");
    return 0;
}