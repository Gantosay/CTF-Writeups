int main(void) {
    char buf[16];                          // rbp-0x10, 0x10 bytes reserved

    system("echo -n \"What's your name? \""); // 0x4006a8 → string in .rodata

    scanf("%s", buf);                      // 0x4006c5 → "%s"
    printf("Welcome to the Pwn World, %s!\n", buf); // 0x4006c8 → format string

    return 0;
}