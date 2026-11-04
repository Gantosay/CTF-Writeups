int x;  // 0x0804a02c, zero-initialized, lives in .data/.bss

int main(int argc, char **argv) {
    char buf[0x50];
    unsigned long canary = *(unsigned long *)(FS_BASE + 0x14);

    be_nice_to_people();   // drop SUID privileges via setresgid(getegid(), ...)

    memset(buf, 0, 0x50);
    int n = read(0, buf, 0x50);

    printf(buf);            // <-- format string vulnerability: no format args supplied

    printf("%d!\n", x);

    if (x == 4) {
        puts("running sh...");
        system("/bin/sh");
    }

    if (*(unsigned long *)(FS_BASE + 0x14) != canary)
        __stack_chk_fail();

    return 0;
}