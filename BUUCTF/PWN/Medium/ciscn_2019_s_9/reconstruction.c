int pwn(void)
{
    char buf[32];                       // at ebp-0x20

    puts("\nHey! ^_^");
    puts("\nIt's nice to meet you");
    puts("\nDo you have anything to tell?");
    puts(">");
    fflush(stdout);

    fgets(buf, 0x32, stdin);            // 0x32 = 50 — the actual bug

    puts("OK bye~");
    fflush(stdout);
    return 1;
}