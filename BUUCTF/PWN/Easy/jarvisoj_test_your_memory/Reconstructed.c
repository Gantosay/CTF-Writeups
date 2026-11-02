#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

char *hint = "cat flag";               // global @ 0x804a040

void win_func(char *cmd) {
    system(cmd);
}

void mem_test(char *random_hint) {
    char buf[11];                      // real usable size; compiler padded frame to 0x13 to buf
    memset(buf, 0, 11);

    puts("what???? : ");
    printf("0x%x \n", hint);           // leaks &"cat flag"
    puts("cff flag go go go ...");

    printf("> ");
    scanf("%s", buf);                  // VULNERABLE: unbounded write into an 11-byte buffer

    if (strncmp(buf, random_hint, 4) == 0)
        puts("good job!!");
    else
        puts("cff flag is failed!!");
}

int main(void) {
    char charset[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    char random_buf[10 + 1];           // +1 implied by frame layout / null terminator space
    int i;

    puts("\n\n\n------Test Your Memory!-------\n");

    srand(time(NULL));
    for (i = 0; i < 10; i++)
        random_buf[i] = charset[rand() % 62];

    printf("%s", random_buf);
    mem_test(random_buf);

    return 0;
}