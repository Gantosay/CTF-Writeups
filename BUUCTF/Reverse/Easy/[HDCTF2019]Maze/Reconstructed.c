#include <stdio.h>

int x = 7;                       // 0x408078
int y = 0;                       // 0x40807c

// 0x408030 - never referenced by any code
char maze[] =
    "*******+*********"
    " ******    ****   "
    "******* **F******"
    "    **************";

int main(void) {
    char buf[15];
    int i;

    printf("Go through the maze to get the flag!\n");
    scanf("%14s", buf);

    for (i = 0; i < 14; i++) {
        switch (buf[i]) {
            case 'a': x--; break;
            case 'd': x++; break;
            case 's': y--; break;
            case 'w': y++; break;
        }
    }

    if (x == 5 && y == -4) {
        printf("Congratulations!\n");
        printf("Here is the flag:flag{%s}\n", buf);
    } else {
        printf("Try again...\n");
    }
    return 0;
}