#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void print_flag() {
    char c;
    FILE *f = fopen("flag.txt", "r");
    while ((c = fgetc(f)) != EOF) {
        putc(c, stdout);
    }
}

int main() {
    char name[40];
    // This is an 8 byte number which exists after the 40 bytes of name.
    uint64_t number = 0xdeadbeef;

    setup();

    puts("Welcome to the overflow challenge!");
    puts("If you can change the number to something other than 0xdeadbeef, you win!");
    puts("What's your name?");

    // Read a lot of input into name. What happens when we put (a lot) more than
    // 40 characters?
    gets(name);

    if (number != 0xdeadbeef) {
        print_flag();
    } else {
        printf("The number is 0x%lx right now.\nTry again!\n",
               number);
    }

    return 0;
}
