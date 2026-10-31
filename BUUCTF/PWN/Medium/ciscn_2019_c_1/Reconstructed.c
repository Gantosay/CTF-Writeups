#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>

int x = 0;  // global state for the XOR cipher position

void handler(int sig) {
    puts("Timeout");
    _exit(1);
}

void init() {
    setvbuf(stdout, 0, 2, 0);
    setvbuf(stdin, 0, 2, 0);
    setvbuf(stderr, 0, 2, 0);
    signal(SIGALRM, handler);
    alarm(60);
}

void delete_char(char *s, char c) {
    int i = 0, j = 0;
    while (s[j] != '\0') {
        if (s[j] != c) {
            s[i++] = s[j];
        }
        j++;
    }
    s[i] = '\0';
}

void encrypt() {
    char buf[72];       // actually spans rbp-0x50 to rbp-0x08 (72 bytes usable)
    memset(buf, 0, 0x30); // rough equivalent of the rep stos zeroing

    puts("Input your Plaintext to be encrypted");
    gets(buf);           // <-- VULNERABLE: no bounds check

    while (x < strlen(buf)) {
        char c = buf[x];
        if (c > 0x60 && c <= 0x7a) {
            buf[x] ^= 0xd;          // lowercase letters
        } else if (c > 0x40 && c <= 0x5a) {
            buf[x] ^= 0xe;          // uppercase letters
        } else if (c > 0x2f && c <= 0x39) {
            buf[x] ^= 0xf;          // digits
        }
        x++;
    }

    puts("Ciphertext");
    puts(buf);
}

void begin() {
    puts("====================================================================");
    puts("1.Encrypt");
    puts("2.Decrypt");
    puts("3.Exit");
    puts("Input your choice!");
}

int main() {
    init();
    puts("... banner art ...");
    begin();

    while (1) {
        fflush(stdout);
        int choice;
        scanf("%d", &choice);
        getchar();

        if (choice == 1) {
            encrypt();
            begin();
        } else if (choice == 2) {
            puts("I think you can do it by yourself");
            begin();
        } else if (choice == 3) {
            puts("Bye!");
            break;
        } else {
            puts("Something Wrong!");
            break;
        }
    }
    return 0;
}