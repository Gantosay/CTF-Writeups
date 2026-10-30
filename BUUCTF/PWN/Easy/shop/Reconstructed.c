#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>

/* ── Global variables (fixed addresses, No PIE) ── */
int   money     = 100;     // 0x6020a0
int   bag[16];             // 0x6020c0  — 0=empty 1=flag 2=pen 3=wish
char  flag_buf[0x30];      // 0x6022a0  — raw /flag content

typedef struct {
    int   price;    // what you pay to buy
    int   recycle;  // what you get when you sell
    char  name[16];
} Item;

Item items[] = {
    {  0,   0, ""     },  // index 0: unused
    {200, 100, "flag" },  // index 1
    {100,  99, "pen"  },  // index 2
    { 50,   0, "wish" },  // index 3
};

/* ── init: load /flag into memory ── */
void init(void) {
    int fd = open("/flag", O_RDONLY);
    read(fd, flag_buf, 0x30);  // flag lives at 0x6022a0 forever
    close(fd);
    setbuf(stdout, NULL);
    setbuf(stdin,  NULL);
}

/* ── look: print all bag slots; prints flag if slot type == 1 ── */
void look(void) {
    for (int i = 0; i < 16; i++) {
        int type = bag[i];
        if      (type == 1) printf("[%02d]: flag -> %s\n", i, flag_buf); // WIN
        else if (type == 2) printf("[%02d]: pen\n",  i);
        else if (type == 3) printf("[%02d]: wish\n", i);
        else if (type == 0) printf("[%02d]: NULL\n", i);
        else { printf("Oops???"); exit(0); }
    }
    printf("your money: %d\n", money);
}

/* ── to_sale: runs in a background thread ── */
void *to_sale(void *arg) {
    int slot = (int)(long)arg;  // NO bounds check inherited from caller

    int type = bag[slot];       // BUG: slot can be negative → OOB read
    if      (type == 1) money += items[1].recycle;  // +100
    else if (type == 2) money += items[2].recycle;  // +99
    else { printf("Oops???"); exit(0); }

    usleep(50000);              // BUG: 50ms gap between money update and slot clear
                                //      ← TOCTOU race window is HERE

    bag[slot] = 0;              // BUG: with negative slot this writes outside bag
    return NULL;
}

/* ── sale: BUG — no bounds check on index ── */
void sale(void) {
    printf("Which one?\n> ");
    int slot = read_int();          // user input, unchecked

    if (bag[slot] != 0) {          // BUG: slot can be -8 → reads &money instead
        pthread_t tid;
        pthread_create(&tid, NULL, to_sale, (void*)(long)slot);
        // NO pthread_join — main thread returns immediately!
        puts("Fair prices!");
    } else {
        puts("R U kidding me?");
    }
}

/* ── to_buy / buy: standard purchase logic (threads, no race here) ── */
void *to_buy(void *arg) {
    int item = (int)(long)arg;
    money -= items[item].price;
    for (int i = 0; i < 16; i++)
        if (bag[i] == 0) { bag[i] = item; break; }
    return NULL;
}

void buy(void) {
    printf("Which one?\n> ");
    int choice = read_int();
    if (choice < 1 || choice > 3) return;
    if (items[choice].price > money) { puts("Poor bastard!"); return; }
    if (choice == 3) { money -= 50; puts("God bless you"); return; }
    pthread_t tid;
    pthread_create(&tid, NULL, to_buy, (void*)(long)choice);
    puts("Thank you for your patronage~");
}

int main(void) {
    init();
    game();   // infinite menu loop calling look/buy/sale
}