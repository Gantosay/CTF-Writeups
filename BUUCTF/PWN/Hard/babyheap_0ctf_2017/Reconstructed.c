#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_CHUNKS 16
#define MAX_SIZE   0x1000

typedef struct {
    long status;   // 0 = free, 1 = in use
    long size;     // size as actually allocated
    char *ptr;     // calloc'd heap pointer
} chunk_t;

static chunk_t chunks[MAX_CHUNKS];

static long read_long(void) {
    char buf[8]; int i = 0; char c;
    while (i < 7) {
        if (read(0, &c, 1) != 1) break;
        if (c == '\n') break;
        buf[i++] = c;
    }
    buf[i] = 0;
    return atol(buf);
}

static void do_allocate(void) {
    int idx = -1;
    for (int i = 0; i < MAX_CHUNKS; i++)
        if (chunks[i].status == 0) { idx = i; break; }
    if (idx == -1) return;

    printf("Size: ");
    long size = read_long();
    if (size <= 0) return;
    if (size > MAX_SIZE) size = MAX_SIZE;

    char *p = calloc(size, 1);        // <-- deliberate calloc, not malloc
    if (!p) return;

    chunks[idx] = (chunk_t){1, size, p};
    printf("Allocate Index %d\n", idx);
}

static void do_fill(void) {
    printf("Index: ");
    int idx = (int)read_long();
    if (idx < 0 || idx >= MAX_CHUNKS || chunks[idx].status != 1) return;

    printf("Size: ");
    long size = read_long();          // <-- BUG: never checked against chunks[idx].size
    if (size <= 0) return;

    printf("Content: ");
    read(0, chunks[idx].ptr, size);   // heap overflow if size > chunks[idx].size
}

static void do_free(void) {
    printf("Index: ");
    int idx = (int)read_long();
    if (idx < 0 || idx >= MAX_CHUNKS || chunks[idx].status != 1) return;

    chunks[idx].status = 0;
    chunks[idx].size = 0;
    free(chunks[idx].ptr);
    chunks[idx].ptr = 0;              // closes UAF through the index
}

static void do_dump(void) {
    printf("Index: ");
    int idx = (int)read_long();
    if (idx < 0 || idx >= MAX_CHUNKS || chunks[idx].status != 1) return;

    printf("Content: \n");
    write(1, chunks[idx].ptr, chunks[idx].size);
    printf("\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    puts("===== Baby Heap in 2017 =====");
    while (1) {
        printf("1. Allocate\n2. Fill\n3. Free\n4. Dump\n5. Exit\nCommand: ");
        switch (read_long()) {
            case 1: do_allocate(); break;
            case 2: do_fill();     break;
            case 3: do_free();     break;
            case 4: do_dump();     break;
            case 5: return 0;
        }
    }
}