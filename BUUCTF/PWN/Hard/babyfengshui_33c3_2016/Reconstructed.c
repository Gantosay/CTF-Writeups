#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MAX_USERS 50

struct user {
    char *desc_ptr;
    char  name[124];
};

static struct user *users[MAX_USERS];
static unsigned char user_count = 0;   // NEVER decremented on delete

// ---- helper: fgets-based line reader, newline stripped ----
static void read_line(char *buf, int size) {
    fgets(buf, size, stdin);
    char *nl = strchr(buf, '\n');
    if (nl) *nl = '\0';
}

// ---- shared by "Add a user" AND menu option 3 ----
static void update_description(unsigned char index) {
    if (index >= user_count) return;
    struct user *u = users[index];
    if (!u) return;

    unsigned size;
    char junk;
    printf("text length: ");
    scanf("%u%c", &size, &junk);

    /* ***** THE BUG *****
     * This should validate against the TRUE size of the desc_ptr
     * allocation (the value passed to malloc() when this user's
     * desc_ptr buffer was created). Instead it compares against the
     * address of the struct itself minus 4 — two completely
     * unrelated heap allocations. This check is nearly always true
     * for any reasonable `size`, giving an effectively unbounded
     * heap buffer overflow on desc_ptr.
     */
    if ((char *)u->desc_ptr + size >= (char *)u - 4) {
        puts("my l33t defenses cannot be fooled, cya!");
        exit(1);
    }

    printf("text: ");
    read_line(u->desc_ptr, size + 1);   // fgets(desc_ptr, size+1, stdin)
}

static void add_user(unsigned size) {
    char *desc = malloc(size);
    memset(desc, 0, size);

    struct user *u = malloc(sizeof(struct user));   // request 0x80
    memset(u, 0, sizeof(struct user));
    u->desc_ptr = desc;

    users[user_count] = u;

    printf("name: ");
    read_line(u->name, sizeof(u->name) - 1);   // 0x7c bytes, SAFE

    update_description(user_count);   // <-- shared vulnerable routine
    user_count++;
}

static void delete_user(unsigned char index) {
    if (index >= user_count) return;
    struct user *u = users[index];
    if (!u) return;

    if (u->desc_ptr) free(u->desc_ptr);
    if (u)           free(u);
    users[index] = NULL;
}

static void display_user(unsigned char index) {
    if (index >= user_count) return;
    struct user *u = users[index];
    if (!u) return;

    printf("name: %s\n", u->name);
    printf("description: %s\n", u->desc_ptr);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    alarm(60);

    while (1) {
        int action;
        printf(
            "0: Add a user\n"
            "1: Delete a user\n"
            "2: Display a user\n"
            "3: Update a user description\n"
            "4: Exit\n"
            "Action: ");
        if (scanf("%d", &action) != 1) continue;

        unsigned char idx;
        switch (action) {
            case 0: {
                unsigned size;
                printf("size of description: ");
                scanf("%u", &size);
                if (user_count > 0x31) { puts("maximum capacity exceeded, bye"); exit(0); }
                add_user(size);
                break;
            }
            case 1:
                printf("index: ");
                scanf("%hhu", &idx);
                delete_user(idx);
                break;
            case 2:
                printf("index: ");
                scanf("%hhu", &idx);
                display_user(idx);
                break;
            case 3:
                printf("index: ");
                scanf("%hhu", &idx);
                update_description(idx);
                break;
            case 4:
                exit(0);
        }
    }
}