#include <stdio.h>
#include <stdlib.h>

extern char *gets(char *);   // deprecated / removed from C11 — no bounds checking

void overflow(void)
{
    char buffer[12];   // ebp-0xc, confirmed by `lea eax, [ebp-0xc]`
    gets(buffer);      // <-- the vulnerability: no size limit passed in
}

int main(void)
{
    overflow();
    return 0;
}