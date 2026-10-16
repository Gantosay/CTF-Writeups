#include <stdio.h>

int main(void)
{
    char buf[32]; // exact declared size is uncertain, but reachable offset is 45 bytes

    printf("b0r4 v3r s3 7u 4h o b1ch4o m3m0... sssss");
    gets(buf);

    return 0;
}