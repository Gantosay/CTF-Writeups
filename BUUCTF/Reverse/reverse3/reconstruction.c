#include <stdio.h>
#include <string.h>

char *base64_encode(const char *in, int len, int *out_len);   /* standard Base64 */

int main(void) {
    char dest[100];
    char Str[21];
    int  outlen;

    for (int i = 0; i < 100; i++)
        dest[i] = 0;

    printf("please enter the flag:");
    scanf("%20s", Str);

    char *enc = base64_encode(Str, (int)strlen(Str), &outlen);
    strncpy(dest, enc, 0x28);

    int len = (int)strlen(dest);
    for (int j = 0; j < len; j++)
        dest[j] = dest[j] + j;

    if (strncmp(dest, "e3nifIH9b_C@n@dH", strlen(dest)) == 0)
        printf("rigth flag!\n");
    else
        printf("wrong flag!\n");

    return 0;
}