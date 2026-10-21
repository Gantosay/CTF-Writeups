#include <stdio.h>
#include <string.h>

static int b64_index(char c) {
    const char *alphabet =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const char *p = strchr(alphabet, c);
    return p ? (int)(p - alphabet) : -1;
}

int main(void) {
    const char target[] = "e3nifIH9b_C@n@dH";
    int len = (int)strlen(target);        /* 16 */
    char b64[64];

    /* Step 1: undo dest[j] = dest[j] + j */
    for (int j = 0; j < len; j++)
        b64[j] = (char)(target[j] - j);
    b64[len] = '\0';

    /* Step 2: Base64 decode (len is a multiple of 4, no '=' padding) */
    unsigned char out[64];
    int o = 0;
    for (int k = 0; k < len; k += 4) {
        int a = b64_index(b64[k]);
        int b = b64_index(b64[k + 1]);
        int c = b64_index(b64[k + 2]);
        int d = b64_index(b64[k + 3]);
        out[o++] = (unsigned char)((a << 2) | (b >> 4));
        out[o++] = (unsigned char)(((b & 0xF) << 4) | (c >> 2));
        out[o++] = (unsigned char)(((c & 0x3) << 6) | d);
    }
    out[o] = '\0';

    printf("Base64 text: %s\n", b64);     /* e2lfbDB2ZV95b3V9 */
    printf("Answer     : %s\n", out);     /* {i_l0ve_you} */
    return 0;
}

