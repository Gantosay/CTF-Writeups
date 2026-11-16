#include <stdio.h>

int check(char *flag) {
    if (flag[0]  * 0x18db80 == 0x09e77500)
    if (flag[1]  * 0x675390 == 0x2b9740c0)
    if (flag[2]  * 0x383280 == 0x154b2280)
    if (flag[3]  * 0x9f2a18 == 0x4009efa8)
    if (flag[4]  * 0x3cb070 == 0x1d28c5d0)
    if (flag[5]  * 0x4e67a0 == 0x1eeee220)
    // flag[6] is never checked -- see section 5.1
    if (flag[7]  * 0x72eeda == 0x183e61fc)
    if (flag[8]  * 0x54b610 == 0x1189b150)
    if (flag[9]  * 0x340740 == 0x0a917900)
    if (flag[10] * 0xc692a6 == 0x26c8a46c)
    if (flag[11] * 0x5ce85d == 0x11c879cd)
    if (flag[12] * 0x784f77 == 0x170735c7)
    if (flag[13] * 0x8879b5 == 0x1a1f4ba5)
    if (flag[14] * 0x4f529a == 0x0edf7ce0)
    if (flag[15] * 0x455806 == 0x1a8bb24c)
    // flag[17] is checked here, BEFORE flag[16] -- see section 5.2
    if (flag[17] * 0x37a0a0 == 0x0a6e1e00)
    if (flag[16] * 0x9a58d0 == 0x3a7ba6d0)
    if (flag[18] * 0x9383b0 == 0x1d633c10)
    if (flag[19] * 0x51dae2 == 0x0f590a60)
    if (flag[20] * 0xcd73dc == 0x2dbecbfc)
    if (flag[21] * 0x53bf30 == 0x12a591b0)
    if (flag[22] * 0xdcf08c == 0x53b7250c)
    if (flag[23] * 0x627276 == 0x12d7e896)
    if (flag[24] * 0x5f6820 == 0x24e54460)
    if (flag[25] * 0x7675a4 == 0x16360ec0)
    if (flag[26] * 0x6fce58 == 0x16461b88)
    if (flag[27] * 0x856290 == 0x1db2f210)
    if (flag[28] * 0x875fc4 == 0x1af8140c)
    if (flag[29] * 0x3e5bc0 == 0x0c6c4740)
    if (flag[30] * 0x8f0ac0 == 0x1ebb4f40)
    if (flag[31] * 0x57e094 == 0x2ae8a844) {
        return 1;
    }
    return 0;
}

int main(void) {
    char flag[32] = {0};   // scanf below can overflow this by exactly 1 byte -- see section 5.3

    printf("input your flag:");
    scanf("%s", flag);

    if (check(flag)) {
        puts("Correct!");
    } else {
        puts("Wrong!");
    }

    return 0;
}