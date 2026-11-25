/*
 * debugme_model.c - portable (Linux/macOS/Windows) model of the flag logic.
 * It performs the same arithmetic and the same stack layout as _main, but
 * with plain C so you can check the maths without a Windows debugger.
 *
 *     gcc -o model debugme_model.c && ./model
 */
#include <stdint.h>
#include <stdio.h>

int main(void)
{
    const uint32_t K = 0x6a253e2du;

    /* value of EAX at each `push eax`, in program order */
    const uint32_t pushed[9] = {
        K,                    /* push 1 */
        K - 0x560c29fcu,      /* push 2 */
        K - 0x49fd1bf4u,      /* push 3 */
        K - 0x2b1124ffu,      /* push 4 */
        K - 0x5e190004u,      /* push 5 */
        K + 0x0de9d64du,      /* push 6 - the only add */
        K - 0x2b003419u,      /* push 7 */
        K - 0x3e001c06u,      /* push 8 */
        K - 0x42aa050eu,      /* push 9 */
    };

    /* the stack grows down: push 9 ends up at the LOWEST address */
    uint32_t stack[9];
    for (int i = 0; i < 9; i++)
        stack[8 - i] = pushed[i];

    /* ESI = EDI = ESP -> walk upward, XOR every byte with 0x4b (lodsb/xor/stosb) */
    const uint8_t *mem = (const uint8_t *)stack;   /* little-endian host assumed */
    char flag[37];
    for (int i = 0; i < 36; i++)
        flag[i] = (char)(mem[i] ^ 0x4b);
    flag[36] = '\0';

    printf("HTB{%s}\n", flag);
    return 0;
}
