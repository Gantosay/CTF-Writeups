#include <windows.h>
#include <stdlib.h>
#include <string.h>

static const char B64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static void b64_block(const unsigned char in[3], char out[5]) {
    unsigned v = (in[0] << 16) | (in[1] << 8) | in[2];
    out[0] = B64[(v >> 18) & 0x3F];
    out[1] = B64[(v >> 12) & 0x3F];
    out[2] = B64[(v >>  6) & 0x3F];
    out[3] = B64[ v        & 0x3F];
    out[4] = '\0';
}

static int cmp_int(const void *a, const void *b) {
    return *(const int *)a - *(const int *)b;
}

INT_PTR CALLBACK DialogProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    if (msg != WM_COMMAND) return FALSE;

    switch (LOWORD(wParam)) {
    case IDOK:
    case IDCANCEL:
        EndDialog(hDlg, LOWORD(wParam));
        return TRUE;

    case 1001: {                                     /* "Check" button */
        char in[0xFFFF] = {0};
        GetDlgItemTextA(hDlg, 1000, in, sizeof(in));
        if (strlen(in) != 8) return FALSE;           /* Gate 0 */

        int a[11] = {90, 74, 83, 69, 67, 97, 78, 72, 51, 110, 103};
        qsort(a, 11, sizeof(int), cmp_int);          /* Gate 1: sub_4010F0 */

        unsigned char blk[3];
        char r1[5], r2[5];

        blk[0] = in[5]; blk[1] = in[6]; blk[2] = in[7];
        b64_block(blk, r1);                          /* compared with "ak1w" */

        blk[0] = in[2]; blk[1] = in[3]; blk[2] = in[4];
        b64_block(blk, r2);                          /* compared with "V1Ax" */

        if (in[0] == a[0] + 34            &&         /* Gate 2: algebra */
            in[1] == a[4]                 &&
            4 * in[2] - 141 == 3 * a[2]   &&
            in[3] / 4 == 2 * (a[7] / 9)   &&
            !strcmp(r1, "ak1w")           &&         /* Gate 3: base64 */
            !strcmp(r2, "V1Ax"))
        {
            MessageBoxA(hDlg, "U g3t 1T!", "@_@", MB_OK);
        }
        return FALSE;
    }
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE p, LPSTR cmd, int show) {
    DialogBoxParamA(h, MAKEINTRESOURCEA(103), NULL, DialogProc, 0);
    return 0;
}