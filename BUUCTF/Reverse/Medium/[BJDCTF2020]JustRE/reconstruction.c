#include <windows.h>
#include <stdio.h>

#define IDC_CLICK 1001

static int g_counter = 0;   /* 0x4099f0 */

INT_PTR CALLBACK DlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam)
{
    char buf[100];          /* sub esp, 0x64 */

    switch (msg) {
    case WM_INITDIALOG:     /* 0x110 */
        return TRUE;

    case WM_COMMAND: {      /* 0x111 */
        WORD id = LOWORD(wParam);

        if (id == IDOK || id == IDCANCEL) {      /* 1 and 2 */
            EndDialog(hDlg, id);
            return TRUE;
        }

        g_counter++;
        sprintf(buf, "%d ", g_counter);          /* fmt at 0x40704c */

        if (g_counter == 19999) {                /* 0x4e1f */
            sprintf(buf, "BJD{%d%d2069a45792d233ac}", 19999, 0);
        }
        SetWindowTextA(hDlg, buf);               /* output in the title bar */
        return TRUE;
    }
    }
    return FALSE;
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE hPrev, LPSTR cmd, int show)
{
    DialogBoxParamA(hInst, MAKEINTRESOURCEA(100), NULL, DlgProc, 0);
    return 0;
}