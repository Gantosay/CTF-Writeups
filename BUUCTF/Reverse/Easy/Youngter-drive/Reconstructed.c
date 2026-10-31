#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <windows.h>
#include <tlhelp32.h>

char *flag = "TOiZiZtOrYaToUwPnToBsOaOapsyS";                          // .data 0x418004 -> 0x41574c
char *str  = "QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiopasdfghjklzxcvbnm";  // .data 0x418000 -> 0x415770
int   top  = 29;                                                       // 0x418008, shared counter
char  output[52];                                                      // 0x418148, raw copy
char  input[52];                                                       // 0x41817c, transformed in place
HANDLE hMutex;                                                         // 0x4181b0

// 0x411460: process blacklist (caller not identified)
void anti_debug(void) {
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);                                            // 0x22c
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    BOOL ok = Process32FirstW(h, &pe);
    while (ok) {
        _wcslwr_s(pe.szExeFile, wcslen(pe.szExeFile) + 1);
        if (!wcscmp(pe.szExeFile, L"ollyice.exe")) { printf("///////WARNING///////\n");        exit(0); }
        if (!wcscmp(pe.szExeFile, L"ollydbg.exe")) { printf("///////\nWARNING\n///////\n");   exit(0); }
        if (!wcscmp(pe.szExeFile, L"peid.exe"))    { printf("///////\nWARNING\n///////\n");   exit(0); }
        if (!wcscmp(pe.szExeFile, L"ida.exe"))     { printf("///////\nWARNING\n///////\n");   exit(0); }
        if (!wcscmp(pe.szExeFile, L"idaq.exe"))    { printf("///////\nWARNING\n///////\n");   exit(0); }
        ok = Process32NextW(h, &pe);
    }
    CloseHandle(h);
}

// 0x411bd0
void get_input(void) {
    printf("1111...\n****...banner...\n");
    printf("input flag:\n");
    scanf("%36s", input);
}

// 0x411940
void change(char *a, int idx) {
    char c = a[idx];
    if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')) {
        if (c >= 'a' && c <= 'z') a[idx] = str[c - 0x60];
        else                      a[idx] = str[c - 0x26];
    } else {
        exit(0);                        // non-letter, including NUL
    }
}

// 0x411a40: thread A
DWORD WINAPI ThreadA(LPVOID p) {
    while (1) {
        WaitForSingleObject(hMutex, INFINITE);
        if (top > -1) {
            change(input, top);
            top--;
            Sleep(100);
        }
        ReleaseMutex(hMutex);
    }
    return 0;
}

// 0x411b10: thread B (decoy)
DWORD WINAPI ThreadB(LPVOID p) {
    while (1) {
        WaitForSingleObject(hMutex, INFINITE);
        if (top > -1) {
            Sleep(100);
            top--;
        }
        ReleaseMutex(hMutex);
    }
    return 0;
}

// 0x411880
void check(void) {
    for (int i = 0; i < 29; i++)
        if (input[i] != flag[i]) exit(0);
    printf("\nflag{%s}\n\n", output);     // prints the RAW copy
}

// 0x411c70 (as disassembled: input first, then strcpy, then threads)
int main(void) {
    get_input();
    hMutex = CreateMutexW(NULL, FALSE, NULL);
    strcpy(output, input);
    CloseHandle(CreateThread(NULL, 0, ThreadA, NULL, 0, NULL));
    CloseHandle(CreateThread(NULL, 0, ThreadB, NULL, 0, NULL));
    while (1) {
        if (top == -1) {                // both threads finished the countdown
            check();
            CloseHandle(hMutex);
            return 0;
        }
    }
}