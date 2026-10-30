#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void func() {
    // 1. Encrypted target string hidden in memory (Qsw3sj_lz4_Ujw@l)
    char encrypted_target[17] = {
        0x51, 0x73, 0x73, 0x33, 0x73, 0x6a, 0x5f, 0x6c, 
        0x7a, 0x34, 0x5f, 0x55, 0x6a, 0x77, 0x40, 0x6c, 0x00
    };
    
    char input[100];
    char processed_input[17];
    int i;

    printf("Please input:");
    scanf("%s", input);

    // 2. Early validation check for the flag format (ACTF{)
    // If the input doesn't start with the correct header, it exits silently
    if (input[0] != 'A' || input[1] != 'C' || input[2] != 'T' || input[3] != 'F' || input[4] != '{') {
        return;
    }

    // 3. Extract the inner content inside the brackets (skipping the first 5 chars "ACTF{")
    for (i = 0; i < 16; i++) {
        processed_input[i] = input[i + 5];
    }
    processed_input[16] = '\0';

    // 4. Main custom Caesar cipher encryption loop
    for (i = 0; i < 16; i++) {
        char c = processed_input[i];

        if (c >= 'A' && c <= 'Z') {
            // Uppercase transformation (13-step shift)
            processed_input[i] = ((c - 51) % 26) + 65;
        } 
        else if (c >= 'a' && c <= 'z') {
            // Lowercase transformation (11-step shift)
            processed_input[i] = ((c - 79) % 26) + 97;
        }
        // Special characters (_, @) and numbers are left completely unchanged
    }

    // 5. Character-by-character validation loop against the encrypted target
    for (i = 0; i < 16; i++) {
        if (processed_input[i] != encrypted_target[i]) {
            return; // Loser trap: exits silently if even a single character mismatches
        }
    }

    // 6. Success block executed only if all checks pass successfully
    printf("You are correct!");
}

int main() {
    func();
    return 0;
}
