#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Global hardcoded ciphertext extracted from offset 0x100000f6e (.cstring)
// Mapped from assembly: rsi = qword [sym._global]
const unsigned char global_cipher[33] = {
    0x66, 0x0a, 0x6b, 0x0c, 0x77, 0x26, 0x4f, 0x2e, 0x40, 0x11, 
    0x78, 0x0d, 0x5a, 0x3b, 0x55, 0x11, 0x70, 0x19, 0x46, 0x1f, 
    0x76, 0x22, 0x4d, 0x23, 0x44, 0x0e, 0x67, 0x06, 0x68, 0x0f, 
    0x47, 0x32, 0x4f
};

// Reconstructed custom input routine matching sym._get_line
void get_line(char *buffer, int max_size) {
    int bytes_read = read(0, buffer, max_size - 1);
    if (bytes_read > 0 && buffer[bytes_read - 1] == '\n') {
        buffer[bytes_read - 1] = '\0'; // Purge trailing newline
    }
}

int main(int argc, char **argv) {
    char s1[256];
    
    // Initialize user stack array to zero
    // Assembly: call sym.imp.memset
    memset(s1, 0, sizeof(s1)); 
    
    // Assembly: lea rax, qword [str.Input_your_flag:] -> call printf
    printf("Input your flag:\n");
    get_line(s1, 256);
    
    // --- Step 1: Enforce Strict 33-Byte Length Gate ---
    // Assembly: call sym.imp.strlen -> cmp rax, 0x21 (33) -> jz
    if (strlen(s1) != 33) {
        printf("Failed\n");
        return 1;
    }
    
    // --- Step 2: The Cascading / Rolling XOR Loop ---
    // Mapped from offset 0x100000e17 up to 0x100000e6a
    // Loop counter (var_12ch) starts at index 1 and goes up to 33
    for (int i = 1; i < 33; i++) {
        // Assembly: movsx eax, byte [rbp+rcx*1-0x110] (reads s1[i-1])
        // Assembly: movsx edx, byte [rbp+rcx*1-0x110] (reads s1[i])
        // Assembly: xor eax, edx -> mov byte [rbp+rcx*1-0x110], sil
        s1[i] = s1[i] ^ s1[i - 1]; 
    }
    
    // --- Step 3: Global Reference Buffer Evaluation ---
    // Assembly: call sym.imp.strncmp against sym._global
    if (strncmp(s1, (const char*)global_cipher, 33) == 0) {
        printf("Success\n");
    } else {
        printf("Failed\n");
    }
    
    return 0;
}
