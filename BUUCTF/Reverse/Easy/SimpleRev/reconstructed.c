#include <stdio.h>
#include <string.h>
#include <stdlib.h>


char* join(const char* s1, const char* s2) {
    char* result = malloc(strlen(s1) + strlen(s2) + 1);
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

void Exit() {
    exit(0);
}

int Decry() {
    char v1;
    int v2 = 0;
    int v3 = 0;
    int i;
    int v5;
    
    
    const char* key1 = "ADSFK";
    const char* key3 = "kills";
    
    char key[100] = {0};
    char str2[100] = {0};
    char* text;

    
    char src[8] = "NDCLS"; 
    char v9[2][8] = {"hadow", ""}; 

    
    text = join(key3, v9[0]); 
    strcpy(key, key1);        
    strcat(key, src);         
    getchar(); 

    
    v5 = strlen(key);
    for (i = 0; i < v5; ++i) {
        if (key[v3 % v5] > 64 && key[v3 % v5] <= 90) {
            key[i] = key[v3 % v5] + 32; 
        }
        ++v3;
    }

    
    printf("Please input your flag:");
    while (1) {
        v1 = getchar();
        if (v1 == 10) 
            break;
            
        if (v1 == 32) { 
            ++v2;
        } else {
            
            if ((v1 <= 96 || v1 > 122) && (v1 > 64 && v1 <= 90)) {
                str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
                ++v3;
            } else if (v1 > 96 && v1 <= 122) {
                str2[v2] = (v1 - 39 - key[v3 % v5] + 97) % 26 + 97;
                ++v3;
            }
            
            if (!(v3 % v5)) {
                putchar(32);
            }
            ++v2;
        }
    }

    if (strcmp(text, str2) == 0) {
        puts("Congratulation!\n");
    } else {
        puts("Try again!\n");
    }

    return 0;
}

int main(int argc, const char **argv) {
    int v3;
    char v4;

    while (1) {
        while (1) {
            printf("Welcome to CTF game!\nPlease input d/D to start or input q/Q to quit this program: ");
            v4 = getchar();
            if (v4 != 'd' && v4 != 'D') 
                break;
            Decry();
        }
        if (v4 == 'q' || v4 == 'Q') 
            Exit();
            
        puts("Input fault format!");
        v3 = getchar();
        putchar(v3);
    }
}
