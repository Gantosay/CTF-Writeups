#include <stdio.h>
#include <string.h>

int main() {
    // The key value hidden natively in read-only segment
    char target_key[] = "HappyNewYear!";
    char user_input[30];

    printf("please input the true flag:");
    scanf("%s", user_input);

    // Corresponds to: call sym._strncmp followed by jz
    if (strncmp(user_input, target_key, strlen(target_key)) == 0) {
        printf("this is true flag!\n");
    } else {
        printf("wrong!\n");
    }

    return 0;
}