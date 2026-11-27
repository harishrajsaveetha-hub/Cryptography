/* Experiment 1: Caesar Cipher (shift by k, 1 <= k <= 25)
 * Compile: gcc exp1.c -o exp1      Run: ./exp1
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

void caesar(char *s, int k) {
    for (; *s; s++) {
        if (isupper((unsigned char)*s)) *s = 'A' + (*s - 'A' + k + 26) % 26;
        else if (islower((unsigned char)*s)) *s = 'a' + (*s - 'a' + k + 26) % 26;
    }
}

int main(void) {
    char text[1000];
    int k, ch;
    printf("1. Encrypt\n2. Decrypt\n3. Brute force (try all 25 keys)\nChoice: ");
    scanf("%d", &ch); getchar();
    printf("Enter text: ");
    fgets(text, sizeof text, stdin);
    text[strcspn(text, "\n")] = 0;
    if (ch == 3) {
        for (k = 1; k <= 25; k++) {
            char t[1000];
            strcpy(t, text);
            caesar(t, -k);
            printf("k=%2d: %s\n", k, t);
        }
        return 0;
    }
    printf("Enter key k (1-25): ");
    scanf("%d", &k);
    if (k < 1 || k > 25) { printf("Invalid key\n"); return 1; }
    caesar(text, ch == 1 ? k : -k);
    printf("Result: %s\n", text);
    return 0;
}
