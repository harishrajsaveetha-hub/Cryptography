/* Experiment 4: Polyalphabetic Substitution Cipher (Vigenere)
 * Compile: gcc exp4.c -o exp4      Run: ./exp4
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(void) {
    char key[100], text[1000], kk[100];
    int ch, i, j = 0, kl = 0;
    printf("Enter key (letters only): ");
    fgets(key, sizeof key, stdin);
    for (i = 0; key[i]; i++) if (isalpha((unsigned char)key[i])) kk[kl++] = toupper((unsigned char)key[i]) - 'A';
    if (kl == 0) { puts("Invalid key"); return 1; }
    printf("1. Encrypt\n2. Decrypt\nChoice: ");
    scanf("%d", &ch); getchar();
    printf("Enter text: ");
    fgets(text, sizeof text, stdin);
    for (i = 0; text[i]; i++) {
        unsigned char c = text[i];
        if (isalpha(c)) {
            int base = isupper(c) ? 'A' : 'a';
            int s = (ch == 1) ? kk[j % kl] : 26 - kk[j % kl];
            text[i] = base + (c - base + s) % 26;
            j++;
        }
    }
    printf("Result: %s", text);
    return 0;
}
