/* Experiment 8: Keyword-based Monoalphabetic Cipher (e.g. keyword CIPHER)
 * Cipher alphabet = keyword (duplicates removed) followed by unused letters in order.
 * Compile: gcc exp8.c -o exp8      Run: ./exp8
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(void) {
    char key[100], cip[27], inv[26], text[1000];
    int used[26] = {0}, n = 0, i, ch;
    printf("Enter keyword: ");
    scanf("%99s", key); getchar();
    for (i = 0; key[i]; i++) {
        int c = toupper((unsigned char)key[i]);
        if (isalpha(c) && !used[c - 'A']) { used[c - 'A'] = 1; cip[n++] = c; }
    }
    for (i = 0; i < 26; i++) if (!used[i]) cip[n++] = 'A' + i;
    cip[26] = 0;
    for (i = 0; i < 26; i++) inv[cip[i] - 'A'] = 'a' + i;
    printf("plain : a b c d e f g h i j k l m n o p q r s t u v w x y z\ncipher: ");
    for (i = 0; i < 26; i++) printf("%c ", cip[i]);
    printf("\n1. Encrypt\n2. Decrypt\nChoice: ");
    scanf("%d", &ch); getchar();
    printf("Enter text: ");
    fgets(text, sizeof text, stdin);
    for (i = 0; text[i]; i++) {
        if (!isalpha((unsigned char)text[i])) continue;
        int c = toupper((unsigned char)text[i]) - 'A';
        text[i] = (ch == 1) ? cip[c] : inv[c];
    }
    printf("Result: %s", text);
    return 0;
}
