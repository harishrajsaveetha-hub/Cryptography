/* Experiment 14: One-time-pad version of the Vigenere cipher
 * a) Encrypt "send more money" with key stream 9 0 1 7 23 15 21 14 11 11 2 8 9
 * b) Find the key stream that makes that ciphertext decrypt to "cash not needed"
 * Compile: gcc exp14.c -o exp14      Run: ./exp14
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int main(void) {
    const char *p1 = "send more money", *p2 = "cash not needed";
    int key[] = {9, 0, 1, 7, 23, 15, 21, 14, 11, 11, 2, 8, 9};
    int a[50], c[50], k2[50], n = 0, i;
    for (i = 0; p1[i]; i++) if (isalpha((unsigned char)p1[i])) a[n++] = p1[i] - 'a';
    printf("a) Plaintext : %s\n   Key stream: ", p1);
    for (i = 0; i < n; i++) printf("%d ", key[i]);
    printf("\n   Ciphertext: ");
    for (i = 0; i < n; i++) { c[i] = (a[i] + key[i]) % 26; putchar('A' + c[i]); }
    printf("\n\nb) Target plaintext: %s\n   Key stream needed: ", p2);
    int m = 0, b[50];
    for (i = 0; p2[i]; i++) if (isalpha((unsigned char)p2[i])) b[m++] = p2[i] - 'a';
    for (i = 0; i < m && i < n; i++) { k2[i] = ((c[i] - b[i]) % 26 + 26) % 26; printf("%d ", k2[i]); }
    printf("\n   Check: ");
    for (i = 0; i < m && i < n; i++) putchar('a' + ((c[i] - k2[i]) % 26 + 26) % 26);
    printf("\n(Any ciphertext can decrypt to any plaintext of equal length -> perfect secrecy.)\n");
    return 0;
}
