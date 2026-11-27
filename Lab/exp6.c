/* Experiment 6: Break an affine cipher using letter frequencies.
 * Most frequent ciphertext letter = B, second = U (default). Assume they stand
 * for plaintext e and t, then solve  a*4+b = 1 (mod 26),  a*19+b = 20 (mod 26).
 * Compile: gcc exp6.c -o exp6      Run: ./exp6
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int gcd(int a, int b) { return b ? gcd(b, a % b) : a; }
int inverse(int a) { int x; for (x = 1; x < 26; x++) if ((a * x) % 26 == 1) return x; return -1; }

int main(void) {
    char c1 = 'B', c2 = 'U', in[10], text[1000];
    const char *common = "ETAOINSHR";
    int a, b, i, j, found = 0, ka = 0, kb = 0;
    printf("Most frequent ciphertext letter [B]: ");
    fgets(in, sizeof in, stdin); if (isalpha((unsigned char)in[0])) c1 = toupper((unsigned char)in[0]);
    printf("Second most frequent letter [U]: ");
    fgets(in, sizeof in, stdin); if (isalpha((unsigned char)in[0])) c2 = toupper((unsigned char)in[0]);
    for (i = 0; common[i] && !found; i++)
        for (j = 0; common[j] && !found; j++) {
            if (i == j) continue;
            int p1 = common[i] - 'A', p2 = common[j] - 'A';
            for (a = 1; a < 26 && !found; a++) {
                if (gcd(a, 26) != 1) continue;
                for (b = 0; b < 26; b++)
                    if ((a * p1 + b) % 26 == c1 - 'A' && (a * p2 + b) % 26 == c2 - 'A') {
                        found = 1; ka = a; kb = b;
                        printf("Assuming %c->%c and %c->%c\n", common[i], c1, common[j], c2);
                        break;
                    }
            }
        }
    if (!found) { puts("No affine key fits"); return 1; }
    printf("Key found: a = %d, b = %d  (C = %d*p + %d mod 26)\n", ka, kb, ka, kb);
    printf("Decryption: p = %d*(C - %d) mod 26\n", inverse(ka), kb);
    printf("Enter ciphertext to decrypt (blank to skip): ");
    fgets(text, sizeof text, stdin);
    int ai = inverse(ka);
    for (i = 0; text[i]; i++)
        if (isalpha((unsigned char)text[i])) {
            int c = toupper((unsigned char)text[i]) - 'A';
            text[i] = 'a' + (ai * (c - kb + 26)) % 26;
        }
    printf("Plaintext: %s", text);
    return 0;
}
