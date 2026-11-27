/* Experiment 27: RSA applied to each letter separately (A=0 ... Z=25)
 * IS IT SECURE?  NO. There are only 26 possible plaintext values, so an attacker simply
 * encrypts all 26 values with the PUBLIC key (e, n) and builds a lookup table; each
 * ciphertext block is matched against the table (a dictionary / codebook attack). Cost: 26
 * encryptions, independent of the size of n. Fix: pad/randomise (e.g. OAEP) and encrypt
 * large blocks.
 * Compile: gcc exp27.c -o exp27      Run: ./exp27
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef unsigned long long ull;
typedef unsigned __int128 u128;
ull power(ull b, ull e, ull m) { ull r = 1; b %= m; while (e) { if (e & 1) r = (u128)r * b % m; b = (u128)b * b % m; e >>= 1; } return r; }

int main(void) {
    ull n = 3599, e = 31, c[500], table[26];
    char msg[500] = "HELLO", in[500];
    int i, j, len = 0;
    printf("Public key e and n [31 3599]: ");
    if (scanf("%llu %llu", &e, &n) != 2) { e = 31; n = 3599; }
    getchar();
    printf("Message in capital letters [HELLO]: ");
    fgets(in, sizeof in, stdin);
    if (in[0] != '\n') { in[strcspn(in, "\n")] = 0; strcpy(msg, in); }
    printf("Alice sends:  ");
    for (i = 0; msg[i]; i++) if (isalpha((unsigned char)msg[i])) {
        c[len] = power(toupper((unsigned char)msg[i]) - 'A', e, n); printf("%llu ", c[len++]);
    }
    printf("\n\nAttack: Eve encrypts all 26 letters with the public key:\n");
    for (i = 0; i < 26; i++) { table[i] = power(i, e, n); printf("%c=%llu ", 'A' + i, table[i]); }
    printf("\n\nEve matches each ciphertext block with the table:\nRecovered message: ");
    for (i = 0; i < len; i++) for (j = 0; j < 26; j++) if (table[j] == c[i]) putchar('A' + j);
    printf("\n");
    return 0;
}
