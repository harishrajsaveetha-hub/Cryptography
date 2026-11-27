/* Experiment 12: Hill cipher (2x2) - encryption and decryption with calculations
 * Message: "meet me at the usual place at ten rather than eight oclock"
 * Key = [9 4; 5 7]
 * Compile: gcc exp12.c -o exp12      Run: ./exp12
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int md(int x) { x %= 26; return x < 0 ? x + 26 : x; }
int invnum(int a) { int x; for (x = 1; x < 26; x++) if (md(a * x) == 1) return x; return -1; }

int main(void) {
    int K[2][2] = {{9, 4}, {5, 7}}, Ki[2][2], i, n = 0, det, di;
    char msg[1000] = "meet me at the usual place at ten rather than eight oclock", in[1000];
    int p[1000], c[1000];
    printf("Enter key as 4 numbers (row-wise) or 0 0 0 0 for default [9 4 5 7]: ");
    int t[4]; scanf("%d %d %d %d", &t[0], &t[1], &t[2], &t[3]); getchar();
    if (t[0] || t[1] || t[2] || t[3]) { K[0][0]=t[0]; K[0][1]=t[1]; K[1][0]=t[2]; K[1][1]=t[3]; }
    det = md(K[0][0] * K[1][1] - K[0][1] * K[1][0]);
    di = invnum(det);
    if (di < 0) { printf("Key not invertible mod 26 (det=%d)\n", det); return 1; }
    printf("Key K = [%d %d; %d %d], det = %d, det^-1 mod 26 = %d\n", K[0][0], K[0][1], K[1][0], K[1][1], det, di);
    Ki[0][0] = md(di * K[1][1]); Ki[0][1] = md(-di * K[0][1]);
    Ki[1][0] = md(-di * K[1][0]); Ki[1][1] = md(di * K[0][0]);
    printf("K^-1 = [%d %d; %d %d]\n\n", Ki[0][0], Ki[0][1], Ki[1][0], Ki[1][1]);

    printf("Message [default: %s]: ", msg);
    fgets(in, sizeof in, stdin);
    if (in[0] != '\n') { in[strcspn(in, "\n")] = 0; strcpy(msg, in); }
    for (i = 0; msg[i]; i++) if (isalpha((unsigned char)msg[i])) p[n++] = tolower((unsigned char)msg[i]) - 'a';
    if (n % 2) p[n++] = 'x' - 'a';

    printf("---- Encryption  C = K*P mod 26 ----\n");
    for (i = 0; i < n; i += 2) {
        int c0 = md(K[0][0] * p[i] + K[0][1] * p[i + 1]);
        int c1 = md(K[1][0] * p[i] + K[1][1] * p[i + 1]);
        c[i] = c0; c[i + 1] = c1;
        printf("%c%c = (%2d,%2d): [%d*%d+%d*%d, %d*%d+%d*%d] mod 26 = (%2d,%2d) -> %c%c\n",
               'a' + p[i], 'a' + p[i + 1], p[i], p[i + 1],
               K[0][0], p[i], K[0][1], p[i + 1], K[1][0], p[i], K[1][1], p[i + 1],
               c0, c1, 'A' + c0, 'A' + c1);
    }
    printf("Ciphertext: ");
    for (i = 0; i < n; i++) putchar('A' + c[i]);
    printf("\n\n---- Decryption  P = K^-1 * C mod 26 ----\n");
    for (i = 0; i < n; i += 2) {
        int p0 = md(Ki[0][0] * c[i] + Ki[0][1] * c[i + 1]);
        int p1 = md(Ki[1][0] * c[i] + Ki[1][1] * c[i + 1]);
        printf("%c%c = (%2d,%2d): [%d*%d+%d*%d, %d*%d+%d*%d] mod 26 = (%2d,%2d) -> %c%c\n",
               'A' + c[i], 'A' + c[i + 1], c[i], c[i + 1],
               Ki[0][0], c[i], Ki[0][1], c[i + 1], Ki[1][0], c[i], Ki[1][1], c[i + 1],
               p0, p1, 'a' + p0, 'a' + p1);
    }
    return 0;
}
