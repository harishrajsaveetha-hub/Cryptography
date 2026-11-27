/* Experiment 9: PT-109 message (Playfair). Decrypt using keyword
 * "ROYAL NEW ZEALAND NAVY" (the Royal New Zealand Navy Playfair key).
 * Compile: gcc exp9.c -o exp9      Run: ./exp9
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

char M[5][5];

void build(const char *key) {
    int used[26] = {0}, n = 0, i;
    char buf[300];
    snprintf(buf, sizeof buf, "%sABCDEFGHIKLMNOPQRSTUVWXYZ", key);
    for (i = 0; buf[i]; i++) {
        int c = toupper((unsigned char)buf[i]);
        if (!isalpha(c)) continue;
        if (c == 'J') c = 'I';
        if (!used[c - 'A']) { used[c - 'A'] = 1; M[n / 5][n % 5] = c; n++; }
    }
}
void find(char c, int *r, int *col) {
    int i, j;
    for (i = 0; i < 5; i++) for (j = 0; j < 5; j++) if (M[i][j] == c) { *r = i; *col = j; return; }
}

int main(void) {
    const char *cipher =
        "KXJEY UREBE ZWEHE WRYTU HEYFS KREHE GOYFI WTTTU OLKSY CAJPO "
        "BOTEI ZONTX BYBNT GONEY CUZWR GDSON SXBOU YWRHE BAAHY USEDQ";
    char key[100] = "ROYAL NEW ZEALAND NAVY", in[100], c[300], p[300];
    int n = 0, i, j;
    printf("Keyword [default: %s]: ", key);
    if (fgets(in, sizeof in, stdin) && in[0] != '\n') { in[strcspn(in, "\n")] = 0; strcpy(key, in); }
    build(key);
    printf("Matrix:\n");
    for (i = 0; i < 5; i++) { for (j = 0; j < 5; j++) printf("%c ", M[i][j]); printf("\n"); }
    for (i = 0; cipher[i]; i++) if (isalpha((unsigned char)cipher[i])) c[n++] = (cipher[i] == 'J') ? 'I' : cipher[i];   /* I/J share one cell */
    c[n] = 0;
    for (i = 0; i < n; i += 2) {
        int r1, c1, r2, c2;
        find(c[i], &r1, &c1); find(c[i + 1], &r2, &c2);
        if (r1 == r2) { c1 = (c1 + 4) % 5; c2 = (c2 + 4) % 5; }
        else if (c1 == c2) { r1 = (r1 + 4) % 5; r2 = (r2 + 4) % 5; }
        else { int t = c1; c1 = c2; c2 = t; }
        p[i] = M[r1][c1]; p[i + 1] = M[r2][c2];
    }
    p[n] = 0;
    printf("Ciphertext: %s\nDecrypted : %s\n", cipher, p);
    printf("(X = filler / word separator, e.g. 'PT BOAT ONE OWE NINE LOST ...')\n");
    return 0;
}
