/* Experiment 13: Known-plaintext and chosen-plaintext attacks on the 2x2 Hill cipher
 * Known plaintext : K = C * P^-1 (mod 26) using two independent digraph pairs.
 * Chosen plaintext: encrypt "ba" (1,0) and "ab" (0,1); the outputs are the columns of K.
 * Compile: gcc exp13.c -o exp13      Run: ./exp13
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

typedef struct { int a, b, c, d; } M2;   /* [[a b],[c d]] */

int md(int x) { x %= 26; return x < 0 ? x + 26 : x; }
int invnum(int a) { int x; for (x = 1; x < 26; x++) if (md(a * x) == 1) return x; return -1; }
int det(M2 m) { return md(m.a * m.d - m.b * m.c); }
M2 inverse(M2 m) {
    int di = invnum(det(m));
    M2 r = { md(di * m.d), md(-di * m.b), md(-di * m.c), md(di * m.a) };
    return r;
}
M2 mul(M2 x, M2 y) {
    M2 r = { md(x.a*y.a + x.b*y.c), md(x.a*y.b + x.b*y.d), md(x.c*y.a + x.d*y.c), md(x.c*y.b + x.d*y.d) };
    return r;
}
void enc(M2 K, int p0, int p1, int *c0, int *c1) { *c0 = md(K.a*p0 + K.b*p1); *c1 = md(K.c*p0 + K.d*p1); }
void show(const char *s, M2 m) { printf("%s = [%d %d; %d %d]\n", s, m.a, m.b, m.c, m.d); }

int main(void) {
    M2 K = {9, 4, 5, 7}, found;
    char pt[500] = "meetmeatthe";
    int p[500], c[500], n = 0, i, j, ok = 0;
    printf("Secret key (4 numbers row-wise, e.g. 9 4 5 7): ");
    scanf("%d %d %d %d", &K.a, &K.b, &K.c, &K.d); getchar();
    if (invnum(det(K)) < 0) { puts("Key not invertible"); return 1; }
    printf("Known plaintext (letters, >= 4) [default %s]: ", pt);
    char in[500]; fgets(in, sizeof in, stdin);
    if (in[0] != '\n') { in[strcspn(in, "\n")] = 0; strcpy(pt, in); }
    for (i = 0; pt[i]; i++) if (isalpha((unsigned char)pt[i])) p[n++] = tolower((unsigned char)pt[i]) - 'a';
    if (n % 2) p[n++] = 'x' - 'a';
    for (i = 0; i < n; i += 2) enc(K, p[i], p[i + 1], &c[i], &c[i + 1]);   /* attacker observes these */
    printf("Observed ciphertext: ");
    for (i = 0; i < n; i++) putchar('A' + c[i]);
    printf("\n\n--- Known plaintext attack ---\n");
    for (i = 0; i + 1 < n / 2 && !ok; i++)
        for (j = i + 1; j < n / 2 && !ok; j++) {
            M2 P = { p[2*i], p[2*j], p[2*i+1], p[2*j+1] };
            M2 C = { c[2*i], c[2*j], c[2*i+1], c[2*j+1] };
            if (invnum(det(P)) < 0) continue;
            printf("Using digraphs #%d and #%d\n", i + 1, j + 1);
            show("P", P); show("C", C);
            found = mul(C, inverse(P));
            show("K = C * P^-1", found);
            ok = 1;
        }
    if (!ok) puts("Need more / independent plaintext digraphs");
    else printf("Recovered key %s the real key\n", (found.a==K.a&&found.b==K.b&&found.c==K.c&&found.d==K.d) ? "MATCHES" : "does NOT match");

    printf("\n--- Chosen plaintext attack ---\n");
    int x0, x1, y0, y1;
    enc(K, 1, 0, &x0, &x1);   /* plaintext "ba" */
    enc(K, 0, 1, &y0, &y1);   /* plaintext "ab" */
    printf("E(\"ba\") = %c%c  -> first column of K  = (%d,%d)\n", 'A'+x0, 'A'+x1, x0, x1);
    printf("E(\"ab\") = %c%c  -> second column of K = (%d,%d)\n", 'A'+y0, 'A'+y1, y0, y1);
    M2 K2 = { x0, y0, x1, y1 };
    show("Recovered K", K2);
    return 0;
}
