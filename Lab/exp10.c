/* Experiment 10: Playfair encryption with the given matrix
 *   M F H I/J K
 *   U N O P Q
 *   Z V W X Y
 *   E L A R G
 *   D S T B C
 * Message: "Must see you over Cadogan West. Coming at once."
 * Compile: gcc exp10.c -o exp10      Run: ./exp10
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

char M[5][5] = {
    {'M','F','H','I','K'}, {'U','N','O','P','Q'}, {'Z','V','W','X','Y'},
    {'E','L','A','R','G'}, {'D','S','T','B','C'}
};

void find(char c, int *r, int *col) {
    int i, j;
    if (c == 'J') c = 'I';
    for (i = 0; i < 5; i++) for (j = 0; j < 5; j++) if (M[i][j] == c) { *r = i; *col = j; return; }
}

int main(void) {
    char msg[1000] = "Must see you over Cadogan West. Coming at once.", in[1000];
    char t[1000], p[2100], c[2100];
    int n = 0, m = 0, i, j;
    printf("Message [default: %s]: ", msg);
    if (fgets(in, sizeof in, stdin) && in[0] != '\n') { in[strcspn(in, "\n")] = 0; strcpy(msg, in); }
    printf("Matrix:\n");
    for (i = 0; i < 5; i++) { for (j = 0; j < 5; j++) printf("%c ", M[i][j]); printf("\n"); }
    for (i = 0; msg[i]; i++) if (isalpha((unsigned char)msg[i])) {
        char ch = toupper((unsigned char)msg[i]); t[n++] = (ch == 'J') ? 'I' : ch;
    }
    for (i = 0; i < n; ) {
        char a = t[i], b = (i + 1 < n) ? t[i + 1] : 'X';
        if (a == b) { b = 'X'; i++; } else i += 2;
        p[m++] = a; p[m++] = b;
    }
    p[m] = 0;
    for (i = 0; i < m; i += 2) {
        int r1, c1, r2, c2;
        find(p[i], &r1, &c1); find(p[i + 1], &r2, &c2);
        if (r1 == r2) { c1 = (c1 + 1) % 5; c2 = (c2 + 1) % 5; }
        else if (c1 == c2) { r1 = (r1 + 1) % 5; r2 = (r2 + 1) % 5; }
        else { int tmp = c1; c1 = c2; c2 = tmp; }
        c[i] = M[r1][c1]; c[i + 1] = M[r2][c2];
    }
    c[m] = 0;
    printf("Digraphs  : "); for (i = 0; i < m; i += 2) printf("%c%c ", p[i], p[i + 1]);
    printf("\nCiphertext: "); for (i = 0; i < m; i += 2) printf("%c%c ", c[i], c[i + 1]);
    printf("\n");
    return 0;
}
