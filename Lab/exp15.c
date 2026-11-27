/* Experiment 15: Letter-frequency attack on an additive (Caesar/shift) cipher
 * Tries all 26 shifts, scores each candidate with English letter frequencies
 * (log-likelihood) and prints the top N plaintexts, most likely first.
 * Compile: gcc exp15.c -o exp15 -lm      Run: ./exp15
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <math.h>

static const double F[26] = {8.167,1.492,2.782,4.253,12.702,2.228,2.015,6.094,6.966,0.153,
    0.772,4.025,2.406,6.749,7.507,1.929,0.095,5.987,6.327,9.056,2.758,0.978,2.360,0.150,1.974,0.074};

typedef struct { int shift; double score; } Cand;

int main(void) {
    char text[2000], out[2000];
    Cand c[26], t;
    int i, j, s, top;
    printf("Enter ciphertext: ");
    fgets(text, sizeof text, stdin);
    printf("How many top candidates (1-26)? ");
    scanf("%d", &top);
    if (top < 1) top = 1;
    if (top > 26) top = 26;
    for (s = 0; s < 26; s++) {
        double sc = 0;
        for (i = 0; text[i]; i++)
            if (isalpha((unsigned char)text[i])) sc += log(F[(toupper((unsigned char)text[i]) - 'A' - s + 26) % 26] / 100.0);
        c[s].shift = s; c[s].score = sc;
    }
    for (i = 0; i < 26; i++) for (j = i + 1; j < 26; j++)
        if (c[j].score > c[i].score) { t = c[i]; c[i] = c[j]; c[j] = t; }
    for (i = 0; i < top; i++) {
        for (j = 0; text[j]; j++) {
            unsigned char ch = text[j];
            if (isalpha(ch)) { int b = isupper(ch) ? 'A' : 'a'; out[j] = b + (ch - b - c[i].shift + 26) % 26; }
            else out[j] = ch;
        }
        out[j] = 0; out[strcspn(out, "\n")] = 0;
        printf("#%2d key=%2d score=%9.2f : %s\n", i + 1, c[i].shift, c[i].score, out);
    }
    return 0;
}
