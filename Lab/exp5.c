/* Experiment 5: Affine Caesar Cipher  C = (a*p + b) mod 26
 * a) Any restriction on b?   b) Which values of a are not allowed?
 * Compile: gcc exp5.c -o exp5      Run: ./exp5
 */
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int gcd(int a, int b) { return b ? gcd(b, a % b) : a; }
int inverse(int a) { int x; for (x = 1; x < 26; x++) if ((a * x) % 26 == 1) return x; return -1; }

int main(void) {
    int a, b, ch, i;
    char text[1000];
    printf("Analysis:\n");
    printf("a) b has no restriction: any b in 0..25 gives a one-to-one mapping provided a is valid.\n");
    printf("b) E is one-to-one only if gcd(a,26) = 1.\n   Allowed a    : ");
    for (a = 1; a < 26; a++) if (gcd(a, 26) == 1) printf("%d ", a);
    printf("\n   Not allowed a: 0 ");
    for (a = 1; a < 26; a++) if (gcd(a, 26) != 1) printf("%d ", a);
    printf("(all even numbers and 13)\n\n");

    printf("Enter a and b: ");
    scanf("%d %d", &a, &b);
    if (gcd(a, 26) != 1) { printf("a=%d is not allowed (gcd(a,26)!=1)\n", a); return 1; }
    b = ((b % 26) + 26) % 26;
    printf("1. Encrypt\n2. Decrypt\nChoice: ");
    scanf("%d", &ch); getchar();
    printf("Enter text: ");
    fgets(text, sizeof text, stdin);
    int ai = inverse(a);
    for (i = 0; text[i]; i++) {
        unsigned char c = text[i];
        if (isalpha(c)) {
            int base = isupper(c) ? 'A' : 'a', p = c - base;
            int r = (ch == 1) ? (a * p + b) % 26 : (ai * (p - b + 26)) % 26;
            text[i] = base + r;
        }
    }
    printf("Result: %s", text);
    return 0;
}
