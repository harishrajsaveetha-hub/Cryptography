/* Experiment 11: Number of keys of the Playfair cipher
 * a) 25! keys (every arrangement of 25 letters in the 5x5 matrix) ~ power of 2
 * b) Matrices that differ only by cyclic row/column shifts (the matrix behaves
 *    like a torus) give identical encryption: 5 x 5 = 25 equivalent matrices,
 *    so effectively unique keys = 25!/25 = 24!
 * Compile: gcc exp11.c -o exp11 -lm      Run: ./exp11
 */
#include <stdio.h>
#include <math.h>

int main(void) {
    long double f = 1.0L, f24 = 1.0L;
    double lg = 0;
    int i;
    for (i = 2; i <= 25; i++) { f *= i; lg += log2((double)i); if (i == 24) f24 = f; }
    printf("a) Total Playfair keys = 25! = %.0Lf\n", f);
    printf("   log2(25!) = %.2f  => approximately 2^%.0f (about 2^84)\n", lg, lg);
    printf("b) Each matrix has 25 equivalent versions (5 row shifts x 5 column shifts).\n");
    printf("   Effectively unique keys = 25!/25 = 24! = %.0Lf\n", f24);
    printf("   log2(24!) = %.2f  => approximately 2^%.0f (about 2^79)\n", lg - log2(25.0), lg - log2(25.0));
    return 0;
}
