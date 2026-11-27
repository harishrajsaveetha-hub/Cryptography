/* Experiment 18: DES subkey structure
 * Shows that the first 24 bits of every subkey come only from the 28 key bits that form C0
 * and the second 24 bits only from the 28 key bits that form D0 (two disjoint subsets).
 * Each key bit is tracked by its label (position 1..64 in the original key).
 * Compile: gcc exp18.c -o exp18      Run: ./exp18
 */
#include <stdio.h>
#include <string.h>

static const int PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const int PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};

static void rot(int *h, int s) {     /* rotate a 28-element half left by s */
    int t[28], i;
    for (i = 0; i < 28; i++) t[i] = h[(i + s) % 28];
    memcpy(h, t, sizeof t);
}

int main(void) {
    int cd[56], i, r, inC[65] = {0}, inD[65] = {0}, usedLeft[65] = {0}, usedRight[65] = {0};
    int ok = 1;
    for (i = 0; i < 56; i++) cd[i] = PC1[i];      /* label = original key bit number */
    for (i = 0; i < 28; i++) inC[cd[i]] = 1;
    for (i = 28; i < 56; i++) inD[cd[i]] = 1;
    printf("28 key bits feeding C0: "); for (i = 1; i <= 64; i++) if (inC[i]) printf("%d ", i);
    printf("\n28 key bits feeding D0: "); for (i = 1; i <= 64; i++) if (inD[i]) printf("%d ", i);
    printf("\n\n");
    for (r = 0; r < 16; r++) {
        rot(cd, SHIFTS[r]); rot(cd + 28, SHIFTS[r]);
        printf("Subkey K%-2d first 24 bits from key bits: ", r + 1);
        for (i = 0; i < 24; i++) { int lab = cd[PC2[i] - 1]; printf("%d ", lab); usedLeft[lab] = 1; if (!inC[lab]) ok = 0; }
        printf("\n            last 24 bits from key bits: ");
        for (i = 24; i < 48; i++) { int lab = cd[PC2[i] - 1]; printf("%d ", lab); usedRight[lab] = 1; if (!inD[lab]) ok = 0; }
        printf("\n");
    }
    for (i = 1; i <= 64; i++) if (inC[i] && inD[i]) ok = 0;
    printf("\nAll first-half bits come from the C subset, all second-half bits from the D subset,\n");
    printf("and the two 28-bit subsets are disjoint: %s\n", ok ? "VERIFIED" : "FAILED");
    return 0;
}
