/* Experiment 29: SHA-3 (rate r = 1024 bits, capacity c = 576 bits)
 * State = 5x5 lanes of 64 bits (1600 bits). Lane index = x + 5*y.
 * First message block P0 is XORed into the first r/64 = 16 lanes (all assumed nonzero);
 * the remaining 9 capacity lanes start as 0. Permutation positions are ignored.
 * Only the theta step spreads data between lanes:  A[x,y] ^= C[x-1] ^ rot(C[x+1]),
 * where C[x] is the XOR of the 5 lanes of column x. We track "lane has a nonzero bit".
 * Compile: gcc exp29.c -o exp29      Run: ./exp29
 */
#include <stdio.h>
#include <string.h>

#define W 5

static void show(int a[W][W]) {
    int x, y;
    for (y = 0; y < W; y++) { printf("   "); for (x = 0; x < W; x++) printf("%d ", a[x][y]); printf("\n"); }
}

int main(void) {
    int a[W][W], x, y, round = 0, rate_lanes = 1024 / 64, all;
    memset(a, 0, sizeof a);
    for (y = 0; y < W; y++) for (x = 0; x < W; x++) if (x + W * y < rate_lanes) a[x][y] = 1;
    printf("Rate lanes = %d, capacity lanes = %d\n", rate_lanes, 25 - rate_lanes);
    printf("After absorbing P0 (1 = nonzero lane, rows are y, columns are x):\n"); show(a);
    do {
        int c[W], d[W];
        round++;
        for (x = 0; x < W; x++) { c[x] = 0; for (y = 0; y < W; y++) c[x] |= a[x][y]; }
        for (x = 0; x < W; x++) d[x] = c[(x + 4) % W] | c[(x + 1) % W];
        for (x = 0; x < W; x++) for (y = 0; y < W; y++) a[x][y] |= d[x];
        printf("After theta of round %d:\n", round); show(a);
        all = 1;
        for (y = 0; y < W; y++) for (x = 0; x < W; x++) if (!a[x][y]) all = 0;
    } while (!all && round < 24);
    printf("\nAll capacity lanes contain a nonzero bit after %d round%s (the theta step of the first round).\n",
           round, round == 1 ? "" : "s");
    printf("Reason: each column x has nonzero lanes in rows y=0..2, so every column parity C[x] is\n");
    printf("nonzero; theta XORs C[x-1] ^ rot(C[x+1]) into every lane, including the capacity lanes.\n");
    return 0;
}
