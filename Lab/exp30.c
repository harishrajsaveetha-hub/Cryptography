/* Experiment 30: CBC-MAC forgery for one-block messages (S-DES, 8-bit block, IV = 0)
 * Given T = MAC(K, X) for a one-block message X, the adversary immediately knows the MAC of
 * the two-block message X || (X xor T):
 *   C1 = E_K(X) = T ; C2 = E_K( (X xor T) xor C1 ) = E_K(X) = T   -> same tag T.
 * Compile: gcc exp30.c -o exp30      Run: ./exp30
 */
#include <stdio.h>
#include <stdint.h>

static const int P10[10] = {3,5,2,7,4,10,1,9,8,6};
static const int P8[8]   = {6,3,7,4,8,5,10,9};
static const int IP8[8]  = {2,6,3,1,4,8,5,7};
static const int IPI8[8] = {4,1,3,5,7,2,8,6};
static const int EP[8]   = {4,1,2,3,2,3,4,1};
static const int P4[4]   = {2,4,3,1};
static const int S0[4][4] = {{1,0,3,2},{3,2,1,0},{0,2,1,3},{3,1,3,2}};
static const int S1[4][4] = {{0,1,2,3},{2,0,1,3},{3,0,1,0},{2,1,0,3}};

static unsigned permute(unsigned in, int inbits, const int *tbl, int outbits) {
    unsigned out = 0; int i;
    for (i = 0; i < outbits; i++) out = (out << 1) | ((in >> (inbits - tbl[i])) & 1);
    return out;
}
static unsigned rotl5(unsigned v, int s) { return ((v << s) | (v >> (5 - s))) & 0x1F; }

static void sdes_keys(unsigned key10, unsigned *k1, unsigned *k2) {
    unsigned p = permute(key10, 10, P10, 10), L = p >> 5, R = p & 0x1F;
    L = rotl5(L, 1); R = rotl5(R, 1);
    *k1 = permute((L << 5) | R, 10, P8, 8);
    L = rotl5(L, 2); R = rotl5(R, 2);
    *k2 = permute((L << 5) | R, 10, P8, 8);
}
static unsigned sdes_F(unsigned R, unsigned k) {
    unsigned e = permute(R, 4, EP, 8) ^ k, l = e >> 4, r = e & 0xF;
    unsigned s0 = S0[((l >> 3) & 1) * 2 + (l & 1)][((l >> 2) & 1) * 2 + ((l >> 1) & 1)];
    unsigned s1 = S1[((r >> 3) & 1) * 2 + (r & 1)][((r >> 2) & 1) * 2 + ((r >> 1) & 1)];
    return permute((s0 << 2) | s1, 4, P4, 4);
}
static unsigned sdes_fk(unsigned in, unsigned k) {
    unsigned L = in >> 4, R = in & 0xF;
    return ((L ^ sdes_F(R, k)) << 4) | R;
}
static unsigned sdes_enc_rev(unsigned ct, unsigned k1, unsigned k2);
static unsigned sdes_enc(unsigned pt, unsigned k1, unsigned k2) {
    unsigned x = permute(pt, 8, IP8, 8);
    x = sdes_fk(x, k1);
    x = ((x << 4) | (x >> 4)) & 0xFF;
    x = sdes_fk(x, k2);
    return permute(x, 8, IPI8, 8);
}
static unsigned sdes_dec(unsigned ct, unsigned k1, unsigned k2) { return sdes_enc_rev(ct, k1, k2); }
static unsigned sdes_enc_rev(unsigned ct, unsigned k1, unsigned k2) {
    return sdes_enc(ct, k2, k1);   /* S-DES is a Feistel network: decrypt = encrypt with keys swapped */
}


static unsigned cbc_mac(const unsigned *m, int n, unsigned k1, unsigned k2) {
    unsigned c = 0; int i;
    for (i = 0; i < n; i++) c = sdes_enc(m[i] ^ c, k1, k2);
    return c;
}
static void bits(unsigned v) { int i; for (i = 7; i >= 0; i--) putchar('0' + ((v >> i) & 1)); }

int main(void) {
    unsigned key = 0x1FD, X = 0x5A, k1, k2;
    printf("10-bit key as number [509 = 0111111101], one-block message X (0-255) [90]: ");
    if (scanf("%u %u", &key, &X) != 2) { key = 0x1FD; X = 0x5A; }
    key &= 0x3FF; X &= 0xFF;
    sdes_keys(key, &k1, &k2);
    unsigned T = cbc_mac(&X, 1, k1, k2);
    printf("\nOracle: T = MAC(K, X) = "); bits(T); printf("  for X = "); bits(X);
    unsigned two[2] = {X, X ^ T};
    printf("\nForged message: X || (X xor T) = "); bits(two[0]); putchar(' '); bits(two[1]);
    printf("\nForged tag claimed by adversary (= T)      : "); bits(T);
    printf("\nReal CBC-MAC of the two-block message      : "); bits(cbc_mac(two, 2, k1, k2));
    printf("\n=> %s\n", cbc_mac(two, 2, k1, k2) == T ? "They are equal: forgery succeeds without knowing K." : "mismatch");
    return 0;
}
