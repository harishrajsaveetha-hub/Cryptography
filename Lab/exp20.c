/* Experiment 20: Error propagation in CBC (demonstrated with S-DES, 8-bit blocks)
 * a) A bit error in ciphertext block C1 garbles P1 completely and flips ONE bit of P2
 *    (same position as the error). P3, P4, ... are NOT affected.
 * b) A bit error in plaintext P1 (at the source) changes C1 and, through chaining, EVERY
 *    following ciphertext block (C1..Cn). At the receiver the (valid) ciphertext decrypts
 *    correctly to the erroneous P1 only - blocks P2..Pn are recovered correctly.
 * Compile: gcc exp20.c -o exp20      Run: ./exp20
 */
#include <stdio.h>
#include <string.h>
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


#define N 6
static void cbc_enc(const unsigned *p, unsigned *c, unsigned iv, unsigned k1, unsigned k2) {
    unsigned prev = iv; int i;
    for (i = 0; i < N; i++) { c[i] = sdes_enc(p[i] ^ prev, k1, k2); prev = c[i]; }
}
static void cbc_dec(const unsigned *c, unsigned *p, unsigned iv, unsigned k1, unsigned k2) {
    unsigned prev = iv; int i;
    for (i = 0; i < N; i++) { p[i] = sdes_dec(c[i], k1, k2) ^ prev; prev = c[i]; }
}
static void show(const char *name, const unsigned *v, const unsigned *ref) {
    int i; printf("%-22s", name);
    for (i = 0; i < N; i++) printf(" %02X%s", v[i], (ref && v[i] != ref[i]) ? "*" : " ");
    printf("\n");
}

int main(void) {
    unsigned k1, k2, iv = 0xAA, key = 0x1FD;
    unsigned P[N] = {0x41, 0x42, 0x43, 0x44, 0x45, 0x46}, C[N], R[N], C2[N], P2[N];
    sdes_keys(key, &k1, &k2);
    printf("(* marks blocks that differ from the error-free value)\n\n");
    cbc_enc(P, C, iv, k1, k2);
    show("Plaintext", P, NULL); show("Ciphertext", C, NULL);

    printf("\n--- a) one bit error in ciphertext block C1 ---\n");
    memcpy(C2, C, sizeof C); C2[0] ^= 0x10;
    show("Received ciphertext", C2, C);
    cbc_dec(C2, R, iv, k1, k2);
    show("Decrypted plaintext", R, P);
    printf("=> P1 is garbled, P2 has a single-bit error, P3.. are correct (no error beyond P2).\n");

    printf("\n--- b) one bit error in source plaintext P1 ---\n");
    memcpy(P2, P, sizeof P); P2[0] ^= 0x01;
    cbc_enc(P2, C2, iv, k1, k2);
    show("Ciphertext", C2, C);
    cbc_dec(C2, R, iv, k1, k2);
    show("Receiver's plaintext", R, P);
    printf("=> The error propagates through ALL ciphertext blocks (C1..C%d); the receiver\n   decrypts correctly, so only P1 (the original error) is wrong.\n", N);
    return 0;
}
