/* Experiment 23: Counter (CTR) mode using S-DES
 *   C_i = P_i xor E_K(counter + i)     (encryption and decryption are identical)
 * Test data: counter starts at 0000 0000, key = 01111 11101,
 *   plaintext 0000 0001 0000 0010 0000 0100 -> ciphertext 0011 1000 0100 1111 0011 0010
 * Compile: gcc exp23.c -o exp23      Run: ./exp23
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


static void bits(unsigned v, int n) { int i; for (i = n - 1; i >= 0; i--) putchar('0' + ((v >> i) & 1)); }

static void ctr(unsigned key, unsigned counter, const unsigned *in, int n) {
    unsigned k1, k2; int i;
    sdes_keys(key, &k1, &k2);
    for (i = 0; i < n; i++) { bits(in[i] ^ sdes_enc((counter + i) & 0xFF, k1, k2), 8); putchar(' '); }
    printf("\n");
}

int main(void) {
    char line[600]; unsigned key = 0, cnt = 0, blk[64], all = 0; int n = 0, total = 0, i, mode;
    printf("1. Encrypt/Decrypt (same operation)  2. Run built-in test\nChoice: ");
    scanf("%d", &mode); getchar();
    if (mode == 2) {
        unsigned p[3] = {0x01, 0x02, 0x04}, c[3] = {0x38, 0x4F, 0x32};
        printf("Encrypt 00000001 00000010 00000100 -> "); ctr(0x1FD, 0, p, 3);
        printf("Decrypt 00111000 01001111 00110010 -> "); ctr(0x1FD, 0, c, 3);
        return 0;
    }
    printf("10-bit key: "); fgets(line, sizeof line, stdin);
    for (i = 0; line[i]; i++) if (line[i] == '0' || line[i] == '1') key = (key << 1) | (line[i] - '0');
    printf("8-bit starting counter: "); fgets(line, sizeof line, stdin);
    for (i = 0; line[i]; i++) if (line[i] == '0' || line[i] == '1') cnt = (cnt << 1) | (line[i] - '0');
    printf("Input bits (multiple of 8): "); fgets(line, sizeof line, stdin);
    for (i = 0; line[i]; i++) if (line[i] == '0' || line[i] == '1') {
        all = (all << 1) | (line[i] - '0'); total++;
        if (total % 8 == 0) { blk[n++] = all & 0xFF; all = 0; }
    }
    if (total == 0 || total % 8) { puts("Length must be a multiple of 8 bits"); return 1; }
    printf("Output: "); ctr(key, cnt, blk, n);
    return 0;
}
