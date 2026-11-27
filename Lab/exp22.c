/* Experiment 22: Cipher Block Chaining (CBC) mode using S-DES
 * Test data: IV = 1010 1010, key = 01111 11101,
 *   plaintext 0000 0001 0010 0011  ->  ciphertext 1111 0100 0000 1011
 * Compile: gcc exp22.c -o exp22      Run: ./exp22
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


static int read_bits(const char *s, unsigned *v, int max) {   /* returns number of bits read */
    int n = 0; *v = 0; (void)max;
    for (; *s; s++) if (*s == '0' || *s == '1') { *v = (*v << 1) | (*s - '0'); n++; }
    return n;
}
static void bits(unsigned v, int n) { int i; for (i = n - 1; i >= 0; i--) putchar('0' + ((v >> i) & 1)); }

static void run(int enc, unsigned key, unsigned iv, const unsigned *in, int n) {
    unsigned k1, k2, prev = iv, out; int i;
    sdes_keys(key, &k1, &k2);
    for (i = 0; i < n; i++) {
        if (enc) { out = sdes_enc(in[i] ^ prev, k1, k2); prev = out; }
        else     { out = sdes_dec(in[i], k1, k2) ^ prev; prev = in[i]; }
        bits(out, 8); putchar(' ');
    }
    printf("\n");
}

int main(void) {
    char line[600]; unsigned key, iv, blocks[64]; int mode, n = 0, i;
    printf("1. Encrypt  2. Decrypt  3. Run built-in test\nChoice: ");
    scanf("%d", &mode); getchar();
    if (mode == 3) {
        unsigned p[2] = {0x01, 0x23}, c[2] = {0xF4, 0x0B};
        printf("Encrypt 00000001 00100011 -> "); run(1, 0x1FD, 0xAA, p, 2);
        printf("Decrypt 11110100 00001011 -> "); run(0, 0x1FD, 0xAA, c, 2);
        return 0;
    }
    printf("10-bit key: ");   fgets(line, sizeof line, stdin); read_bits(line, &key, 10);
    printf("8-bit IV  : ");   fgets(line, sizeof line, stdin); read_bits(line, &iv, 8);
    printf("%s bits (multiple of 8, spaces allowed): ", mode == 1 ? "Plaintext" : "Ciphertext");
    fgets(line, sizeof line, stdin);
    unsigned all = 0; int total = 0, cnt = 0;
    for (i = 0; line[i]; i++) if (line[i] == '0' || line[i] == '1') {
        all = (all << 1) | (line[i] - '0'); total++;
        if (total % 8 == 0) { blocks[n++] = all & 0xFF; all = 0; }
    }
    (void)cnt;
    if (total == 0 || total % 8) { puts("Input length must be a multiple of 8 bits"); return 1; }
    printf("Result: "); run(mode == 1, key, iv, blocks, n);
    return 0;
}
