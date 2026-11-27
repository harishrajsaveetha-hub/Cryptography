/* Experiment 17: DES decryption key schedule
 * For decryption the 16 subkeys are used in reverse order (K16..K1). They can be generated
 * directly with a modified schedule: no shift in round 1, then RIGHT circular shifts of
 *     0 1 2 2 2 2 2 2 1 2 2 2 2 2 2 1
 * (round 1 gives K16 because the 16 left shifts total 28 = full rotation).
 * Compile: gcc exp17.c -o exp17      Run: ./exp17
 */
#include <stdio.h>
#include <stdint.h>

static const int IP[64] = {58,50,42,34,26,18,10,2,60,52,44,36,28,20,12,4,62,54,46,38,30,22,14,6,64,56,48,40,32,24,16,8,
    57,49,41,33,25,17,9,1,59,51,43,35,27,19,11,3,61,53,45,37,29,21,13,5,63,55,47,39,31,23,15,7};
static const int FP[64] = {40,8,48,16,56,24,64,32,39,7,47,15,55,23,63,31,38,6,46,14,54,22,62,30,37,5,45,13,53,21,61,29,
    36,4,44,12,52,20,60,28,35,3,43,11,51,19,59,27,34,2,42,10,50,18,58,26,33,1,41,9,49,17,57,25};
static const int EXP[48] = {32,1,2,3,4,5,4,5,6,7,8,9,8,9,10,11,12,13,12,13,14,15,16,17,
    16,17,18,19,20,21,20,21,22,23,24,25,24,25,26,27,28,29,28,29,30,31,32,1};
static const int PP[32] = {16,7,20,21,29,12,28,17,1,15,23,26,5,18,31,10,2,8,24,14,32,27,3,9,19,13,30,6,22,11,4,25};
static const int PC1[56] = {57,49,41,33,25,17,9,1,58,50,42,34,26,18,10,2,59,51,43,35,27,19,11,3,60,52,44,36,
    63,55,47,39,31,23,15,7,62,54,46,38,30,22,14,6,61,53,45,37,29,21,13,5,28,20,12,4};
static const int PC2[48] = {14,17,11,24,1,5,3,28,15,6,21,10,23,19,12,4,26,8,16,7,27,20,13,2,
    41,52,31,37,47,55,30,40,51,45,33,48,44,49,39,56,34,53,46,42,50,36,29,32};
static const int SHIFTS[16] = {1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
static const int SBOX[8][64] = {
{14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
 4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13},
{15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
 0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9},
{10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
 13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12},
{7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
 10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14},
{2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
 4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3},
{12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
 9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13},
{4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
 1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12},
{13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
 7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11}};

/* generic bit permutation: table entries are 1-based from the MSB of an 'inbits'-wide value */
static uint64_t permute(uint64_t in, int inbits, const int *tbl, int outbits) {
    uint64_t out = 0; int i;
    for (i = 0; i < outbits; i++) out = (out << 1) | ((in >> (inbits - tbl[i])) & 1);
    return out;
}
static uint32_t rotl28(uint32_t v, int s) { return ((v << s) | (v >> (28 - s))) & 0x0FFFFFFF; }

static void des_subkeys(uint64_t key, uint64_t sk[16]) {
    uint64_t cd = permute(key, 64, PC1, 56);
    uint32_t C = (cd >> 28) & 0x0FFFFFFF, D = cd & 0x0FFFFFFF;
    int i;
    for (i = 0; i < 16; i++) {
        C = rotl28(C, SHIFTS[i]); D = rotl28(D, SHIFTS[i]);
        sk[i] = permute(((uint64_t)C << 28) | D, 56, PC2, 48);
    }
}
static uint32_t des_f(uint32_t R, uint64_t K) {
    uint64_t e = permute(R, 32, EXP, 48) ^ K;
    uint32_t out = 0; int i;
    for (i = 0; i < 8; i++) {
        int six = (e >> (42 - 6 * i)) & 0x3F;
        int row = ((six & 0x20) >> 4) | (six & 1), col = (six >> 1) & 0xF;
        out = (out << 4) | SBOX[i][row * 16 + col];
    }
    return (uint32_t)permute(out, 32, PP, 32);
}
/* decrypt = 1 uses the subkeys in reverse order */
static uint64_t des_block(uint64_t in, const uint64_t sk[16], int decrypt) {
    uint64_t ip = permute(in, 64, IP, 64);
    uint32_t L = ip >> 32, R = (uint32_t)ip, t; int i;
    for (i = 0; i < 16; i++) {
        t = R; R = L ^ des_f(R, sk[decrypt ? 15 - i : i]); L = t;
    }
    return permute(((uint64_t)R << 32) | L, 64, FP, 64);
}


static uint32_t rotr28(uint32_t v, int s) { return ((v >> s) | (v << (28 - s))) & 0x0FFFFFFF; }

int main(void) {
    static const int DSHIFT[16] = {0,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1};
    uint64_t key = 0x133457799BBCDFF1ULL, pt = 0x0123456789ABCDEFULL, enc[16], dec[16];
    char in[64];
    int i, ok = 1;
    printf("Enter 64-bit key in hex [133457799BBCDFF1]: ");
    if (fgets(in, sizeof in, stdin) && in[0] != '\n') sscanf(in, "%llx", (unsigned long long *)&key);

    des_subkeys(key, enc);                       /* encryption schedule: left shifts */
    uint64_t cd = permute(key, 64, PC1, 56);     /* decryption schedule: right shifts */
    uint32_t C = (cd >> 28) & 0x0FFFFFFF, D = cd & 0x0FFFFFFF;
    for (i = 0; i < 16; i++) {
        C = rotr28(C, DSHIFT[i]); D = rotr28(D, DSHIFT[i]);
        dec[i] = permute(((uint64_t)C << 28) | D, 56, PC2, 48);
    }
    printf("\nRound  Encryption subkey      Decryption subkey (right-shift schedule)\n");
    for (i = 0; i < 16; i++) {
        printf("%2d     %012llX          %012llX   %s\n", i + 1, (unsigned long long)enc[i],
               (unsigned long long)dec[i], dec[i] == enc[15 - i] ? "= K" : "MISMATCH");
        if (dec[i] != enc[15 - i]) ok = 0;
    }
    printf("\nDecryption subkey i equals encryption subkey 17-i : %s\n", ok ? "YES" : "NO");
    uint64_t c = des_block(pt, enc, 0);
    uint64_t p = des_block(c, dec, 0);           /* forward algorithm + new schedule = decryption */
    printf("Plaintext %016llX -> Ciphertext %016llX -> Decrypted (new schedule) %016llX\n",
           (unsigned long long)pt, (unsigned long long)c, (unsigned long long)p);
    return 0;
}
