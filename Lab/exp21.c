/* Experiment 21: Padding for ECB, CBC and CFB modes
 * Method: append a 1 bit followed by as few 0 bits as needed (byte form: 0x80 00 00 ...).
 * Why pad EVERY message, even when the last block is already full?
 *   If padding were skipped for full blocks, the receiver could not tell whether a final
 *   byte pattern like 0x80 0x00.. is padding or genuine data. Always adding padding (a whole
 *   extra block when needed) makes removal unambiguous: strip trailing zeros, then the 0x80.
 * Compile: gcc exp21.c -o exp21      Run: ./exp21
 */
#include <stdio.h>
#include <string.h>

#define BS 8

int pad(const unsigned char *in, int len, unsigned char *out) {
    int n = len + 1;
    memcpy(out, in, len);
    out[len] = 0x80;
    while (n % BS) out[n++] = 0x00;
    return n;
}
int unpad(const unsigned char *in, int len) {
    while (len > 0 && in[len - 1] == 0x00) len--;
    if (len > 0 && in[len - 1] == 0x80) return len - 1;
    return -1;
}
void dump(const char *t, const unsigned char *b, int n) {
    int i; printf("%s", t); for (i = 0; i < n; i++) printf("%02X ", b[i]); printf("\n");
}

int main(void) {
    unsigned char out[200], msg[200];
    const char *tests[] = {"ABCDE", "ABCDEFGH", "ABCDEFGHIJKLMNOP"};
    int t, n, m;
    for (t = 0; t < 3; t++) {
        int len = strlen(tests[t]);
        n = pad((const unsigned char *)tests[t], len, out);
        printf("Message \"%s\" (%d bytes, %s)\n", tests[t], len, len % BS ? "partial last block" : "last block already full");
        dump("  padded : ", out, n);
        printf("  blocks : %d (added %d padding bytes)\n", n / BS, n - len);
        m = unpad(out, n); memcpy(msg, out, m); msg[m] = 0;
        printf("  unpadded: \"%s\"\n\n", msg);
    }
    /* ambiguity demo: data that looks like padding */
    unsigned char tricky[8] = {'A','B','C','D','E','F', 0x80, 0x00};
    printf("Ambiguity demo: genuine 8-byte data ending in 80 00 (no padding block added):\n");
    dump("  data       : ", tricky, 8);
    m = unpad(tricky, 8);
    printf("  receiver would strip it down to %d bytes -> data lost!\n", m);
    n = pad(tricky, 8, out); m = unpad(out, n);
    printf("  with an always-added padding block the receiver recovers all %d bytes.\n", m);
    return 0;
}
