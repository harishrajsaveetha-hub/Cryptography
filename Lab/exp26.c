/* Experiment 26: Bob leaks his RSA private key d and picks a NEW (e', d') with the SAME n.
 * IS THIS SAFE?  NO. Knowing (e, d) lets anyone factor n: e*d - 1 is a multiple of phi(n),
 * and with it a nontrivial square root of 1 mod n is found (Miller-Rabin style), giving p, q.
 * Then phi(n) is known and the new private key d' follows from the new public e'.
 * Compile: gcc exp26.c -o exp26      Run: ./exp26
 */
#include <stdio.h>

typedef unsigned long long ull;
typedef unsigned __int128 u128;

ull gcd(ull a, ull b) { return b ? gcd(b, a % b) : a; }
ull mulmod(ull a, ull b, ull m) { return (u128)a * b % m; }
ull power(ull b, ull e, ull m) { ull r = 1; b %= m; while (e) { if (e & 1) r = mulmod(r, b, m); b = mulmod(b, b, m); e >>= 1; } return r; }
long long inv(long long a, long long m) { long long t = 0, nt = 1, r = m, nr = a % m; while (nr) { long long q = r / nr, tmp = t - q * nt; t = nt; nt = tmp; tmp = r - q * nr; r = nr; nr = tmp; } return t < 0 ? t + m : t; }

int main(void) {
    ull n = 3599, e = 31, d = 3031, newe = 7;
    printf("Enter n, e, leaked d [3599 31 3031]: ");
    if (scanf("%llu %llu %llu", &n, &e, &d) != 3) { n = 3599; e = 31; d = 3031; }
    printf("Bob's NEW public exponent e' (coprime to phi) [7]: ");
    if (scanf("%llu", &newe) != 1) newe = 7;

    ull k = e * d - 1, r = k; int t = 0;
    while (r % 2 == 0) { r /= 2; t++; }
    printf("\ne*d - 1 = %llu = 2^%d * %llu\n", k, t, r);
    ull p = 0;
    for (ull g = 2; g < n && !p; g++) {
        ull x = power(g, r, n);
        if (x == 1 || x == n - 1) continue;
        for (int i = 0; i < t; i++) {
            ull y = mulmod(x, x, n);
            if (y == 1) { ull f = gcd(x - 1, n); if (f > 1 && f < n) { p = f; } break; }
            if (y == n - 1) break;
            x = y;
        }
    }
    if (!p) { puts("Failed to factor (check inputs)"); return 1; }
    ull q = n / p, phi = (p - 1) * (q - 1);
    printf("Attacker factors n = %llu x %llu using only (n, e, d)\n", p, q);
    printf("phi(n) = %llu\n", phi);
    if (gcd(newe, phi) != 1) { puts("e' not coprime to phi"); return 1; }
    ull newd = inv(newe, phi);
    printf("Bob's new keys: e' = %llu, d' = %llu (secret)\n", newe, newd);
    printf("Attacker computes d' from the PUBLIC e' = %llu  ->  d' = %llu\n", newe, inv(newe, phi));
    printf("\nConclusion: NOT safe - a leaked private key forces a new modulus n.\n");
    return 0;
}
