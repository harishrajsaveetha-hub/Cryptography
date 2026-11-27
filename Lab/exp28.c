/* Experiment 28: What if Diffie-Hellman sent x^a mod q (instead of a^x mod q)?
 * Each party sends  y = x^a mod q  for a public number a (gcd(a, q-1) = 1).
 * - Anyone can compute a' = a^-1 mod (q-1) quickly, and then  y^a' = x^(a*a') = x (mod q).
 * - So Alice and Bob can recover each other's secret and agree on e.g.  K = xA * xB mod q.
 * - But EVE can do exactly the same: she finds the secret numbers AND the key without any
 *   effort. The system is worthless. In real DH, y = a^x is a discrete log problem (hard);
 *   here it is just an e-th root problem with a known inverse exponent (easy).
 * Compile: gcc exp28.c -o exp28      Run: ./exp28
 */
#include <stdio.h>

typedef unsigned long long ull;
typedef long long ll;
typedef unsigned __int128 u128;

ull power(ull b, ull e, ull m) { ull r = 1; b %= m; while (e) { if (e & 1) r = (u128)r * b % m; b = (u128)b * b % m; e >>= 1; } return r; }
ull gcd(ull a, ull b) { return b ? gcd(b, a % b) : a; }
ull inv(ull a, ull m) { ll t = 0, nt = 1, r = m, nr = a % m; while (nr) { ll q = r / nr, tmp = t - q * nt; t = nt; nt = tmp; tmp = r - q * nr; r = nr; nr = tmp; } return t < 0 ? t + m : t; }

int main(void) {
    ull q = 2147483647ULL, a = 5, xa = 123456, xb = 654321;
    printf("Prime q [2147483647], public a [5], Alice secret xA, Bob secret xB: ");
    if (scanf("%llu %llu %llu %llu", &q, &a, &xa, &xb) != 4) { q = 2147483647ULL; a = 5; xa = 123456; xb = 654321; }
    if (gcd(a, q - 1) != 1) { puts("Choose a with gcd(a, q-1) = 1 so x -> x^a is one-to-one"); return 1; }
    ull ya = power(xa, a, q), yb = power(xb, a, q);
    printf("\nAlice sends yA = xA^a mod q = %llu\nBob   sends yB = xB^a mod q = %llu\n", ya, yb);
    ull ai = inv(a, q - 1);
    printf("\nInverse exponent a' = a^-1 mod (q-1) = %llu\n", ai);
    ull xb_found = power(yb, ai, q), xa_found = power(ya, ai, q);
    printf("Alice recovers Bob's secret: %llu\nBob recovers Alice's secret: %llu\n", xb_found, xa_found);
    ull keyA = (u128)xa * xb_found % q, keyB = (u128)xb * xa_found % q;
    printf("Shared key (K = xA*xB mod q): Alice=%llu  Bob=%llu  %s\n", keyA, keyB, keyA == keyB ? "(agree)" : "(DIFFER)");
    printf("\n--- Eve (sees only q, a, yA, yB) ---\n");
    ull ea = power(ya, ai, q), eb = power(yb, ai, q);
    printf("Eve finds secrets xA = %llu, xB = %llu\n", ea, eb);
    printf("Eve computes the key = %llu  -> %s\n", (ull)((u128)ea * eb % q), (ull)((u128)ea * eb % q) == keyA ? "SAME as Alice/Bob" : "different");
    printf("\nAnswers: Eve CAN break it without any secret search; Eve CAN find the secret numbers.\n");
    return 0;
}
