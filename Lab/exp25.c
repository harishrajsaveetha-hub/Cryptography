/* Experiment 25: RSA - what if a plaintext block shares a common factor with n?
 * If gcd(m, n) = p > 1 then p also divides c = m^e mod n, so gcd(c, n) = p reveals a
 * prime factor of n. n is then factored, phi(n) and the private key d are computed and
 * ALL blocks can be decrypted. YES, it helps - it completely breaks the system.
 * Compile: gcc exp25.c -o exp25      Run: ./exp25
 */
#include <stdio.h>

typedef long long ll;

ll gcd(ll a, ll b) { return b ? gcd(b, a % b) : a; }
ll power(ll b, ll e, ll m) { ll r = 1; b %= m; while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; } return r; }
ll inv(ll a, ll m) { ll t = 0, nt = 1, r = m, nr = a % m; while (nr) { ll q = r / nr, tmp = t - q * nt; t = nt; nt = tmp; tmp = r - q * nr; r = nr; nr = tmp; } return t < 0 ? t + m : t; }

int main(void) {
    ll n = 3599, e = 31, c[50], m[50], i, cnt, mode;
    printf("1. Demo (toy RSA n=3599, e=31, blocks 1000 118 2500 3000)\n2. Enter my own n, e and ciphertext blocks\nChoice: ");
    scanf("%lld", &mode);
    if (mode == 2) {
        printf("n e: "); scanf("%lld %lld", &n, &e);
        printf("Number of ciphertext blocks: "); scanf("%lld", &cnt);
        for (i = 0; i < cnt; i++) scanf("%lld", &c[i]);
    } else {
        ll pt[4] = {1000, 118, 2500, 3000};   /* 118 = 2*59 shares the factor 59 with n */
        cnt = 4;
        for (i = 0; i < cnt; i++) { c[i] = power(pt[i], e, n); printf("P=%lld -> C=%lld\n", pt[i], c[i]); }
    }
    for (i = 0; i < cnt; i++) {
        ll g = gcd(c[i], n);
        if (g > 1 && g < n) {
            ll p = g, q = n / g, phi = (p - 1) * (q - 1), d = inv(e, phi);
            printf("\nBlock %lld: gcd(C, n) = %lld  => n = %lld x %lld\n", i + 1, g, p, q);
            printf("phi(n) = %lld, private key d = %lld\nDecrypted blocks: ", phi, d);
            for (ll j = 0; j < cnt; j++) { m[j] = power(c[j], d, n); printf("%lld ", m[j]); }
            printf("\n=> The whole message is recovered: the attack succeeds.\n");
            return 0;
        }
    }
    printf("\nNo ciphertext block shares a factor with n.\n");
    return 0;
}
