/* Experiment 24: RSA - find the private key for public key e = 31, n = 3599
 * Step 1: trial division to find p and q.  Step 2: phi = (p-1)(q-1).
 * Step 3: extended Euclid to get d = e^-1 mod phi.
 * Compile: gcc exp24.c -o exp24      Run: ./exp24
 */
#include <stdio.h>

typedef long long ll;

ll ext_gcd(ll a, ll b, ll *x, ll *y) {
    if (b == 0) { *x = 1; *y = 0; return a; }
    ll x1, y1, g = ext_gcd(b, a % b, &x1, &y1);
    *x = y1; *y = x1 - (a / b) * y1;
    return g;
}
ll power(ll b, ll e, ll m) { ll r = 1; b %= m; while (e) { if (e & 1) r = r * b % m; b = b * b % m; e >>= 1; } return r; }

int main(void) {
    ll e = 31, n = 3599, p = 0, q, phi, x, y, d, i;
    printf("Enter e and n [31 3599]: ");
    if (scanf("%lld %lld", &e, &n) != 2) { e = 31; n = 3599; }
    for (i = 2; i * i <= n; i++) if (n % i == 0) { p = i; break; }
    if (!p) { puts("n is prime - not a valid RSA modulus"); return 1; }
    q = n / p;
    phi = (p - 1) * (q - 1);
    printf("Trial division: n = %lld x %lld\nphi(n) = (%lld-1)(%lld-1) = %lld\n", p, q, p, q, phi);
    if (ext_gcd(e, phi, &x, &y) != 1) { puts("e is not coprime to phi(n)"); return 1; }
    d = ((x % phi) + phi) % phi;
    printf("Extended Euclid: %lld*%lld + %lld*%lld = 1\n", e, x, phi, y);
    printf("Private key d = %lld   (check: e*d mod phi = %lld)\n", d, (e * d) % phi);
    printf("Private key = {%lld, %lld}\n", d, n);
    ll m = 1234 % n, c = power(m, e, n);
    printf("Test: m=%lld -> c=%lld -> decrypted=%lld\n", m, c, power(c, d, n));
    return 0;
}
