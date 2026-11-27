/* Experiment 16: Letter-frequency attack on ANY monoalphabetic substitution cipher
 * (no human intervention). Method: start from a frequency-rank key, then hill-climb
 * (swap two key letters while the English fitness improves) from many random restarts.
 * Fitness = log-likelihood under an English letter/bigram/trigram model learned from
 * a built-in training text.
 * Output: top N distinct candidate plaintexts, best first.
 * Note: reliable for ciphertexts of roughly 100+ letters.
 * Compile: gcc exp16.c -o exp16 -lm      Run: ./exp16
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <math.h>
#include <time.h>

#define MAXT 5000
#define MAXC 600

/* Small built-in English training text: letter, bigram and trigram statistics are
 * learned from it at start-up (more text = better model). */
static const char *CORPUS =
 "THE QUICK BROWN FOX JUMPS OVER THE LAZY DOG AND THEN RUNS ACROSS THE FIELD TO FIND SOMETHING TO EAT "
 "IT IS A TRUTH UNIVERSALLY ACKNOWLEDGED THAT A SINGLE MAN IN POSSESSION OF A GOOD FORTUNE MUST BE IN WANT OF A WIFE "
 "HOWEVER LITTLE KNOWN THE FEELINGS OR VIEWS OF SUCH A MAN MAY BE ON HIS FIRST ENTERING A NEIGHBOURHOOD THIS TRUTH IS SO WELL FIXED "
 "IN THE MINDS OF THE SURROUNDING FAMILIES THAT HE IS CONSIDERED THE RIGHTFUL PROPERTY OF SOME ONE OR OTHER OF THEIR DAUGHTERS "
 "IN THE BEGINNING GOD CREATED THE HEAVEN AND THE EARTH AND THE EARTH WAS WITHOUT FORM AND VOID AND DARKNESS WAS UPON THE FACE OF THE DEEP "
 "ALL HUMAN BEINGS ARE BORN FREE AND EQUAL IN DIGNITY AND RIGHTS THEY ARE ENDOWED WITH REASON AND CONSCIENCE AND SHOULD ACT TOWARDS ONE ANOTHER "
 "IN A SPIRIT OF BROTHERHOOD EVERYONE HAS THE RIGHT TO LIFE LIBERTY AND SECURITY OF PERSON "
 "WE HOLD THESE TRUTHS TO BE SELF EVIDENT THAT ALL MEN ARE CREATED EQUAL THAT THEY ARE ENDOWED BY THEIR CREATOR WITH CERTAIN RIGHTS "
 "CRYPTOGRAPHY IS THE PRACTICE AND STUDY OF TECHNIQUES FOR SECURE COMMUNICATION IN THE PRESENCE OF THIRD PARTIES CALLED ADVERSARIES "
 "THE SENDER ENCRYPTS THE MESSAGE USING A KEY AND THE RECEIVER DECRYPTS THE CIPHERTEXT TO RECOVER THE ORIGINAL PLAINTEXT MESSAGE "
 "A SUBSTITUTION CIPHER REPLACES EACH LETTER OF THE PLAINTEXT WITH ANOTHER LETTER AND THE FREQUENCY OF LETTERS IN THE ENGLISH LANGUAGE "
 "CAN BE USED TO BREAK THE CIPHER BECAUSE THE LETTER E IS THE MOST COMMON LETTER FOLLOWED BY T A O I N S H AND R "
 "WHEN THE MORNING CAME THEY WENT DOWN TO THE RIVER AND WATCHED THE BOATS PASS BY WHILE THE CHILDREN PLAYED IN THE WATER AND THE OLD MEN TALKED "
 "ABOUT THE WEATHER AND THE PRICE OF GRAIN AND WHAT THE GOVERNMENT WOULD DO NEXT YEAR IF THERE WERE NO RAIN "
 "THERE WAS NOTHING FOR IT BUT TO WAIT UNTIL THE STORM HAD PASSED AND THEN TO SEARCH THE HOUSE FROM THE ATTIC TO THE CELLAR FOR ANY SIGN OF THEM "
 "THIS MESSAGE WILL BE SENT TO YOU WITH INSTRUCTIONS ON WHERE AND WHEN WE SHOULD MEET AND WHAT YOU MUST BRING WITH YOU TO THE PLACE "
 "INFORMATION SECURITY REQUIRES CONFIDENTIALITY INTEGRITY AND AVAILABILITY AND THESE THREE GOALS ARE ACHIEVED BY CAREFUL USE OF MANY MECHANISMS "
 "I THINK THAT HE WOULD HAVE BEEN VERY GLAD TO SEE US BUT THERE WERE SO MANY THINGS TO DO THAT WE DID NOT HAVE ANY TIME LEFT FOR VISITING";

static double lp[26][26][26];   /* log P(next | previous two letters) */

void train(void) {
    static double c1[26], c2[26][26], c3[26][26][26];
    int i, a, b, c, p[3] = {0, 0, 0}, k = 0;
    double tot = 0;
    for (i = 0; CORPUS[i]; i++) {
        if (!isalpha((unsigned char)CORPUS[i])) continue;
        p[0] = p[1]; p[1] = p[2]; p[2] = CORPUS[i] - 'A'; k++;
        c1[p[2]]++; tot++;
        if (k >= 2) c2[p[1]][p[2]]++;
        if (k >= 3) c3[p[0]][p[1]][p[2]]++;
    }
    for (a = 0; a < 26; a++) for (b = 0; b < 26; b++) {
        double s2 = 0, s3 = 0;
        for (c = 0; c < 26; c++) { s2 += c2[b][c]; s3 += c3[a][b][c]; }
        for (c = 0; c < 26; c++) {
            double p1 = (c1[c] + 1) / (tot + 26);
            double p2 = (c2[b][c] + 0.5) / (s2 + 13);
            double p3 = s3 > 0 ? c3[a][b][c] / s3 : 0;
            double w3 = s3 > 3 ? 0.35 : 0.0;
            lp[a][b][c] = log(0.15 * p1 + (0.85 - w3) * p2 + w3 * p3);
        }
    }
}

static int ct[MAXT], n;
static char orig[MAXT + 10];

typedef struct { int key[26]; double score; } Cand;   /* key[cipher letter] = plain letter */
static Cand pool[MAXC];
static int npool = 0;

double fit(const int *key) {
    static int p[MAXT];
    int i; double s = 0;
    for (i = 0; i < n; i++) p[i] = key[ct[i]];
    for (i = 2; i < n; i++) s += lp[p[i - 2]][p[i - 1]][p[i]];
    return s;
}

void climb(int *key) {
    double best = fit(key);
    int improved = 1, i, j;
    while (improved) {
        improved = 0;
        for (i = 0; i < 25; i++) for (j = i + 1; j < 26; j++) {
            int t = key[i]; key[i] = key[j]; key[j] = t;
            double f = fit(key);
            if (f > best + 1e-9) { best = f; improved = 1; }
            else { t = key[i]; key[i] = key[j]; key[j] = t; }
        }
    }
}

int cmp(const void *a, const void *b) {
    double d = ((const Cand *)b)->score - ((const Cand *)a)->score;
    return (d > 0) - (d < 0);
}

int main(void) {
    int i, j, r, top, cnt[26] = {0}, order[26], restarts;
    const char *eng = "ETAOINSHRDLCUMWFGYPBVKJXQZ";
    char line[MAXT];
    srand((unsigned)time(NULL));
    train();

    printf("Enter ciphertext (one line): ");
    fgets(line, sizeof line, stdin);
    line[strcspn(line, "\n")] = 0;
    strncpy(orig, line, MAXT);
    for (i = 0; line[i] && n < MAXT; i++) if (isalpha((unsigned char)line[i])) ct[n++] = toupper((unsigned char)line[i]) - 'A';
    if (n < 20) { puts("Ciphertext too short to attack."); return 1; }
    printf("How many top plaintexts do you want? ");
    scanf("%d", &top);
    if (top < 1) top = 1;

    for (i = 0; i < n; i++) cnt[ct[i]]++;
    for (i = 0; i < 26; i++) order[i] = i;
    for (i = 0; i < 26; i++) for (j = i + 1; j < 26; j++) if (cnt[order[j]] > cnt[order[i]]) { int t = order[i]; order[i] = order[j]; order[j] = t; }
    int base[26];
    for (i = 0; i < 26; i++) base[order[i]] = eng[i] - 'A';

    restarts = 8000000 / (n * 40 + 1); if (restarts < 60) restarts = 60;
    if (restarts > 400) restarts = 400;
    for (r = 0; r < restarts; r++) {
        Cand c;
        memcpy(c.key, base, sizeof base);
        if (r > 0) {
            int swaps = (r % 2) ? 100 : 3 + rand() % 20;   /* odd restarts: near-random key */
            while (swaps--) { int a = rand() % 26, b = rand() % 26, t = c.key[a]; c.key[a] = c.key[b]; c.key[b] = t; }
        }
        climb(c.key);
        c.score = fit(c.key);
        for (i = 0; i < npool; i++) if (!memcmp(pool[i].key, c.key, sizeof c.key)) break;
        if (i == npool && npool < MAXC) pool[npool++] = c;
    }
    qsort(pool, npool, sizeof(Cand), cmp);
    if (top > npool) top = npool;
    for (i = 0; i < top; i++) {
        printf("\n#%d (score %.1f)  key cipher->plain: ", i + 1, pool[i].score);
        for (j = 0; j < 26; j++) printf("%c%c ", 'A' + j, 'a' + pool[i].key[j]);
        printf("\n    ");
        for (j = 0; orig[j]; j++) putchar(isalpha((unsigned char)orig[j]) ? 'a' + pool[i].key[toupper((unsigned char)orig[j]) - 'A'] : orig[j]);
        printf("\n");
    }
    return 0;
}
