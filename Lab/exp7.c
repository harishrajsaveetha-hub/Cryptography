/* Experiment 7: Decrypt a simple substitution cipher (Poe's "Gold-Bug" style cryptogram)
 * Symbols are written in ASCII:  ‡ -> #   † -> @   ¶ -> &   — -> -
 * Steps used (see comments): 1) frequency count, 2) most common symbol 8 = e,
 * 3) the trigram ;48 = "the" gives ; = t, 4 = h, 4) deduce remaining words.
 * Compile: gcc exp7.c -o exp7      Run: ./exp7
 */
#include <stdio.h>
#include <string.h>

int main(void) {
    const char *cipher =
        "53##@305))6*;4826)4#.)4#);806*;48@8&60))85;;]8*;:#*8@83"
        "(88)5*@;46(;88*96*?;8)*#(;485);5*@2:*#(;4956*2(5*-4)8&8*"
        ";4069285);)6@8)4##;1(#9;48081;8:8#1;48@85;4)485@528806*81"
        "(#9;48;(88;4(#?34;48)4#;161;:188;#?;";
    /* substitution table, derived by frequency analysis */
    const char *sym = "52-@81346.0*9#(;)?&]:";
    const char *pla = "abcdefghilmnoprstuvwy";   /* will be re-ordered below */
    char map[128];
    int cnt[128] = {0}, i;
    memset(map, '_', sizeof map);
    map['5']='a'; map['2']='b'; map['-']='c'; map['@']='d'; map['8']='e'; map['1']='f';
    map['3']='g'; map['4']='h'; map['6']='i'; map['0']='l'; map['9']='m'; map['*']='n';
    map['#']='o'; map['.']='p'; map['(']='r'; map[')']='s'; map[';']='t'; map['?']='u';
    map['&']='v'; map[']']='w'; map[':']='y';
    (void)sym; (void)pla;

    printf("Ciphertext:\n%s\n\nFrequency of symbols:\n", cipher);
    for (i = 0; cipher[i]; i++) cnt[(int)cipher[i]]++;
    for (i = 0; i < 128; i++) if (cnt[i]) printf("%c:%d  ", i, cnt[i]);
    printf("\n\nSymbol -> letter key:\n");
    for (i = 0; i < 128; i++) if (cnt[i]) printf("%c=%c ", i, map[i]);
    printf("\n\nPlaintext:\n");
    for (i = 0; cipher[i]; i++) putchar(map[(int)cipher[i]]);
    printf("\n");
    return 0;
}
