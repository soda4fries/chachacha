#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include "../../chacha20poly1305.h"

static int evp_seal(uint8_t *c, uint8_t t[16], const uint8_t *p, size_t n,
                    const uint8_t *a, size_t al, const uint8_t *k, const uint8_t *iv) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new();
    int l = 0, ok = 0;
    if (EVP_EncryptInit_ex(x, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(x, NULL, NULL, k, iv) == 1 &&
        (!al || EVP_EncryptUpdate(x, NULL, &l, a, (int)al) == 1) &&
        EVP_EncryptUpdate(x, c, &l, p, (int)n) == 1 &&
        EVP_EncryptFinal_ex(x, c + l, &l) == 1 &&
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, t) == 1) ok = 1;
    EVP_CIPHER_CTX_free(x);
    return ok;
}

static uint8_t pt[8192], ct[8300], rt[8300], ref[8300], reftag[16], k[32], iv[12], ad[32];

static int one(size_t L, size_t A) {
    size_t on = 0;
    if (!evp_seal(ref, reftag, pt, L, ad, A, k, iv)) { printf("EVP failed L=%zu\n", L); return 1; }
    if (!chacha20_poly1305_seal(ct, &on, sizeof ct, pt, L, ad, A, k, iv) || on != L + 16) {
        printf("seal refused L=%zu A=%zu\n", L, A); return 1; }
    if (memcmp(ct, ref, L)) { printf("ciphertext differs L=%zu A=%zu\n", L, A); return 1; }
    if (memcmp(ct + L, reftag, 16)) { printf("tag differs L=%zu A=%zu\n", L, A); return 1; }
    if (!chacha20_poly1305_open(rt, &on, sizeof rt, ct, L + 16, ad, A, k, iv) ||
        on != L || memcmp(rt, pt, L)) { printf("open failed L=%zu A=%zu\n", L, A); return 1; }
    memcpy(rt, ct, L + 16);
    if (!chacha20_poly1305_open(rt, &on, sizeof rt, rt, L + 16, ad, A, k, iv) ||
        on != L || memcmp(rt, pt, L)) { printf("in-place open failed L=%zu A=%zu\n", L, A); return 1; }
    ct[L / 2] ^= 1;
    if (chacha20_poly1305_open(rt, &on, sizeof rt, ct, L + 16, ad, A, k, iv)) {
        printf("forgery ACCEPTED L=%zu A=%zu\n", L, A); return 1; }
    ct[L / 2] ^= 1;
    return 0;
}

int main(void) {
    static const size_t ads[] = {0, 1, 13, 16, 17, 32};
    size_t n = 0, bad = 0;
    for (size_t i = 0; i < sizeof pt; i++) pt[i] = (uint8_t)(i * 29 + 7);
    for (size_t i = 0; i < sizeof ad; i++) ad[i] = (uint8_t)(i * 17 + 3);
    for (size_t i = 0; i < sizeof k; i++) k[i] = (uint8_t)(i * 11 + 5);
    for (size_t i = 0; i < sizeof iv; i++) iv[i] = (uint8_t)(i * 13 + 1);
    printf("avx512=%d\n", chacha20_poly1305_using_avx512());
    for (size_t ai = 0; ai < sizeof ads / sizeof *ads; ai++) {
        for (size_t L = 0; L <= 1200; L++)      { n++; bad += one(L, ads[ai]); }
        for (size_t L = 2000; L <= 2700; L++)   { n++; bad += one(L, ads[ai]); }
        for (size_t L = 3050; L <= 3120; L++)   { n++; bad += one(L, ads[ai]); }
    }
    printf("%zu cases, %zu failures\n", n, bad);
    return bad != 0;
}
