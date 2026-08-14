// Copyright 2026 soda4fries
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/evp.h>
#include "../../chacha20poly1305.h"

#define MAXL 70000
static uint8_t pt[MAXL], ct[MAXL + 16], rt[MAXL + 16], ref[MAXL + 16], ad[64];
static unsigned seed = 0xC0FFEE;
static uint8_t rnd(void) { seed = seed * 1103515245u + 12345u; return (uint8_t)(seed >> 16); }

static int evp_seal(uint8_t *c, uint8_t t[16], const uint8_t *p, size_t n,
                    const uint8_t *a, size_t al, const uint8_t *k, const uint8_t *iv) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new(); int o = 0, ok = 0;
    if (EVP_EncryptInit_ex(x, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1 &&
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1 &&
        EVP_EncryptInit_ex(x, NULL, NULL, k, iv) == 1 &&
        (al == 0 || EVP_EncryptUpdate(x, NULL, &o, a, (int)al) == 1) &&
        (n == 0 || EVP_EncryptUpdate(x, c, &o, p, (int)n) == 1) &&
        EVP_EncryptFinal_ex(x, c + o, &o) == 1 &&
        EVP_CIPHER_CTX_ctrl(x, EVP_CTRL_AEAD_GET_TAG, 16, t) == 1) ok = 1;
    EVP_CIPHER_CTX_free(x); return ok;
}
static int evp_chacha(uint8_t *o_, const uint8_t *i_, size_t n,
                      const uint8_t *k, const uint8_t iv[16]) {
    EVP_CIPHER_CTX *x = EVP_CIPHER_CTX_new(); int o = 0, ok = 0;
    if (EVP_EncryptInit_ex(x, EVP_chacha20(), NULL, k, iv) == 1 &&
        (n == 0 || EVP_EncryptUpdate(x, o_, &o, i_, (int)n) == 1)) ok = 1;
    EVP_CIPHER_CTX_free(x); return ok;
}

static const size_t LENS[] = {0, 1, 15, 16, 17, 63, 64, 65, 127, 512, 576, 1023,
                              1024, 1025, 1420, 2048, 2049, 4096, 8191, 8192,
                              8193, 12288, 16384, 16385, 32768, 65535, 65536, 69999};
static const size_t ADS[] = {0, 1, 16, 17, 63};

static int run(const char *tag) {
    uint8_t k[32], iv12[12], iv16[16], t[16];
    int bad = 0, n = 0;

    for (int trial = 0; trial < 2; trial++) {
        for (int i = 0; i < 32; i++) k[i] = rnd();
        for (int i = 0; i < 12; i++) iv12[i] = rnd();
        for (int i = 0; i < 64; i++) ad[i] = rnd();
        for (int i = 0; i < MAXL; i++) pt[i] = rnd();

        for (unsigned li = 0; li < sizeof LENS / sizeof *LENS; li++) {
            for (unsigned ai = 0; ai < sizeof ADS / sizeof *ADS; ai++) {
                size_t L = LENS[li], A = ADS[ai], on = 0;
                n++;
                if (!evp_seal(ref, t, pt, L, ad, A, k, iv12)) { printf("EVP failed\n"); return 1; }
                memcpy(ref + L, t, 16);

                if (!chacha20_poly1305_seal(ct, &on, sizeof ct, pt, L, ad, A, k, iv12)) {
                    printf("  %s seal returned 0 at L=%zu\n", tag, L); bad++; continue;
                }
                if (on != L + 16 || memcmp(ct, ref, L + 16)) {
                    printf("  %s seal mismatch L=%zu A=%zu\n", tag, L, A); bad++;
                }
                if (!chacha20_poly1305_open(rt, &on, sizeof rt, ct, L + 16, ad, A, k, iv12) ||
                    on != L || (L && memcmp(rt, pt, L))) {
                    printf("  %s open mismatch L=%zu A=%zu\n", tag, L, A); bad++;
                }
                memcpy(rt, ct, L + 16);
                if (!chacha20_poly1305_open(rt, &on, sizeof rt, rt, L + 16, ad, A, k, iv12) ||
                    on != L || (L && memcmp(rt, pt, L))) {
                    printf("  %s in-place open failed L=%zu A=%zu\n", tag, L, A); bad++;
                }
                memcpy(rt, ct, L + 16); rt[L] ^= 0x40;
                if (chacha20_poly1305_open(rt, &on, sizeof rt, rt, L + 16, ad, A, k, iv12)) {
                    printf("  %s forged tag ACCEPTED L=%zu\n", tag, L); bad++;
                } else {
                    for (size_t i = 0; i < L; i++)
                        if (rt[i]) { printf("  %s output not zeroed on failure L=%zu\n", tag, L);
                                     bad++; break; }
                }
                {
                    uint8_t st[32]; size_t tl = 0;
                    if (!chacha20_poly1305_seal_scatter(rt, st, &tl, sizeof st,
                                                        pt, L, NULL, 0, ad, A, k, iv12) ||
                        tl != 16 || (L && memcmp(rt, ct, L)) || memcmp(st, ct + L, 16)) {
                        printf("  %s seal_scatter mismatch L=%zu A=%zu\n", tag, L, A); bad++;
                    }
                    if (!chacha20_poly1305_open_gather(rt, ct, L, ct + L, 16, ad, A, k, iv12) ||
                        (L && memcmp(rt, pt, L))) {
                        printf("  %s open_gather mismatch L=%zu A=%zu\n", tag, L, A); bad++;
                    }
                    if (chacha20_poly1305_seal_scatter(rt, st, &tl, sizeof st, pt, L,
                                                       (const uint8_t *)"\x17", 1,
                                                       ad, A, k, iv12)) {
                        printf("  %s extra_in ACCEPTED L=%zu\n", tag, L); bad++;
                    }
                    if (chacha20_poly1305_seal_scatter(rt, st, &tl, 15, pt, L,
                                                       NULL, 0, ad, A, k, iv12)) {
                        printf("  %s short out_tag ACCEPTED L=%zu\n", tag, L); bad++;
                    }
                    if (chacha20_poly1305_open_gather(rt, ct, L, ct + L, 15, ad, A, k, iv12)) {
                        printf("  %s wrong in_tag_len ACCEPTED L=%zu\n", tag, L); bad++;
                    }
                }
                if (chacha20_poly1305_open(rt, &on, sizeof rt, ct, 15, ad, A, k, iv12)) {
                    printf("  %s short input ACCEPTED\n", tag); bad++;
                }
                if (L && chacha20_poly1305_seal(ct, &on, L + 15, pt, L, ad, A, k, iv12)) {
                    printf("  %s undersized max_out ACCEPTED L=%zu\n", tag, L); bad++;
                }
            }
        }

        memcpy(iv16 + 4, iv12, 12);
        iv16[0] = 1; iv16[1] = iv16[2] = iv16[3] = 0;
        for (unsigned li = 0; li < sizeof LENS / sizeof *LENS; li++) {
            size_t L = LENS[li]; n++;
            if (!evp_chacha(ref, pt, L, k, iv16)) { printf("EVP failed\n"); return 1; }
            CRYPTO_chacha_20(ct, pt, L, k, iv12, 1);
            if (L && memcmp(ct, ref, L)) { printf("  %s chacha20 mismatch L=%zu\n", tag, L); bad++; }
        }

        for (int rep = 0; rep < 200; rep++) {
            size_t L = 1 + (((size_t)rnd() << 8 | rnd()) % 9000);
            uint32_t c0 = rnd();
            iv16[0] = (uint8_t)c0; iv16[1] = (uint8_t)(c0 >> 8);
            iv16[2] = (uint8_t)(c0 >> 16); iv16[3] = (uint8_t)(c0 >> 24);
            n++;
            if (!evp_chacha(ref, pt, L, k, iv16)) { printf("EVP failed\n"); return 1; }
            CHACHA20_CTX cx;
            CRYPTO_chacha_20_init(&cx, k, iv16);
            size_t off = 0;
            while (off < L) {
                size_t chunk = 1 + (((size_t)rnd() << 8 | rnd()) % 300);
                if (chunk > L - off) chunk = L - off;
                CRYPTO_chacha_20_update(&cx, ct + off, pt + off, chunk);
                off += chunk;
            }
            CRYPTO_chacha_20_cleanup(&cx);
            if (memcmp(ct, ref, L)) {
                printf("  %s streaming mismatch L=%zu ctr=%u\n", tag, L, c0); bad++;
            }
        }
    }
    printf("%-10s %-9s %d cases, %d failures\n", tag,
           bad ? "FAILED" : "ok", n, bad);
    return bad;
}

int main(void) {
    int bad = 0;
    printf("fused 512-bit kernels available: %s\n",
           chacha20_poly1305_using_avx512() ? "yes" : "no");
    bad |= run(chacha20_poly1305_using_avx512() ? "fused" : "portable");
    chacha20_poly1305_set_avx512_enabled(0);
    bad |= run("portable");
    printf("%s\n", bad ? "FAILURES" : "all paths agree with OpenSSL EVP");
    return bad != 0;
}
