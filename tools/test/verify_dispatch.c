// Copyright 2026 soda4fries
// SPDX-License-Identifier: Apache-2.0

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <cpuid.h>

extern void ChaCha20_ctr32(uint8_t *, const uint8_t *, size_t,
                           const uint32_t *, const uint32_t *);

unsigned int OPENSSL_ia32cap_P[4] = {0};
static int has_avx2, has_avx512f, has_avx512vl;

static void detect(void) {
    unsigned a, b, c, d, vb, vc, vd;
    __cpuid_count(0, 0, a, vb, vc, vd);
    int is_amd = (vb == 0x68747541 && vd == 0x69746e65 && vc == 0x444d4163);
    __cpuid_count(1, 0, a, b, c, d);
    OPENSSL_ia32cap_P[0] = d;
    OPENSSL_ia32cap_P[1] = c & ~(1u << 11);
    if (is_amd) {
        unsigned ea, eb, ec, ed;
        __cpuid_count(0x80000001, 0, ea, eb, ec, ed);
        if (ec & (1u << 11)) OPENSSL_ia32cap_P[1] |= (1u << 11);
    }
    __cpuid_count(7, 0, a, b, c, d);
    OPENSSL_ia32cap_P[2] = b; OPENSSL_ia32cap_P[3] = c;
    has_avx2     = (b >> 5)  & 1;
    has_avx512f  = (b >> 16) & 1;
    has_avx512vl = (b >> 31) & 1;
}

static inline uint32_t rotl(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
static void qr(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = rotl(*d, 16); *c += *d; *b ^= *c; *b = rotl(*b, 12);
    *a += *b; *d ^= *a; *d = rotl(*d, 8);  *c += *d; *b ^= *c; *b = rotl(*b, 7);
}
static void block(const uint32_t key[8], const uint32_t ctr[4], uint8_t out[64]) {
    static const uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    uint32_t s[16], x[16];
    memcpy(s, sigma, 16); memcpy(s + 4, key, 32); memcpy(s + 12, ctr, 16);
    memcpy(x, s, 64);
    for (int i = 0; i < 10; i++) {
        qr(&x[0], &x[4], &x[8],  &x[12]); qr(&x[1], &x[5], &x[9],  &x[13]);
        qr(&x[2], &x[6], &x[10], &x[14]); qr(&x[3], &x[7], &x[11], &x[15]);
        qr(&x[0], &x[5], &x[10], &x[15]); qr(&x[1], &x[6], &x[11], &x[12]);
        qr(&x[2], &x[7], &x[8],  &x[13]); qr(&x[3], &x[4], &x[9],  &x[14]);
    }
    for (int i = 0; i < 16; i++) { uint32_t v = x[i] + s[i]; memcpy(out + 4 * i, &v, 4); }
}
static void reference(const uint32_t key[8], const uint32_t ctr[4],
                      const uint8_t *in, uint8_t *out, size_t len) {
    uint32_t c[4]; uint8_t ks[64];
    memcpy(c, ctr, 16);
    for (size_t off = 0; off < len; off += 64, c[0]++) {
        size_t n = len - off < 64 ? len - off : 64;
        block(key, c, ks);
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
    }
}

#define MAXLEN (64 * 1024 + 4096)
#define PAD 64
static uint8_t inp[MAXLEN], ref[MAXLEN], got[MAXLEN + PAD];

static int chk(size_t len, const uint32_t key[8], const uint32_t ctr[4]) {
    memset(got, 0xa5, sizeof got);
    reference(key, ctr, inp, ref, len);
    ChaCha20_ctr32(got, inp, len, key, ctr);
    if (memcmp(ref, got, len)) {
        for (size_t i = 0; i < len; i++)
            if (ref[i] != got[i]) {
                printf("  FAIL len=%zu: first diff at %zu (block %zu) %02x != %02x\n",
                       len, i, i / 64, ref[i], got[i]);
                return 1;
            }
    }
    for (int i = 0; i < PAD; i++)
        if (got[len + i] != 0xa5) { printf("  FAIL len=%zu: wrote past the end\n", len); return 1; }
    return 0;
}

int main(void) {
    detect();
    printf("dispatch gate: avx2=%d avx512f=%d avx512vl=%d  ->  %s\n",
           has_avx2, has_avx512f, has_avx512vl,
           has_avx512f ? "ChaCha20_ctr32 should reach 17x" :
           has_avx2    ? "ChaCha20_ctr32 should reach 9x"  : "no vector path");

    for (size_t i = 0; i < MAXLEN; i++) inp[i] = (uint8_t)(i * 31 + 7);
    uint32_t key[8], ctr[4] = {0, 0x11111111, 0x22222222, 0x33333333};
    for (int i = 0; i < 8; i++) key[i] = 0x03020100u + 0x04040404u * i;

    int bad = 0, n = 0;
    for (size_t len = 1; len <= 8191; len++) { bad |= chk(len, key, ctr); n++; }
    if (!bad) printf("  ok   exhaustive 1..8191\n");

    int b2 = 0;
    for (int k = 1; k <= 60; k++)
        for (int step = 576, m = 0; m < 2; m++, step = 1088)
            for (int d = -2; d <= 2; d++) {
                long len = (long)k * step + d;
                if (len > 0 && len < MAXLEN) b2 |= chk((size_t)len, key, ctr), n++;
            }
    if (!b2) printf("  ok   576/1088 batch boundaries, k=1..60, +-2\n");
    bad |= b2;

    int b3 = 0;
    uint32_t wrap[4] = {0xfffffff0u, 1, 2, 3};
    for (size_t len = 1; len <= 4096; len += 7) b3 |= chk(len, key, wrap), n++;
    if (!b3) printf("  ok   counter wrap at 0xfffffff0\n");
    bad |= b3;

    printf("%s (%d cases)\n", bad ? "FAILED" : "all passed", n);
    return bad;
}
