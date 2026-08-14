/* Copyright 2026 soda4fries
 * SPDX-License-Identifier: Apache-2.0
 */
#include "chacha20poly1305.h"

#include <string.h>
#ifdef __x86_64__
#include <cpuid.h>
#endif

void ChaCha20_ctr32(uint8_t *out, const uint8_t *in, size_t len,
                    const uint32_t key[8], const uint32_t counter[4]);

union aead_data {
    struct {
        uint8_t key[32] __attribute__((aligned(16)));
        uint32_t counter;
        uint8_t nonce[12];
        const uint8_t *extra_in;
        size_t extra_in_len;
    } in;
    struct { uint8_t tag[CHACHA20_POLY1305_TAG_LEN]; } out;
};

void chacha20_poly1305_seal_512(uint8_t *out, const uint8_t *in, size_t in_len,
                                const uint8_t *ad, size_t ad_len,
                                union aead_data *data);
void chacha20_poly1305_open_512(uint8_t *out, const uint8_t *in, size_t in_len,
                                const uint8_t *ad, size_t ad_len,
                                union aead_data *data);

#ifndef CHACHA20_USE_OPENSSL_CAP
unsigned int OPENSSL_ia32cap_P[4] = {0};
#else
extern unsigned int OPENSSL_ia32cap_P[4];
#endif

static int g_avx512;
static int g_ready;

static void detect(void) {
#ifdef __x86_64__
    unsigned a, b, c, d, vb, vc, vd;
    __cpuid_count(0, 0, a, vb, vc, vd);
    int is_amd = (vb == 0x68747541 && vd == 0x69746e65 && vc == 0x444d4163);

    __cpuid_count(1, 0, a, b, c, d);
    unsigned sig = a & 0x0fff0ff0;
    unsigned w0 = d, w1 = c;
    /* Bit 11 of word 1 is XOP on AMD; clear on Intel to avoid XOP dispatch */
    w1 &= ~(1u << 11);
    if (is_amd) {
        unsigned ea, eb, ec, ed;
        __cpuid_count(0x80000001, 0, ea, eb, ec, ed);
        if (ec & (1u << 11)) w1 |= (1u << 11);
    }
    __cpuid_count(7, 0, a, b, c, d);
    unsigned w2 = b, w3 = c;

#ifndef CHACHA20_ALLOW_SKYLAKEX_AVX512
    if (sig == 0x00050650) w2 &= ~(1u << 16);
#endif

#ifndef CHACHA20_USE_OPENSSL_CAP
    OPENSSL_ia32cap_P[0] = w0;
    OPENSSL_ia32cap_P[1] = w1;
    OPENSSL_ia32cap_P[2] = w2;
    OPENSSL_ia32cap_P[3] = w3;
#else
    (void)w0; (void)w1; (void)w3;
    w2 = OPENSSL_ia32cap_P[2];
#endif

    const unsigned need = (1u << 5) | (1u << 8) | (1u << 16) |
                          (1u << 21) | (1u << 30) | (1u << 31);
    g_avx512 = (w2 & need) == need;
#else
    g_avx512 = 0;
#endif
    g_ready = 1;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((constructor)) static void init_ctor(void) { detect(); }
#endif
static inline void ensure_ready(void) { if (!g_ready) detect(); }

int chacha20_poly1305_using_avx512(void) { ensure_ready(); return g_avx512; }

void chacha20_poly1305_set_avx512_enabled(int enabled) {
    ensure_ready();
    if (!enabled) g_avx512 = 0;
    else detect();
}

static void load_state(uint32_t k[8], uint32_t c[4], const uint8_t *key,
                       const uint8_t *nonce, uint32_t counter) {
    memcpy(k, key, 32);
    c[0] = counter;
    memcpy(&c[1], nonce, 12);
}

void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[CHACHA20_KEY_LEN],
                      const uint8_t nonce[CHACHA20_NONCE_LEN],
                      uint32_t counter) {
    uint32_t k[8], c[4];
    if (in_len == 0) return;
    ensure_ready();
    load_state(k, c, key, nonce, counter);
    ChaCha20_ctr32(out, in, in_len, k, c);
    memset(k, 0, sizeof k);
}

void CRYPTO_chacha_20_init(CHACHA20_CTX *ctx, const uint8_t key[CHACHA20_KEY_LEN],
                           const uint8_t iv[16]) {
    ensure_ready();
    memcpy(ctx->key, key, 32);
    memcpy(ctx->ctr, iv, 16);
    ctx->ks_used = 64;
}

void CRYPTO_chacha_20_update(CHACHA20_CTX *ctx, uint8_t *out, const uint8_t *in,
                             size_t in_len) {
    static const uint8_t zeros[64] = {0};

    while (in_len && ctx->ks_used < 64) {
        *out++ = (uint8_t)(*in++ ^ ctx->ks[ctx->ks_used++]);
        in_len--;
    }
    if (in_len >= 64) {
        size_t n = in_len & ~(size_t)63;
        ChaCha20_ctr32(out, in, n, ctx->key, ctx->ctr);
        ctx->ctr[0] += (uint32_t)(n / 64);
        out += n; in += n; in_len -= n;
    }
    if (in_len) {
        ChaCha20_ctr32(ctx->ks, zeros, 64, ctx->key, ctx->ctr);
        ctx->ctr[0]++;
        for (size_t i = 0; i < in_len; i++) out[i] = (uint8_t)(in[i] ^ ctx->ks[i]);
        ctx->ks_used = (unsigned)in_len;
    }
}

void CRYPTO_chacha_20_cleanup(CHACHA20_CTX *ctx) { memset(ctx, 0, sizeof *ctx); }

/* Portable Poly1305 implementation (radix 2^26) */
struct poly1305 {
    uint32_t r[5], s[4], h[5], pad[4];
    uint8_t buf[16];
    size_t buf_used;
};

static uint32_t ld32(const uint8_t *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}
static void st32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)v; p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16); p[3] = (uint8_t)(v >> 24);
}

static void poly1305_init(struct poly1305 *st, const uint8_t key[32]) {
    memset(st, 0, sizeof *st);
    st->r[0] = (ld32(key + 0)) & 0x03ffffff;
    st->r[1] = (ld32(key + 3) >> 2) & 0x03ffff03;
    st->r[2] = (ld32(key + 6) >> 4) & 0x03ffc0ff;
    st->r[3] = (ld32(key + 9) >> 6) & 0x03f03fff;
    st->r[4] = (ld32(key + 12) >> 8) & 0x000fffff;
    for (int i = 0; i < 4; i++) st->s[i] = st->r[i + 1] * 5;
    for (int i = 0; i < 4; i++) st->pad[i] = ld32(key + 16 + 4 * i);
}

static void poly1305_blocks(struct poly1305 *st, const uint8_t *m, size_t len,
                            uint32_t hibit) {
    const uint32_t M = 0x03ffffff;
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    const uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
    const uint32_t s1 = st->s[0], s2 = st->s[1], s3 = st->s[2], s4 = st->s[3];

    while (len >= 16) {
        h0 += (ld32(m + 0)) & M;
        h1 += (ld32(m + 3) >> 2) & M;
        h2 += (ld32(m + 6) >> 4) & M;
        h3 += (ld32(m + 9) >> 6) & M;
        h4 += (ld32(m + 12) >> 8) | hibit;

        uint64_t d0 = (uint64_t)h0 * r0 + (uint64_t)h1 * s4 + (uint64_t)h2 * s3 +
                      (uint64_t)h3 * s2 + (uint64_t)h4 * s1;
        uint64_t d1 = (uint64_t)h0 * r1 + (uint64_t)h1 * r0 + (uint64_t)h2 * s4 +
                      (uint64_t)h3 * s3 + (uint64_t)h4 * s2;
        uint64_t d2 = (uint64_t)h0 * r2 + (uint64_t)h1 * r1 + (uint64_t)h2 * r0 +
                      (uint64_t)h3 * s4 + (uint64_t)h4 * s3;
        uint64_t d3 = (uint64_t)h0 * r3 + (uint64_t)h1 * r2 + (uint64_t)h2 * r1 +
                      (uint64_t)h3 * r0 + (uint64_t)h4 * s4;
        uint64_t d4 = (uint64_t)h0 * r4 + (uint64_t)h1 * r3 + (uint64_t)h2 * r2 +
                      (uint64_t)h3 * r1 + (uint64_t)h4 * r0;

        uint32_t c = (uint32_t)(d0 >> 26); h0 = (uint32_t)d0 & M;
        d1 += c; c = (uint32_t)(d1 >> 26); h1 = (uint32_t)d1 & M;
        d2 += c; c = (uint32_t)(d2 >> 26); h2 = (uint32_t)d2 & M;
        d3 += c; c = (uint32_t)(d3 >> 26); h3 = (uint32_t)d3 & M;
        d4 += c; c = (uint32_t)(d4 >> 26); h4 = (uint32_t)d4 & M;
        h0 += c * 5;                c = h0 >> 26;  h0 &= M;
        h1 += c;

        m += 16; len -= 16;
    }
    st->h[0] = h0; st->h[1] = h1; st->h[2] = h2; st->h[3] = h3; st->h[4] = h4;
}

static void poly1305_update(struct poly1305 *st, const uint8_t *m, size_t len) {
    if (st->buf_used) {
        size_t want = 16 - st->buf_used;
        if (want > len) want = len;
        memcpy(st->buf + st->buf_used, m, want);
        st->buf_used += want; m += want; len -= want;
        if (st->buf_used == 16) {
            poly1305_blocks(st, st->buf, 16, 1u << 24);
            st->buf_used = 0;
        }
    }
    if (len >= 16) {
        size_t n = len & ~(size_t)15;
        poly1305_blocks(st, m, n, 1u << 24);
        m += n; len -= n;
    }
    if (len) { memcpy(st->buf, m, len); st->buf_used = len; }
}

static void poly1305_finish(struct poly1305 *st, uint8_t tag[16]) {
    const uint32_t M = 0x03ffffff;
    if (st->buf_used) {
        st->buf[st->buf_used++] = 1;
        memset(st->buf + st->buf_used, 0, 16 - st->buf_used);
        poly1305_blocks(st, st->buf, 16, 0);
    }
    uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
    uint32_t c;
    c = h1 >> 26; h1 &= M; h2 += c;
    c = h2 >> 26; h2 &= M; h3 += c;
    c = h3 >> 26; h3 &= M; h4 += c;
    c = h4 >> 26; h4 &= M; h0 += c * 5;
    c = h0 >> 26; h0 &= M; h1 += c;

    uint32_t g0 = h0 + 5;      c = g0 >> 26; g0 &= M;
    uint32_t g1 = h1 + c;      c = g1 >> 26; g1 &= M;
    uint32_t g2 = h2 + c;      c = g2 >> 26; g2 &= M;
    uint32_t g3 = h3 + c;      c = g3 >> 26; g3 &= M;
    uint32_t g4 = h4 + c - (1u << 26);

    uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask;
    mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2;
    h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;

    uint32_t w0 = (h0      ) | (h1 << 26);
    uint32_t w1 = (h1 >>  6) | (h2 << 20);
    uint32_t w2 = (h2 >> 12) | (h3 << 14);
    uint32_t w3 = (h3 >> 18) | (h4 <<  8);
    uint64_t f = (uint64_t)w0 + st->pad[0]; w0 = (uint32_t)f;
    f = (uint64_t)w1 + st->pad[1] + (f >> 32); w1 = (uint32_t)f;
    f = (uint64_t)w2 + st->pad[2] + (f >> 32); w2 = (uint32_t)f;
    f = (uint64_t)w3 + st->pad[3] + (f >> 32); w3 = (uint32_t)f;
    st32(tag + 0, w0); st32(tag + 4, w1); st32(tag + 8, w2); st32(tag + 12, w3);
    memset(st, 0, sizeof *st);
}

static void pad16(struct poly1305 *st, size_t len) {
    static const uint8_t zeros[16] = {0};
    if (len % 16) poly1305_update(st, zeros, 16 - (len % 16));
}

static void tag_portable(uint8_t tag[16], const uint8_t *ad, size_t ad_len,
                         const uint8_t *ct, size_t ct_len,
                         const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t pk[32] = {0};
    struct poly1305 st;
    uint8_t lens[16];
    CRYPTO_chacha_20(pk, pk, sizeof pk, key, nonce, 0);
    poly1305_init(&st, pk);
    poly1305_update(&st, ad, ad_len);  pad16(&st, ad_len);
    poly1305_update(&st, ct, ct_len);  pad16(&st, ct_len);
    for (int i = 0; i < 8; i++) lens[i]     = (uint8_t)((uint64_t)ad_len >> (8 * i));
    for (int i = 0; i < 8; i++) lens[8 + i] = (uint8_t)((uint64_t)ct_len >> (8 * i));
    poly1305_update(&st, lens, 16);
    poly1305_finish(&st, tag);
    memset(pk, 0, sizeof pk);
}

static int ct_eq16(const uint8_t *a, const uint8_t *b) {
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

int chacha20_poly1305_seal_scatter(uint8_t *out, uint8_t *out_tag,
                                   size_t *out_tag_len, size_t max_out_tag_len,
                                   const uint8_t *in, size_t in_len,
                                   const uint8_t *extra_in, size_t extra_in_len,
                                   const uint8_t *ad, size_t ad_len,
                                   const uint8_t key[CHACHA20_KEY_LEN],
                                   const uint8_t nonce[CHACHA20_NONCE_LEN]) {
    (void)extra_in;
    if (extra_in_len != 0) return 0;
    if (max_out_tag_len < CHACHA20_POLY1305_TAG_LEN) return 0;
    ensure_ready();

    if (g_avx512) {
        union aead_data d;
        memset(&d, 0, sizeof d);
        memcpy(d.in.key, key, 32);
        d.in.counter = 0;
        memcpy(d.in.nonce, nonce, 12);
        chacha20_poly1305_seal_512(out, in, in_len, ad, ad_len, &d);
        memcpy(out_tag, d.out.tag, CHACHA20_POLY1305_TAG_LEN);
        memset(&d, 0, sizeof d);
    } else {
        CRYPTO_chacha_20(out, in, in_len, key, nonce, 1);
        tag_portable(out_tag, ad, ad_len, out, in_len, key, nonce);
    }
    *out_tag_len = CHACHA20_POLY1305_TAG_LEN;
    return 1;
}

int chacha20_poly1305_open_gather(uint8_t *out,
                                  const uint8_t *in, size_t in_len,
                                  const uint8_t *in_tag, size_t in_tag_len,
                                  const uint8_t *ad, size_t ad_len,
                                  const uint8_t key[CHACHA20_KEY_LEN],
                                  const uint8_t nonce[CHACHA20_NONCE_LEN]) {
    uint8_t tag[CHACHA20_POLY1305_TAG_LEN];
    if (in_tag_len != CHACHA20_POLY1305_TAG_LEN) return 0;
    ensure_ready();

    if (g_avx512) {
        union aead_data d;
        memset(&d, 0, sizeof d);
        memcpy(d.in.key, key, 32);
        d.in.counter = 0;
        memcpy(d.in.nonce, nonce, 12);
        chacha20_poly1305_open_512(out, in, in_len, ad, ad_len, &d);
        memcpy(tag, d.out.tag, sizeof tag);
        memset(&d, 0, sizeof d);
    } else {
        tag_portable(tag, ad, ad_len, in, in_len, key, nonce);
        CRYPTO_chacha_20(out, in, in_len, key, nonce, 1);
    }

    if (!ct_eq16(tag, in_tag)) {
        memset(out, 0, in_len);
        memset(tag, 0, sizeof tag);
        return 0;
    }
    memset(tag, 0, sizeof tag);
    return 1;
}

int chacha20_poly1305_seal(uint8_t *out, size_t *out_len, size_t max_out_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t key[CHACHA20_KEY_LEN],
                           const uint8_t nonce[CHACHA20_NONCE_LEN]) {
    size_t need = in_len + CHACHA20_POLY1305_TAG_LEN, tag_len;
    if (need < in_len || max_out_len < need) return 0;
    if (!chacha20_poly1305_seal_scatter(out, out + in_len, &tag_len,
                                        max_out_len - in_len, in, in_len,
                                        NULL, 0, ad, ad_len, key, nonce))
        return 0;
    *out_len = need;
    return 1;
}

int chacha20_poly1305_open(uint8_t *out, size_t *out_len, size_t max_out_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t key[CHACHA20_KEY_LEN],
                           const uint8_t nonce[CHACHA20_NONCE_LEN]) {
    size_t ct_len;
    if (in_len < CHACHA20_POLY1305_TAG_LEN) return 0;
    ct_len = in_len - CHACHA20_POLY1305_TAG_LEN;
    if (max_out_len < ct_len) return 0;
    if (!chacha20_poly1305_open_gather(out, in, ct_len, in + ct_len,
                                       CHACHA20_POLY1305_TAG_LEN,
                                       ad, ad_len, key, nonce))
        return 0;
    *out_len = ct_len;
    return 1;
}
