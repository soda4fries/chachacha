/* Copyright 2026 soda4fries
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "bench_perf.h"

void ChaCha20_32x(uint8_t *, const uint8_t *, size_t,
                  const uint32_t *, const uint32_t *);
void ChaCha20_16x(uint8_t *, const uint8_t *, size_t, const void *, const void *);
void ChaCha20_17x_key(uint8_t *, const uint8_t *, size_t, const void *, const void *, void *);
void ChaCha20_tail_avx512(uint8_t *, const uint8_t *, size_t, const void *, const void *);
void ChaCha20_16x_mac(uint8_t *, const uint8_t *, size_t, const void *, const void *, void *);
void ChaCha20_16x_mac128(uint8_t *, const uint8_t *, size_t, const void *, const void *, void *);
void ChaCha20_16x_mac256(uint8_t *, const uint8_t *, size_t, const void *, const void *, void *);
void ChaCha20_16x_mac512(uint8_t *, const uint8_t *, size_t, const void *, const void *, void *);
void poly1305_aead_update_fma_avx512(const void *, uint64_t, void *, const void *);
void poly1305_aead_finish_fma_avx512(const void *, uint64_t, void *, const void *,
                                     const void *, void *);
void poly1305_aead_complete_fma_avx512(const void *, const void *, void *);
void poly1305_pow32(void *, const void *);
void poly1305_gmul44_fast(void *, const void *);
int chacha20_poly1305_seal(uint8_t *, size_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *, size_t, const uint8_t[32], const uint8_t[12]);
int chacha20_poly1305_open(uint8_t *, size_t *, size_t, const uint8_t *, size_t,
                           const uint8_t *, size_t, const uint8_t[32], const uint8_t[12]);

static uint8_t buf[1 << 17], out[1 << 17], ct[1 << 17];
static uint8_t key[32] = {1, 2, 3}, nonce[12] = {4}, ad[13] = {7};
static uint8_t ctr[16] = {1, 0, 0, 0, 9, 9, 9, 9, 8, 8, 8, 8, 7, 7, 7, 7};
static uint8_t pk[64], tag[16];
static uint64_t hash[3], lens[2] = {13, 1420}, q[5];
struct macctx { uint64_t A[3], B[3], k[3]; const uint8_t *ptr; };
static struct macctx mc;

static uint8_t fill_frame[512] __attribute__((aligned(64)));
static void narrow_fill(size_t len) {
    typedef uint64_t vec __attribute__((vector_size(32)));
    for (size_t i = 0; i < (64 + len + 31) / 32; i++) ((vec *)fill_frame)[i] = (vec){0};
    ChaCha20_tail_avx512(fill_frame, fill_frame, 64 + len, key, ctr);
    memcpy(pk, fill_frame, 32);
    for (size_t i = 0; i < (len + 31) / 32; i++)
        ((vec *)out)[i] = ((const vec *)buf)[i] ^ ((const vec *)(fill_frame + 64))[i];
}

static double best_of(unsigned iters, void (*fn)(void)) {
    double best = 1e30;
    for (int rep = 0; rep < 9; rep++) {
        struct bench_sample s;
        bench_perf_start();
        for (unsigned i = 0; i < iters; i++) fn();
        if (bench_perf_stop(iters, &s)) continue;
        if (s.cycles_per_byte < best) best = s.cycles_per_byte;
    }
    return best;
}
#define PART(name, iters, body) do { \
    void fn_(void) { body; } \
    printf("part,%s,%.1f\n", name, best_of(iters, fn_)); } while (0)

static size_t L;

int main(void) {
    setbuf(stdout, NULL);
    bench_perf_init();
    memset(buf, 0x5a, sizeof buf);
    mc.k[0] = 0x0ffffffc0fffffffULL;
    mc.k[1] = 0x0ffffffc0ffffffcULL;
    mc.k[2] = mc.k[1] + (mc.k[1] >> 2);
    poly1305_pow32(q, pk);

    PART("chacha_16x_1024",   20000, ChaCha20_16x(out, buf, 1024, key, ctr));
    PART("chacha_17x_key_1024", 20000, ChaCha20_17x_key(out, buf, 1024, key, ctr, pk));
    { static const size_t kl[] = {64, 128, 192, 256, 512, 1024};
      for (unsigned i = 0; i < sizeof kl / sizeof *kl; i++) {
        char nm[48]; L = kl[i]; sprintf(nm, "chacha_17x_key_%zu", L);
        PART(nm, 20000, ChaCha20_17x_key(out, buf, L, key, ctr, pk));
      } }

    { static const size_t fl[] = {64, 128, 192, 256, 448, 512, 768, 1024};
      for (unsigned i = 0; i < sizeof fl / sizeof *fl; i++) {
        char nm[48]; L = fl[i]; sprintf(nm, "chacha_fill_%zu", L);
        if (64 + L <= 512) PART(nm, 20000, narrow_fill(L));
        else PART(nm, 20000, ChaCha20_17x_key(out, buf, L, key, ctr, pk));
      } }

    PART("chacha_32x_onepass_2048", 20000, ChaCha20_32x(out, buf, 2048, key, ctr));
    PART("chacha_16x_mac_1024", 20000, (mc.ptr = buf, ChaCha20_16x_mac(out, buf, 1024, key, ctr, &mc)));
    static const size_t tails[] = {64, 128, 256, 396, 512, 768, 1024};
    for (unsigned i = 0; i < sizeof tails / sizeof *tails; i++) {
        char nm[48]; L = tails[i]; sprintf(nm, "chacha_tail_%zu", L);
        PART(nm, 20000, ChaCha20_tail_avx512(out, buf, L, key, ctr));
    }
    L = 128; PART("mac128_128", 20000, (mc.ptr = buf, ChaCha20_16x_mac128(out, buf, L, key, ctr, &mc)));
    L = 256; PART("mac256_256", 20000, (mc.ptr = buf, ChaCha20_16x_mac256(out, buf, L, key, ctr, &mc)));
    L = 396; PART("mac512_396", 20000, (mc.ptr = buf, ChaCha20_16x_mac512(out, buf, L, key, ctr, &mc)));

    static const size_t upd[] = {13, 256, 512, 908, 1024, 1036, 1420, 2048};
    for (unsigned i = 0; i < sizeof upd / sizeof *upd; i++) {
        char nm[48]; L = upd[i]; sprintf(nm, "ifma_update_%zu", L);
        PART(nm, 20000, poly1305_aead_update_fma_avx512(buf, L, hash, pk));
    }

    static const size_t fin[] = {908, 1024, 1036, 1280, 1420, 1500};
    for (unsigned i = 0; i < sizeof fin / sizeof *fin; i++) {
        char nm[48]; L = fin[i]; sprintf(nm, "ifma_finish_%zu", L);
        PART(nm, 20000, poly1305_aead_finish_fma_avx512(buf, L, hash, pk, lens, tag));
    }
    PART("ifma_complete", 20000, poly1305_aead_complete_fma_avx512(hash, pk, tag));
    PART("pow32", 50000, poly1305_pow32(q, pk));
    PART("gmul44_fast", 100000, (mc.ptr = buf, poly1305_gmul44_fast(&mc, q)));

    static const size_t e2e[] = {64, 128, 256, 512, 1024, 1420, 1500, 2048, 4096, 9000, 65536};
    for (unsigned i = 0; i < sizeof e2e / sizeof *e2e; i++) {
        size_t o; L = e2e[i];
        unsigned it = L > 20000 ? 2000 : 20000;
        chacha20_poly1305_seal(ct, &o, sizeof ct, buf, L, ad, 13, key, nonce);
        { void fn_(void) { size_t oo; chacha20_poly1305_seal(out, &oo, sizeof out, buf, L, ad, 13, key, nonce); }
          printf("e2e,seal,%zu,%.1f\n", L, best_of(it, fn_)); }
        { void fn_(void) { size_t oo; chacha20_poly1305_open(out, &oo, sizeof out, ct, L + 16, ad, 13, key, nonce); }
          printf("e2e,open,%zu,%.1f\n", L, best_of(it, fn_)); }
    }
    return 0;
}
