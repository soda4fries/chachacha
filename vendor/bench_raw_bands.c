/* Raw ChaCha20 stream, per ISA tier, over real-world workload bands.
 *
 * Derived from bench_raw_chacha.c; the difference is the size list, which
 * samples each protocol band instead of hitting one convenient length.
 * All implementations are cross-checked against ours for identical keystream
 * at every size before any timing is taken.
 *
 * AVX2 tier:    ours (9x hybrid), OpenSSL 8x, BoringSSL, Intel IPsec-MB
 * AVX-512 tier: ours (17x below 2240 B, 32x above), OpenSSL 16x, Intel
 *               -- BoringSSL is omitted because it has no AVX-512 ChaCha20.
 */
#define _GNU_SOURCE
#include <cpuid.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "bench_perf.h"

extern void ChaCha20_ctr32(uint8_t *, const uint8_t *, size_t,
                           const uint32_t *, const uint32_t *);
extern void vendor_openssl_ChaCha20_ctr32(uint8_t *, const uint8_t *, size_t,
                                          const uint32_t *, const uint32_t *);
extern void ChaCha20_ctr32_avx2(uint8_t *, const uint8_t *, size_t,
                                const uint32_t *, const uint32_t *);
extern uint32_t OPENSSL_ia32cap_P[4];
uint32_t vendor_openssl_ia32cap_P[4];

struct intel_chacha_poly_ctx {
    uint64_t hash[3], aad_len, hash_len;
    uint8_t last_ks[64], poly_key[32], poly_scratch[16];
    uint64_t last_block_count, remain_ks_bytes, remain_ct_bytes;
    uint8_t iv[12];
};
extern void vendor_intel_chacha20_enc_dec_ks_avx2(
    const void *, void *, uint64_t, const void *, struct intel_chacha_poly_ctx *);
extern void vendor_intel_chacha20_enc_dec_ks_avx512(
    const void *, void *, uint64_t, const void *, struct intel_chacha_poly_ctx *);

/* Real-world workload bands, sampled across each range rather than at a single
 * convenient point -- a length that happens to divide the kernel's batch is not
 * representative of the band it sits in.  The report averages each band. */
static const size_t sizes[] = {
    /* QUIC / HTTP-3 path MTU, 1200-1350 */
    1200, 1220, 1240, 1260, 1280, 1300, 1330, 1350,
    /* WireGuard / IPsec tunnel MTU, 1360-1420 */
    1360, 1370, 1380, 1390, 1400, 1410, 1420,
    /* Tuned web TLS record, 4096-4229 */
    4096, 4115, 4134, 4153, 4172, 4191, 4210, 4229,
    /* Jumbo-frame VPN, 8900-9000 */
    8900, 8915, 8930, 8945, 8960, 8975, 8990, 9000,
    /* TLS 1.3 full record, with and without the content-type byte */
    16384, 16385,
    /* Bulk transfer */
    32768, 40960, 49152, 57344, 65536
};
static uint8_t input[65536], ours[65536], stock[65536];
static uint32_t key[8] = {0, 1, 2, 3, 4, 5, 6, 7};
static uint32_t counter[4] = {1, 0x11111111, 0x22222222, 0x33333333};

static int detect_caps(uint32_t cap[4]) {
    unsigned a, b, c, d, vb, vc, vd;
    __cpuid_count(0, 0, a, vb, vc, vd);
    int amd = vb == 0x68747541 && vd == 0x69746e65 && vc == 0x444d4163;
    __cpuid_count(1, 0, a, b, c, d);
    cap[0] = d;
    cap[1] = c & ~(1u << 11); /* OpenSSL bit 11 is XOP, not CPUID SDBG. */
    if (amd) {
        unsigned ea, eb, ec, ed;
        __cpuid_count(0x80000001, 0, ea, eb, ec, ed);
        if (ec & (1u << 11)) cap[1] |= 1u << 11;
    }
    __cpuid_count(7, 0, a, b, c, d);
    cap[2] = b;
    cap[3] = c;
    __builtin_cpu_init();
    return __builtin_cpu_supports("avx512f") && __builtin_cpu_supports("avx512vl");
}

typedef void (*chacha_fn)(uint8_t *, const uint8_t *, size_t,
                           const uint32_t *, const uint32_t *);

static void intel_call(int avx512, uint8_t *out, const uint8_t *in, size_t len,
                       const uint32_t *k, const uint32_t *ctr) {
    struct intel_chacha_poly_ctx ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.last_block_count = (uint64_t)ctr[0] - 1;
    memcpy(ctx.iv, ctr + 1, 12);
    if (avx512)
        vendor_intel_chacha20_enc_dec_ks_avx512(in, out, len, k, &ctx);
    else
        vendor_intel_chacha20_enc_dec_ks_avx2(in, out, len, k, &ctx);
}
static void intel_avx2(uint8_t *o, const uint8_t *i, size_t n,
                       const uint32_t *k, const uint32_t *c) {
    intel_call(0, o, i, n, k, c);
}
static void intel_avx512(uint8_t *o, const uint8_t *i, size_t n,
                         const uint32_t *k, const uint32_t *c) {
    intel_call(1, o, i, n, k, c);
}

static int sample(chacha_fn fn, uint8_t *out, size_t len, unsigned iters,
                  struct bench_sample *result) {
    bench_perf_start();
    for (unsigned i = 0; i < iters; i++) fn(out, input, len, key, counter);
    return bench_perf_stop((uint64_t)iters * len, result);
}

static int run_algorithm(const char *machine, const char *algorithm,
                         const uint32_t detected[4], int avx512) {
    struct implementation { const char *name; chacha_fn fn; } impl[4];
    size_t impl_count;
    uint32_t selected[4];
    memcpy(selected, detected, sizeof(selected));
    if (strcmp(algorithm, "avx2") == 0) {
        /* Force both dispatchers down their AVX2 routes: ours reaches 9x,
         * pinned OpenSSL reaches its stock 8x route. */
        selected[2] &= ~((1u << 16) | (1u << 31));
        impl[0] = (struct implementation){"ours-avx2", ChaCha20_ctr32};
        impl[1] = (struct implementation){"openssl-avx2", vendor_openssl_ChaCha20_ctr32};
        impl[2] = (struct implementation){"boringssl-avx2", ChaCha20_ctr32_avx2};
        impl[3] = (struct implementation){"intel-avx2", intel_avx2};
        impl_count = 4;
    } else if (!avx512) {
        const char *names[] = {"ours-avx512", "openssl-avx512", "intel-avx512"};
        for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
            for (size_t j = 0; j < sizeof(names) / sizeof(names[0]); j++)
                bench_print_unsupported(algorithm, machine, sizes[i], names[j]);
        return 0;
    } else {
        impl[0] = (struct implementation){"ours-avx512", ChaCha20_ctr32};
        impl[1] = (struct implementation){"openssl-avx512", vendor_openssl_ChaCha20_ctr32};
        impl[2] = (struct implementation){"intel-avx512", intel_avx512};
        impl_count = 3;
    }
    memcpy(OPENSSL_ia32cap_P, selected, sizeof(selected));
    memcpy(vendor_openssl_ia32cap_P, selected, sizeof(selected));

    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        size_t len = sizes[si];
        impl[0].fn(ours, input, len, key, counter);
        for (size_t ii = 1; ii < impl_count; ii++) {
            impl[ii].fn(stock, input, len, key, counter);
            if (memcmp(ours, stock, len)) {
                fprintf(stderr, "%s/%s correctness failure at %zu\n",
                        algorithm, impl[ii].name, len);
                return 1;
            }
        }
        unsigned iters = (unsigned)(32u * 1024u * 1024u / len);
        if (iters < 300) iters = 300;
        if (iters > 50000) iters = 50000;
        struct bench_sample samples[4][7];
        for (unsigned rep = 0; rep < 7; rep++) {
            for (size_t step = 0; step < impl_count; step++) {
                size_t ii = (rep & 1) ? impl_count - 1 - step : step;
                if (sample(impl[ii].fn, ii == 0 ? ours : stock, len, iters,
                           &samples[ii][rep])) return 3;
            }
        }
        for (size_t ii = 0; ii < impl_count; ii++) {
            struct bench_sample best = bench_best(samples[ii]);
            bench_print_sample(algorithm, machine, len, impl[ii].name, &best);
        }
        fflush(stdout);
    }
    return 0;
}

int main(int argc, char **argv) {
    const char *machine = argc > 1 ? argv[1] : "unknown";
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        return 2;
    }
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (uint8_t)(i * 31 + 7);
    uint32_t detected[4];
    int avx512 = detect_caps(detected);
    if (bench_perf_init() > 0)
        fprintf(stderr, "warning: hardware PMU unavailable; recording TSC only\n");
    puts("algorithm,machine,size,variant,metric,value");
    return run_algorithm(machine, "avx2", detected, avx512) |
           run_algorithm(machine, "avx512", detected, avx512);
}
