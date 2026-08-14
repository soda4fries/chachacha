#include "vendor_aead.h"

#include <cpuid.h>
#include <limits.h>
#include <string.h>

/* This is the exact ABI layout consumed by Intel's assembly. */
struct intel_chacha_poly_ctx {
    uint64_t hash[3];
    uint64_t aad_len;
    uint64_t hash_len;
    uint8_t last_ks[64];
    uint8_t poly_key[32];
    uint8_t poly_scratch[16];
    uint64_t last_block_count;
    uint64_t remain_ks_bytes;
    uint64_t remain_ct_bytes;
    uint8_t iv[12];
};

extern void vendor_intel_chacha20_enc_dec_ks_avx512(
    const void *, void *, uint64_t, const void *, struct intel_chacha_poly_ctx *);
extern void vendor_intel_poly1305_key_gen_avx(const void *, const void *, void *);
extern void vendor_intel_poly1305_aead_update_fma_avx512(
    const void *, uint64_t, void *, const void *);
extern void vendor_intel_poly1305_aead_complete_fma_avx512(
    const void *, const void *, void *);

union bssl_open_data {
    struct { _Alignas(16) uint8_t key[32]; uint32_t counter; uint8_t nonce[12]; } in;
    struct { uint8_t tag[16]; } out;
};
union bssl_seal_data {
    struct {
        _Alignas(16) uint8_t key[32];
        uint32_t counter;
        uint8_t nonce[12];
        const uint8_t *extra_ciphertext;
        size_t extra_ciphertext_len;
    } in;
    struct { uint8_t tag[16]; } out;
};

extern void chacha20_poly1305_seal_avx2(uint8_t *, const uint8_t *, size_t,
                                         const uint8_t *, size_t,
                                         union bssl_seal_data *);
extern void chacha20_poly1305_open_avx2(uint8_t *, const uint8_t *, size_t,
                                         const uint8_t *, size_t,
                                         union bssl_open_data *);

_Static_assert(sizeof(struct intel_chacha_poly_ctx) == 192, "Intel context ABI");
_Static_assert(sizeof(union bssl_open_data) == 48, "BoringSSL open ABI");
_Static_assert(sizeof(union bssl_seal_data) == 64, "BoringSSL seal ABI");

static int cpu_has(const char *unused) {
    (void)unused;
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    __builtin_cpu_init();
    return 1;
#else
    return 0;
#endif
}

int vendor_intel_available(void) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    cpu_has(NULL);
    return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("avx512f") &&
           __builtin_cpu_supports("avx512bw") && __builtin_cpu_supports("avx512vl") &&
           __builtin_cpu_supports("avx512ifma");
#else
    return 0;
#endif
}

int vendor_boringssl_available(void) {
#if defined(__x86_64__) && (defined(__GNUC__) || defined(__clang__))
    cpu_has(NULL);
    return __builtin_cpu_supports("avx2") && __builtin_cpu_supports("bmi2");
#else
    return 0;
#endif
}

static unsigned tag_diff(const uint8_t a[16], const uint8_t b[16]) {
    unsigned d = 0;
    for (unsigned i = 0; i < 16; i++) d |= (unsigned)(a[i] ^ b[i]);
    return d;
}

static int intel_tag_and_crypt(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                               size_t len, const uint8_t *aad, size_t aad_len,
                               const uint8_t key[32], const uint8_t nonce[12],
                               int decrypt) {
    struct intel_chacha_poly_ctx ctx;
    uint64_t lengths[2];

    if (!vendor_intel_available() || (uint64_t)len >= (UINT64_C(1) << 38) - 64)
        return 0;
    memset(&ctx, 0, sizeof(ctx));
    memcpy(ctx.iv, nonce, 12);
    ctx.aad_len = (uint64_t)aad_len;
    ctx.hash_len = (uint64_t)len;
    vendor_intel_poly1305_key_gen_avx(key, nonce, ctx.poly_key);
    if (aad_len)
        vendor_intel_poly1305_aead_update_fma_avx512(
            aad, (uint64_t)aad_len, ctx.hash, ctx.poly_key);

    if (decrypt) {
        if (len)
            vendor_intel_poly1305_aead_update_fma_avx512(
                in, (uint64_t)len, ctx.hash, ctx.poly_key);
    } else if (len) {
        vendor_intel_chacha20_enc_dec_ks_avx512(in, out, (uint64_t)len, key, &ctx);
        vendor_intel_poly1305_aead_update_fma_avx512(
            out, (uint64_t)len, ctx.hash, ctx.poly_key);
    }
    lengths[0] = (uint64_t)aad_len;
    lengths[1] = (uint64_t)len;
    vendor_intel_poly1305_aead_update_fma_avx512(
        lengths, sizeof(lengths), ctx.hash, ctx.poly_key);
    vendor_intel_poly1305_aead_complete_fma_avx512(ctx.hash, ctx.poly_key, tag);
    if (decrypt && len)
        vendor_intel_chacha20_enc_dec_ks_avx512(in, out, (uint64_t)len, key, &ctx);
    memset(&ctx, 0, sizeof(ctx));
    return 1;
}

int vendor_intel_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                      size_t len, const uint8_t *aad, size_t aad_len,
                      const uint8_t key[32], const uint8_t nonce[12]) {
    return intel_tag_and_crypt(out, tag, in, len, aad, aad_len, key, nonce, 0);
}

int vendor_intel_open(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t tag[16], const uint8_t *aad, size_t aad_len,
                      const uint8_t key[32], const uint8_t nonce[12]) {
    uint8_t calculated[16];
    if (!intel_tag_and_crypt(out, calculated, in, len, aad, aad_len, key, nonce, 1))
        return 0;
    if (tag_diff(calculated, tag)) {
        if (len) memset(out, 0, len);
        return 0;
    }
    return 1;
}

int vendor_boringssl_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                          size_t len, const uint8_t *aad, size_t aad_len,
                          const uint8_t key[32], const uint8_t nonce[12]) {
    union bssl_seal_data data;
    if (!vendor_boringssl_available()) return 0;
    memset(&data, 0, sizeof(data));
    memcpy(data.in.key, key, 32);
    memcpy(data.in.nonce, nonce, 12);
    chacha20_poly1305_seal_avx2(out, in, len, aad, aad_len, &data);
    memcpy(tag, data.out.tag, 16);
    return 1;
}

int vendor_boringssl_open(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t tag[16], const uint8_t *aad,
                          size_t aad_len, const uint8_t key[32],
                          const uint8_t nonce[12]) {
    union bssl_open_data data;
    if (!vendor_boringssl_available()) return 0;
    memset(&data, 0, sizeof(data));
    memcpy(data.in.key, key, 32);
    memcpy(data.in.nonce, nonce, 12);
    chacha20_poly1305_open_avx2(out, in, len, aad, aad_len, &data);
    if (tag_diff(data.out.tag, tag)) {
        if (len) memset(out, 0, len);
        return 0;
    }
    return 1;
}

uint32_t vendor_openssl_ia32cap_P[4] = {0};

extern void vendor_openssl_ChaCha20_ctr32(uint8_t *out, const uint8_t *in, size_t len,
                                          const uint32_t *key, const uint32_t *counter);
typedef void (*ossl_poly1305_blocks_fn)(void *ctx, const uint8_t *inp, size_t len, uint32_t padbit);
typedef void (*ossl_poly1305_emit_fn)(void *ctx, uint8_t mac[16], const uint8_t nonce[16]);

struct ossl_poly1305_func {
    ossl_poly1305_blocks_fn blocks;
    ossl_poly1305_emit_fn emit;
};

extern int vendor_openssl_poly1305_init(void *ctx, const uint8_t key[16], struct ossl_poly1305_func *func);

struct ossl_poly1305_ctx {
    _Alignas(64) uint8_t opaque[512];
    uint8_t nonce[16];
    struct ossl_poly1305_func func;
};

static void init_openssl_cap(void) {
    static int ready = 0;
    if (ready) return;
#ifdef __x86_64__
    unsigned a, b, c, d, vb, vc, vd;
    __cpuid_count(0, 0, a, vb, vc, vd);
    int is_amd = (vb == 0x68747541 && vd == 0x69746e65 && vc == 0x444d4163);

    __cpuid_count(1, 0, a, b, c, d);
    unsigned sig = a & 0x0fff0ff0;
    unsigned w0 = d, w1 = c;
    w1 &= ~(1u << 11);
    if (is_amd) {
        unsigned ea, eb, ec, ed;
        __cpuid_count(0x80000001, 0, ea, eb, ec, ed);
        if (ec & (1u << 11)) w1 |= (1u << 11);
    }
    __cpuid_count(7, 0, a, b, c, d);
    unsigned w2 = b, w3 = c;
    if (sig == 0x00050650) w2 &= ~(1u << 16);

    vendor_openssl_ia32cap_P[0] = w0;
    vendor_openssl_ia32cap_P[1] = w1;
    vendor_openssl_ia32cap_P[2] = w2;
    vendor_openssl_ia32cap_P[3] = w3;
#endif
    ready = 1;
}

int vendor_openssl_available(void) {
    init_openssl_cap();
    return 1;
}

static int openssl_poly_init(struct ossl_poly1305_ctx *ctx, const uint8_t key[32], const uint8_t nonce[12]) {
    uint32_t counter[4];
    uint8_t first_block[64];
    uint8_t zero[64] = {0};

    counter[0] = 0;
    memcpy(&counter[1], nonce, 12);
    vendor_openssl_ChaCha20_ctr32(first_block, zero, 64, (const uint32_t *)key, counter);

    memcpy(ctx->nonce, first_block + 16, 16);
    int ret = vendor_openssl_poly1305_init(ctx->opaque, first_block, &ctx->func);
    memset(first_block, 0, sizeof(first_block));
    return ret;
}

static void openssl_poly_update_padded(struct ossl_poly1305_ctx *ctx, const uint8_t *data, size_t len) {
    if (len >= 16) {
        size_t n = len & ~(size_t)15;
        ctx->func.blocks(ctx->opaque, data, n, 1);
        data += n;
        len -= n;
    }
    if (len) {
        uint8_t pad[16] = {0};
        memcpy(pad, data, len);
        ctx->func.blocks(ctx->opaque, pad, 16, 1);
    }
}

int vendor_openssl_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                        size_t len, const uint8_t *aad, size_t aad_len,
                        const uint8_t key[32], const uint8_t nonce[12]) {
    struct ossl_poly1305_ctx ctx;
    init_openssl_cap();
    if (!openssl_poly_init(&ctx, key, nonce)) return 0;

    if (aad_len) openssl_poly_update_padded(&ctx, aad, aad_len);

    if (len) {
        uint32_t counter[4];
        counter[0] = 1;
        memcpy(&counter[1], nonce, 12);
        vendor_openssl_ChaCha20_ctr32(out, in, len, (const uint32_t *)key, counter);
        openssl_poly_update_padded(&ctx, out, len);
    }

    uint64_t lengths[2] = { (uint64_t)aad_len, (uint64_t)len };
    ctx.func.blocks(ctx.opaque, (const uint8_t *)lengths, 16, 1);
    ctx.func.emit(ctx.opaque, tag, ctx.nonce);
    memset(&ctx, 0, sizeof(ctx));
    return 1;
}

int vendor_openssl_open(uint8_t *out, const uint8_t *in, size_t len,
                        const uint8_t tag[16], const uint8_t *aad,
                        size_t aad_len, const uint8_t key[32],
                        const uint8_t nonce[12]) {
    struct ossl_poly1305_ctx ctx;
    uint8_t calculated[16];
    init_openssl_cap();
    if (!openssl_poly_init(&ctx, key, nonce)) return 0;

    if (aad_len) openssl_poly_update_padded(&ctx, aad, aad_len);
    if (len) openssl_poly_update_padded(&ctx, in, len);

    uint64_t lengths[2] = { (uint64_t)aad_len, (uint64_t)len };
    ctx.func.blocks(ctx.opaque, (const uint8_t *)lengths, 16, 1);
    ctx.func.emit(ctx.opaque, calculated, ctx.nonce);
    memset(&ctx, 0, sizeof(ctx));

    if (tag_diff(calculated, tag)) {
        if (len) memset(out, 0, len);
        return 0;
    }

    if (len) {
        uint32_t counter[4];
        counter[0] = 1;
        memcpy(&counter[1], nonce, 12);
        vendor_openssl_ChaCha20_ctr32(out, in, len, (const uint32_t *)key, counter);
    }
    return 1;
}
