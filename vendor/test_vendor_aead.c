#include "vendor_aead.h"
#include "../chacha20poly1305.h"

#include <openssl/evp.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <x86intrin.h>

/* The complete performance table used by FINDINGS.md.  Do not filter this list
 * to winning lengths: every backend is printed at every length. */
static const size_t sizes[] = {
    64, 128, 256, 512, 1024, 1280, 1420, 1500, 2048, 2176, 2304, 2432,
    2560, 4096, 8192, 8320, 8448, 8576, 8704, 9000, 16384, 32768, 65536
};
static const size_t edge_sizes[] = {
    0, 1, 15, 16, 17, 63, 64, 65, 127, 128, 129, 255, 256, 511, 512,
    575, 576, 577, 1023, 1024, 1025, 1087, 1088, 1089,
    1199, 1200, 1201, 1279, 1280, 1281, 1423, 1424, 1425,
    1499, 1500, 1501, 16383, 16384, 16385, 16386, 65535, 65536
};
static const size_t aad_sizes[] = {0, 5, 8, 12, 13, 32};
#define BENCH_AAD_LEN 13

typedef int (*seal_fn)(uint8_t *, uint8_t[16], const uint8_t *, size_t,
                       const uint8_t *, size_t, const uint8_t[32],
                       const uint8_t[12]);
typedef int (*open_fn)(uint8_t *, const uint8_t *, size_t, const uint8_t[16],
                       const uint8_t *, size_t, const uint8_t[32],
                       const uint8_t[12]);
struct backend { const char *name; int (*available)(void); seal_fn seal; open_fn open; };

static int ahead_available(void) { return chacha20_poly1305_using_avx512(); }
static int ahead_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in, size_t len,
                      const uint8_t *aad, size_t aad_len, const uint8_t key[32],
                      const uint8_t nonce[12]) {
    size_t tag_len = 0;
    return chacha20_poly1305_seal_scatter(out, tag, &tag_len, 16, in, len,
                                          NULL, 0, aad, aad_len, key, nonce) &&
           tag_len == 16;
}
static int ahead_open(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t tag[16], const uint8_t *aad, size_t aad_len,
                      const uint8_t key[32], const uint8_t nonce[12]) {
    return chacha20_poly1305_open_gather(out, in, len, tag, 16, aad, aad_len,
                                         key, nonce);
}

static const struct backend backends[] = {
    {"intel-direct", vendor_intel_available, vendor_intel_seal, vendor_intel_open},
    {"boringssl-stitched", vendor_boringssl_available,
     vendor_boringssl_seal, vendor_boringssl_open},
    {"openssl-asm", vendor_openssl_available,
     vendor_openssl_seal, vendor_openssl_open},
    {"ahead-fused", ahead_available, ahead_seal, ahead_open},
};

static int evp_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in, size_t len,
                    const uint8_t *aad, size_t aad_len, const uint8_t key[32],
                    const uint8_t nonce[12]) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    int n = 0, final_n = 0, ok = ctx != NULL;
    ok = ok && EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, NULL, NULL) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) == 1;
    ok = ok && EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) == 1;
    if (aad_len) ok = ok && EVP_EncryptUpdate(ctx, NULL, &n, aad, (int)aad_len) == 1;
    if (len) ok = ok && EVP_EncryptUpdate(ctx, out, &n, in, (int)len) == 1;
    ok = ok && EVP_EncryptFinal_ex(ctx, out + n, &final_n) == 1;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, tag) == 1;
    EVP_CIPHER_CTX_free(ctx);
    return ok;
}

static uint8_t plaintext[65536], ciphertext[65536], recovered[65536];
static uint8_t reference[65536], aad[32], key[32], nonce[12], ref_tag[16];

static void init_inputs(void) {
    for (size_t i = 0; i < sizeof(plaintext); i++) plaintext[i] = (uint8_t)(i * 29 + 7);
    for (size_t i = 0; i < sizeof(aad); i++) aad[i] = (uint8_t)(i * 17 + 3);
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i * 11 + 5);
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(i * 13 + 1);
}

static int check_one(const struct backend *b, size_t len, size_t aad_len) {
    uint8_t tag[16], bad_tag[16];
    const uint8_t *aad_in = aad_len ? aad : NULL;
    if (!evp_seal(reference, ref_tag, plaintext, len, aad_in, aad_len, key, nonce))
        return fprintf(stderr, "OpenSSL EVP failed\n"), 1;
    if (!b->seal(ciphertext, tag, plaintext, len, aad_in, aad_len, key, nonce) ||
        memcmp(ciphertext, reference, len) || memcmp(tag, ref_tag, 16))
        return fprintf(stderr, "%s seal mismatch at %zu bytes, %zu-byte AAD\n",
                       b->name, len, aad_len), 1;
    if (!b->open(recovered, ciphertext, len, tag, aad_in, aad_len, key, nonce) ||
        memcmp(recovered, plaintext, len))
        return fprintf(stderr, "%s open mismatch at %zu bytes, %zu-byte AAD\n",
                       b->name, len, aad_len), 1;
    memcpy(bad_tag, tag, 16); bad_tag[7] ^= 0x80;
    memset(recovered, 0xa5, len);
    if (b->open(recovered, ciphertext, len, bad_tag, aad_in, aad_len, key, nonce))
        return fprintf(stderr, "%s accepted bad tag at %zu bytes, %zu-byte AAD\n",
                       b->name, len, aad_len), 1;
    for (size_t i = 0; i < len; i++)
        if (recovered[i] != 0)
            return fprintf(stderr, "%s exposed plaintext on failure at %zu bytes, "
                           "%zu-byte AAD\n", b->name, len, aad_len), 1;
    return 0;
}

static uint64_t ticks(void) {
    unsigned aux;
    _mm_lfence();
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

static double time_seal(const struct backend *b, size_t len) {
    unsigned iters = (unsigned)(16 * 1024 * 1024 / (len ? len : 1));
    if (iters < 200) iters = 200;
    if (iters > 20000) iters = 20000;
    uint8_t tag[16];
    uint64_t start = ticks();
    for (unsigned i = 0; i < iters; i++) {
        nonce[0] = (uint8_t)i;
        b->seal(ciphertext, tag, plaintext, len, aad, BENCH_AAD_LEN, key, nonce);
    }
    uint64_t end = ticks();
    return (double)(end - start) / (double)(iters * len);
}

static double time_open(const struct backend *b, size_t len) {
    unsigned iters = (unsigned)(16 * 1024 * 1024 / (len ? len : 1));
    if (iters < 200) iters = 200;
    if (iters > 20000) iters = 20000;
    uint8_t tag[16];
    nonce[0] = 0;
    b->seal(ciphertext, tag, plaintext, len, aad, BENCH_AAD_LEN, key, nonce);
    uint64_t start = ticks();
    for (unsigned i = 0; i < iters; i++)
        b->open(recovered, ciphertext, len, tag, aad, BENCH_AAD_LEN, key, nonce);
    uint64_t end = ticks();
    return (double)(end - start) / (double)(iters * len);
}

int main(int argc, char **argv) {
    int failures = 0;
    init_inputs();
    for (size_t bi = 0; bi < sizeof(backends) / sizeof(backends[0]); bi++) {
        const struct backend *b = &backends[bi];
        if (!b->available()) { printf("SKIP %-20s (CPU feature unavailable)\n", b->name); continue; }
        int before = failures;
        for (size_t ai = 0; ai < sizeof(aad_sizes) / sizeof(aad_sizes[0]); ai++) {
            for (size_t i = 0; i < sizeof(edge_sizes) / sizeof(edge_sizes[0]); i++)
                failures += check_one(b, edge_sizes[i], aad_sizes[ai]);
            for (size_t i = 0; i < sizeof(sizes) / sizeof(sizes[0]); i++)
                failures += check_one(b, sizes[i], aad_sizes[ai]);
            if (b->seal == ahead_seal && aad_sizes[ai] == BENCH_AAD_LEN)
                for (size_t len = 2049; len <= 2560; len++)
                    failures += check_one(b, len, aad_sizes[ai]);
        }
        printf("%-25s %s (%zu AAD lengths; %zu edge + %zu table sizes each%s)\n",
               b->name,
               failures == before ? "correct" : "FAILED",
               sizeof(aad_sizes) / sizeof(aad_sizes[0]),
               sizeof(edge_sizes) / sizeof(edge_sizes[0]),
               sizeof(sizes) / sizeof(sizes[0]),
               b->seal == ahead_seal ? "; 512-size medium sweep" : "");
    }
    if (failures || (argc > 1 && strcmp(argv[1], "--check-only") == 0))
        return failures != 0;

    puts("\ncycles/byte (13-byte AAD; every size, no winner filtering)");
    puts("bytes   intel-seal intel-open  bssl-seal bssl-open  ahead-seal ahead-open");
    for (size_t si = 0; si < sizeof(sizes) / sizeof(sizes[0]); si++) {
        printf("%-7zu", sizes[si]);
        for (size_t bi = 0; bi < sizeof(backends) / sizeof(backends[0]); bi++) {
            if (backends[bi].available())
                printf(" %10.4f %10.4f", time_seal(&backends[bi], sizes[si]),
                       time_open(&backends[bi], sizes[si]));
            else
                printf(" %10s %10s", "SKIP", "SKIP");
        }
        putchar('\n');
    }
    return 0;
}
