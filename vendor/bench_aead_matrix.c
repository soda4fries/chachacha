#define _GNU_SOURCE
#include "vendor_aead.h"
#include "../chacha20poly1305.h"
#include "intel-ipsec-mb-kernels/intel-ipsec-mb.h"

#include <dlfcn.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "bench_perf.h"

static const size_t sizes[] = {
    /* protocol bands, their edges, and the boundaries of the one-dispatch
     * range (1025..2048) plus the sizes just outside it */
    64, 128, 256, 512, 1024, 1025, 1088, 1200, 1280, 1350, 1360, 1420,
    1500, 1536, 1537, 1600, 1984, 2048, 2049, 2176, 2432, 2560,
    4096, 4229, 8192, 9000, 16384, 16385, 32768, 65536
};
struct workload { const char *name; size_t len, aad_len; };
static const struct workload profiles[] = {
    {"packet-1500-aad0", 1500, 0},
    {"packet-1500-aad5", 1500, 5},
    {"packet-1500-aad8", 1500, 8},
    {"packet-1500-aad12", 1500, 12},
    {"packet-1500-aad32", 1500, 32},
    {"wireguard-shaped-1424", 1424, 0},
    {"tls13-max-unpadded", 16385, 5},
};
typedef int (*seal_fn)(uint8_t *, uint8_t[16], const uint8_t *, size_t,
                       const uint8_t *, size_t, const uint8_t[32], const uint8_t[12]);
typedef int (*open_fn)(uint8_t *, const uint8_t *, size_t, const uint8_t[16],
                       const uint8_t *, size_t, const uint8_t[32], const uint8_t[12]);
struct backend { const char *name; int (*available)(void); seal_fn seal; open_fn open; };

typedef IMB_JOB *(*intel_one_shot_fn)(IMB_MGR *, IMB_JOB *);
typedef IMB_MGR *(*intel_alloc_fn)(uint64_t);
typedef void (*intel_init_fn)(IMB_MGR *, IMB_ARCH *);
static IMB_MGR *intel_mgr;
static intel_one_shot_fn intel_one_shot;
static int intel_one_shot_state = -1;

static int intel_one_shot_available(void) {
    if (intel_one_shot_state >= 0) return intel_one_shot_state;
    intel_one_shot_state = 0;
    if (!vendor_intel_available()) return 0;
    const char *requested = getenv("INTEL_IPSEC_MB_SO");
    const char *paths[] = {requested, "/tmp/libIPSec_MB.so.3.0.0-dev",
                           "/tmp/imb-src/build/lib/libIPSec_MB.so.3.0.0-dev", NULL};
    void *handle = NULL;
    for (size_t i = 0; paths[i] || (i == 0 && requested == NULL); i++) {
        if (!paths[i]) continue;
        handle = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (handle) break;
    }
    if (!handle) return 0;
    intel_alloc_fn alloc_fn = (intel_alloc_fn)dlsym(handle, "alloc_mb_mgr");
    intel_init_fn init_fn = (intel_init_fn)dlsym(handle, "init_mb_mgr_auto");
    void *anchor = dlsym(handle, "alloc_mb_mgr");
    Dl_info info;
    if (!alloc_fn || !init_fn || !anchor || !dladdr(anchor, &info) || !info.dli_fbase)
        return 0;
    intel_mgr = alloc_fn(0);
    if (!intel_mgr) return 0;
    init_fn(intel_mgr, NULL);
    /* Both benchmark hosts use this exact pinned 6c146bf build. `nm -a` was
     * checked on each binary before collection. The function is LOCAL, so it
     * cannot be resolved with dlsym. */
    intel_one_shot = (intel_one_shot_fn)((uintptr_t)info.dli_fbase + 0x4e7730u);
    intel_one_shot_state = 1;
    return 1;
}

static int intel_one_shot_run(uint8_t *out, uint8_t calculated_tag[16],
                              const uint8_t *in, size_t len, const uint8_t *aad_in,
                              size_t aad_len, const uint8_t key_in[32],
                              const uint8_t nonce_in[12], IMB_CIPHER_DIRECTION direction) {
    struct chacha20_poly1305_context_data ctx;
    IMB_JOB job;
    memset(&ctx, 0, sizeof(ctx));
    memset(&job, 0, sizeof(job));
    job.cipher_mode = IMB_CIPHER_CHACHA20_POLY1305;
    job.hash_alg = IMB_AUTH_CHACHA20_POLY1305;
    job.cipher_direction = direction;
    job.chain_order = IMB_ORDER_CIPHER_HASH;
    job.enc_keys = key_in;
    job.key_len_in_bytes = 32;
    job.iv = nonce_in;
    job.iv_len_in_bytes = 12;
    job.src = in;
    job.dst = out;
    job.msg_len_to_cipher_in_bytes = len;
    job.msg_len_to_hash_in_bytes = len;
    job.u.CHACHA20_POLY1305.aad = aad_in;
    job.u.CHACHA20_POLY1305.aad_len_in_bytes = aad_len;
    job.u.CHACHA20_POLY1305.ctx = &ctx;
    job.auth_tag_output = calculated_tag;
    job.auth_tag_output_len_in_bytes = 16;
    return intel_one_shot(intel_mgr, &job) == &job && job.status == IMB_STATUS_COMPLETED;
}

static int intel_one_shot_seal(uint8_t *out, uint8_t tag_out[16], const uint8_t *in,
                               size_t len, const uint8_t *aad_in, size_t aad_len,
                               const uint8_t key_in[32], const uint8_t nonce_in[12]) {
    return intel_one_shot_available() &&
           intel_one_shot_run(out, tag_out, in, len, aad_in, aad_len, key_in,
                              nonce_in, IMB_DIR_ENCRYPT);
}

static int intel_one_shot_open(uint8_t *out, const uint8_t *in, size_t len,
                               const uint8_t tag_in[16], const uint8_t *aad_in,
                               size_t aad_len, const uint8_t key_in[32],
                               const uint8_t nonce_in[12]) {
    uint8_t calculated[16];
    if (!intel_one_shot_available() ||
        !intel_one_shot_run(out, calculated, in, len, aad_in, aad_len, key_in,
                            nonce_in, IMB_DIR_DECRYPT)) return 0;
    unsigned diff = 0;
    for (unsigned i = 0; i < 16; i++) diff |= calculated[i] ^ tag_in[i];
    if (diff) { if (len) memset(out, 0, len); return 0; }
    return 1;
}

/* Intel's documented single-buffer entry points.  The one-shot path above
 * reaches an internal submit_job by a pinned offset, which both skips the job
 * wrapper and depends on one exact build.  These are exported, resolvable with
 * dlsym, and are what an application encrypting one buffer would actually call
 * -- so this is the apples-to-apples comparison against our low-level entry. */
typedef void (*imb_cp_init_fn)(const void *, struct chacha20_poly1305_context_data *,
                               const void *, const void *, const uint64_t, IMB_MGR *);
typedef void (*imb_cp_update_fn)(const void *, struct chacha20_poly1305_context_data *,
                                 void *, const void *, const uint64_t, IMB_MGR *);
typedef void (*imb_cp_final_fn)(struct chacha20_poly1305_context_data *, void *,
                                const uint64_t, IMB_MGR *);
static imb_cp_init_fn   imb_cp_init;
static imb_cp_update_fn imb_cp_enc, imb_cp_dec;
static imb_cp_final_fn  imb_cp_enc_fin, imb_cp_dec_fin;
static int imb_direct_state = -1;

static int intel_direct_available(void) {
    if (imb_direct_state >= 0) return imb_direct_state;
    imb_direct_state = 0;
    if (!intel_one_shot_available()) return 0;   /* reuses the dlopen + mgr init */
    const char *requested = getenv("INTEL_IPSEC_MB_SO");
    const char *paths[] = {requested, "/tmp/libIPSec_MB.so.3.0.0-dev",
                           "/tmp/imb-src/build/lib/libIPSec_MB.so.3.0.0-dev", NULL};
    void *h = NULL;
    for (size_t i = 0; paths[i] || (i == 0 && requested == NULL); i++) {
        if (!paths[i]) continue;
        h = dlopen(paths[i], RTLD_NOW | RTLD_LOCAL);
        if (h) break;
    }
    if (!h) return 0;
    imb_cp_init    = (imb_cp_init_fn)dlsym(h, "imb_chacha20_poly1305_init");
    imb_cp_enc     = (imb_cp_update_fn)dlsym(h, "imb_chacha20_poly1305_enc_update");
    imb_cp_dec     = (imb_cp_update_fn)dlsym(h, "imb_chacha20_poly1305_dec_update");
    imb_cp_enc_fin = (imb_cp_final_fn)dlsym(h, "imb_chacha20_poly1305_enc_finalize");
    imb_cp_dec_fin = (imb_cp_final_fn)dlsym(h, "imb_chacha20_poly1305_dec_finalize");
    imb_direct_state = imb_cp_init && imb_cp_enc && imb_cp_dec &&
                       imb_cp_enc_fin && imb_cp_dec_fin;
    return imb_direct_state;
}

static int intel_direct_seal(uint8_t *out, uint8_t tag_out[16], const uint8_t *in,
                             size_t len, const uint8_t *aad_in, size_t aad_len,
                             const uint8_t key_in[32], const uint8_t nonce_in[12]) {
    struct chacha20_poly1305_context_data ctx;
    if (!intel_direct_available()) return 0;
    imb_cp_init(key_in, &ctx, nonce_in, aad_in, aad_len, intel_mgr);
    imb_cp_enc(key_in, &ctx, out, in, len, intel_mgr);
    imb_cp_enc_fin(&ctx, tag_out, 16, intel_mgr);
    return 1;
}

static int intel_direct_open(uint8_t *out, const uint8_t *in, size_t len,
                             const uint8_t tag_in[16], const uint8_t *aad_in,
                             size_t aad_len, const uint8_t key_in[32],
                             const uint8_t nonce_in[12]) {
    struct chacha20_poly1305_context_data ctx;
    uint8_t calculated[16];
    if (!intel_direct_available()) return 0;
    imb_cp_init(key_in, &ctx, nonce_in, aad_in, aad_len, intel_mgr);
    imb_cp_dec(key_in, &ctx, out, in, len, intel_mgr);
    imb_cp_dec_fin(&ctx, calculated, 16, intel_mgr);
    unsigned diff = 0;
    for (unsigned i = 0; i < 16; i++) diff |= calculated[i] ^ tag_in[i];
    if (diff) { if (len) memset(out, 0, len); return 0; }
    return 1;
}

/* OpenSSL through EVP.  OpenSSL ships no stitched ChaCha20-Poly1305 -- its
 * provider runs ChaCha20 and Poly1305 as separate passes -- so there is no
 * assembly entry point to call the way there is for BoringSSL and Intel. EVP
 * is what an application uses.
 *
 * The cipher is fetched and the IV length set ONCE, at first use, and each call
 * only re-keys.  Naming the cipher on every call instead costs a provider fetch
 * per message: measured as fixed per-call overhead it was 1603 cycles on Zen 5
 * and 3479 on Zen 4, against 643-742 for every other backend here.  That is a
 * harness artefact, not OpenSSL, and it would have made this column meaningless
 * below a few kilobytes.  Separate encrypt and decrypt contexts so neither
 * direction re-specifies the cipher either. */
static EVP_CIPHER_CTX *ossl_enc, *ossl_dec;
static int ossl_state = -1;

static EVP_CIPHER_CTX *ossl_make(int enc) {
    EVP_CIPHER_CTX *c = EVP_CIPHER_CTX_new();
    if (!c) return NULL;
    if (EVP_CipherInit_ex(c, EVP_chacha20_poly1305(), NULL, NULL, NULL, enc) != 1 ||
        EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) != 1) {
        EVP_CIPHER_CTX_free(c);
        return NULL;
    }
    return c;
}

static int openssl_evp_available(void) {
    if (ossl_state >= 0) return ossl_state;
    ossl_enc = ossl_make(1);
    ossl_dec = ossl_make(0);
    ossl_state = ossl_enc && ossl_dec;
    return ossl_state;
}

static int openssl_evp_seal(uint8_t *out, uint8_t tag_out[16], const uint8_t *in,
                            size_t len, const uint8_t *aad_in, size_t aad_len,
                            const uint8_t key_in[32], const uint8_t nonce_in[12]) {
    int n = 0;
    if (!openssl_evp_available()) return 0;
    if (EVP_EncryptInit_ex(ossl_enc, NULL, NULL, key_in, nonce_in) != 1) return 0;
    if (aad_len && EVP_EncryptUpdate(ossl_enc, NULL, &n, aad_in, (int)aad_len) != 1) return 0;
    if (len && EVP_EncryptUpdate(ossl_enc, out, &n, in, (int)len) != 1) return 0;
    if (EVP_EncryptFinal_ex(ossl_enc, out + n, &n) != 1) return 0;
    return EVP_CIPHER_CTX_ctrl(ossl_enc, EVP_CTRL_AEAD_GET_TAG, 16, tag_out) == 1;
}

static int openssl_evp_open(uint8_t *out, const uint8_t *in, size_t len,
                            const uint8_t tag_in[16], const uint8_t *aad_in,
                            size_t aad_len, const uint8_t key_in[32],
                            const uint8_t nonce_in[12]) {
    int n = 0;
    if (!openssl_evp_available()) return 0;
    if (EVP_DecryptInit_ex(ossl_dec, NULL, NULL, key_in, nonce_in) != 1) return 0;
    if (aad_len && EVP_DecryptUpdate(ossl_dec, NULL, &n, aad_in, (int)aad_len) != 1) return 0;
    if (len && EVP_DecryptUpdate(ossl_dec, out, &n, in, (int)len) != 1) return 0;
    if (EVP_CIPHER_CTX_ctrl(ossl_dec, EVP_CTRL_AEAD_SET_TAG, 16, (void *)tag_in) != 1) return 0;
    return EVP_DecryptFinal_ex(ossl_dec, out + n, &n) == 1;
}

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
    return chacha20_poly1305_open_gather(out, in, len, tag, 16, aad, aad_len, key, nonce);
}
static const struct backend backends[] = {
    {"intel-one-shot", intel_one_shot_available, intel_one_shot_seal, intel_one_shot_open},
    {"boringssl-stitched", vendor_boringssl_available,
     vendor_boringssl_seal, vendor_boringssl_open},
    {"openssl-asm", vendor_openssl_available,
     vendor_openssl_seal, vendor_openssl_open},
    {"openssl-evp", openssl_evp_available, openssl_evp_seal, openssl_evp_open},
    {"ahead-fused", ahead_available, ahead_seal, ahead_open},
    {"intel-direct", intel_direct_available, intel_direct_seal, intel_direct_open},
};

static uint8_t input[65536], ciphertext[65536], output[65536];
static uint8_t aad[32], key[32], nonce[12], tag[16];

static int sample_seal(const struct backend *b, size_t len, size_t aad_len, unsigned iters,
                       struct bench_sample *result) {
    bench_perf_start();
    for (unsigned i = 0; i < iters; i++)
        b->seal(ciphertext, tag, input, len, aad_len ? aad : NULL, aad_len, key, nonce);
    return bench_perf_stop((uint64_t)iters * len, result);
}
static int sample_open(const struct backend *b, size_t len, size_t aad_len, unsigned iters,
                       struct bench_sample *result) {
    bench_perf_start();
    for (unsigned i = 0; i < iters; i++)
        b->open(output, ciphertext, len, tag, aad_len ? aad : NULL, aad_len, key, nonce);
    return bench_perf_stop((uint64_t)iters * len, result);
}

int main(int argc, char **argv) {
    const char *machine = argc > 1 ? argv[1] : "unknown";
    int cpu = argc > 2 ? atoi(argv[2]) : 0;
    int profile_mode = argc > 3 && strcmp(argv[3], "--profiles") == 0;
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof(set), &set) != 0) {
        perror("sched_setaffinity");
        return 2;
    }
    for (size_t i = 0; i < sizeof(input); i++) input[i] = (uint8_t)(i * 29 + 7);
    for (size_t i = 0; i < sizeof(aad); i++) aad[i] = (uint8_t)(i * 17 + 3);
    for (size_t i = 0; i < sizeof(key); i++) key[i] = (uint8_t)(i * 11 + 5);
    for (size_t i = 0; i < sizeof(nonce); i++) nonce[i] = (uint8_t)(i * 13 + 1);

    if (bench_perf_init() > 0)
        fprintf(stderr, "warning: hardware PMU unavailable; recording TSC only\n");
    if (profile_mode)
        puts("algorithm,machine,profile,size,aad_size,variant,metric,value");
    else
        puts("algorithm,machine,size,variant,metric,value");
    size_t workload_count = profile_mode ? sizeof(profiles) / sizeof(profiles[0])
                                         : sizeof(sizes) / sizeof(sizes[0]);
    for (size_t si = 0; si < workload_count; si++) {
        size_t len = profile_mode ? profiles[si].len : sizes[si];
        size_t aad_len = profile_mode ? profiles[si].aad_len : 13;
        const uint8_t *aad_in = aad_len ? aad : NULL;
        unsigned iters = (unsigned)(32u * 1024u * 1024u / len);
        if (iters < 300) iters = 300;
        if (iters > 50000) iters = 50000;
        int available[sizeof(backends) / sizeof(backends[0])];
        struct bench_sample seal_samples[sizeof(backends) / sizeof(backends[0])][7];
        struct bench_sample open_samples[sizeof(backends) / sizeof(backends[0])][7];

        for (size_t bi = 0; bi < sizeof(backends) / sizeof(backends[0]); bi++) {
            const struct backend *b = &backends[bi];
            available[bi] = b->available();
            if (!available[bi]) continue;
            b->seal(ciphertext, tag, input, len, aad_in, aad_len, key, nonce);
            if (!b->open(output, ciphertext, len, tag, aad_in, aad_len, key, nonce) ||
                memcmp(output, input, len)) {
                fprintf(stderr, "%s correctness failure at %zu\n", b->name, len);
                return 1;
            }
        }

        /* Alternate both backend order and seal/open order each repetition. */
        for (unsigned rep = 0; rep < 7; rep++) {
            for (size_t step = 0; step < sizeof(backends) / sizeof(backends[0]); step++) {
                size_t bi = (rep & 1) ?
                    (sizeof(backends) / sizeof(backends[0]) - 1 - step) : step;
                const struct backend *b = &backends[bi];
                if (!available[bi]) continue;
                if ((rep + bi) & 1) {
                    if (sample_open(b, len, aad_len, iters, &open_samples[bi][rep]) ||
                        sample_seal(b, len, aad_len, iters, &seal_samples[bi][rep])) return 3;
                } else {
                    if (sample_seal(b, len, aad_len, iters, &seal_samples[bi][rep]) ||
                        sample_open(b, len, aad_len, iters, &open_samples[bi][rep])) return 3;
                }
            }
        }

        for (size_t bi = 0; bi < sizeof(backends) / sizeof(backends[0]); bi++) {
            const struct backend *b = &backends[bi];
            char seal_name[64], open_name[64];
            snprintf(seal_name, sizeof(seal_name), "%s-seal", b->name);
            snprintf(open_name, sizeof(open_name), "%s-open", b->name);
            if (!available[bi]) {
                if (profile_mode) {
                    const char *metrics[] = {"core_cycles_per_byte", "instructions_per_byte",
                                             "tsc_ticks_per_byte"};
                    for (size_t mi = 0; mi < 3; mi++) {
                        printf("aead-profile,%s,%s,%zu,%zu,%s,%s,nan\n", machine,
                               profiles[si].name, len, aad_len, seal_name, metrics[mi]);
                        printf("aead-profile,%s,%s,%zu,%zu,%s,%s,nan\n", machine,
                               profiles[si].name, len, aad_len, open_name, metrics[mi]);
                    }
                } else {
                    bench_print_unsupported("aead", machine, len, seal_name);
                    bench_print_unsupported("aead", machine, len, open_name);
                }
                continue;
            }
            struct bench_sample seal_best = bench_best(seal_samples[bi]);
            struct bench_sample open_best = bench_best(open_samples[bi]);
            if (profile_mode) {
                const char *metrics[] = {"core_cycles_per_byte", "instructions_per_byte",
                                         "tsc_ticks_per_byte"};
                const double seal_values[] = {seal_best.cycles_per_byte,
                                              seal_best.instructions_per_byte,
                                              seal_best.tsc_per_byte};
                const double open_values[] = {open_best.cycles_per_byte,
                                              open_best.instructions_per_byte,
                                              open_best.tsc_per_byte};
                for (size_t mi = 0; mi < 3; mi++) {
                    printf("aead-profile,%s,%s,%zu,%zu,%s,%s,%.8f\n", machine,
                           profiles[si].name, len, aad_len, seal_name, metrics[mi],
                           seal_values[mi]);
                    printf("aead-profile,%s,%s,%zu,%zu,%s,%s,%.8f\n", machine,
                           profiles[si].name, len, aad_len, open_name, metrics[mi],
                           open_values[mi]);
                }
            } else {
                bench_print_sample("aead", machine, len, seal_name, &seal_best);
                bench_print_sample("aead", machine, len, open_name, &open_best);
            }
            fflush(stdout);
        }
    }
    return 0;
}
