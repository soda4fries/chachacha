/* Copyright 2026 soda4fries
 * SPDX-License-Identifier: Apache-2.0
 */
#ifndef CHACHA20POLY1305_H
#define CHACHA20POLY1305_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define CHACHA20_KEY_LEN            32
#define CHACHA20_NONCE_LEN          12
#define CHACHA20_POLY1305_TAG_LEN   16

/* out = in XOR ChaCha20(key, nonce, counter). Initial counter is 32-bit. */
void CRYPTO_chacha_20(uint8_t *out, const uint8_t *in, size_t in_len,
                      const uint8_t key[CHACHA20_KEY_LEN],
                      const uint8_t nonce[CHACHA20_NONCE_LEN],
                      uint32_t counter);

/* Streaming ChaCha20 state. */
typedef struct {
    uint32_t key[8];
    uint32_t ctr[4];        /* ctr[0] = block counter, ctr[1..3] = nonce */
    uint8_t  ks[64];        /* buffered keystream */
    unsigned ks_used;
} CHACHA20_CTX;

void CRYPTO_chacha_20_init(CHACHA20_CTX *ctx, const uint8_t key[CHACHA20_KEY_LEN],
                           const uint8_t iv[16]);

void CRYPTO_chacha_20_update(CHACHA20_CTX *ctx, uint8_t *out, const uint8_t *in,
                             size_t in_len);

void CRYPTO_chacha_20_cleanup(CHACHA20_CTX *ctx);

/* Encrypts |in_len| bytes and appends 16-byte tag. Returns 1 on success, 0 on failure. */
int chacha20_poly1305_seal(uint8_t *out, size_t *out_len, size_t max_out_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t key[CHACHA20_KEY_LEN],
                           const uint8_t nonce[CHACHA20_NONCE_LEN]);

/* Authenticates and decrypts. Returns 1 on success, 0 on verification failure (zeroing |out|). */
int chacha20_poly1305_open(uint8_t *out, size_t *out_len, size_t max_out_len,
                           const uint8_t *in, size_t in_len,
                           const uint8_t *ad, size_t ad_len,
                           const uint8_t key[CHACHA20_KEY_LEN],
                           const uint8_t nonce[CHACHA20_NONCE_LEN]);

/* Scatter/gather AEAD interface with separate tag buffer. */
int chacha20_poly1305_seal_scatter(uint8_t *out, uint8_t *out_tag,
                                   size_t *out_tag_len, size_t max_out_tag_len,
                                   const uint8_t *in, size_t in_len,
                                   const uint8_t *extra_in, size_t extra_in_len,
                                   const uint8_t *ad, size_t ad_len,
                                   const uint8_t key[CHACHA20_KEY_LEN],
                                   const uint8_t nonce[CHACHA20_NONCE_LEN]);

int chacha20_poly1305_open_gather(uint8_t *out,
                                  const uint8_t *in, size_t in_len,
                                  const uint8_t *in_tag, size_t in_tag_len,
                                  const uint8_t *ad, size_t ad_len,
                                  const uint8_t key[CHACHA20_KEY_LEN],
                                  const uint8_t nonce[CHACHA20_NONCE_LEN]);

/* Returns 1 if AVX-512 path is active, 0 otherwise. */
int chacha20_poly1305_using_avx512(void);

/* Forces portable fallback when enabled is 0. */
void chacha20_poly1305_set_avx512_enabled(int enabled);

#ifdef __cplusplus
}
#endif
#endif /* CHACHA20POLY1305_H */
