#ifndef VENDOR_AEAD_H
#define VENDOR_AEAD_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Direct, job-manager-free wrappers around the vendored assembly.  The tag is
 * detached so the same call shape can be used by the benchmark harness. */
int vendor_intel_available(void);
int vendor_intel_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                      size_t len, const uint8_t *aad, size_t aad_len,
                      const uint8_t key[32], const uint8_t nonce[12]);
int vendor_intel_open(uint8_t *out, const uint8_t *in, size_t len,
                      const uint8_t tag[16], const uint8_t *aad, size_t aad_len,
                      const uint8_t key[32], const uint8_t nonce[12]);

int vendor_boringssl_available(void);
int vendor_boringssl_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                          size_t len, const uint8_t *aad, size_t aad_len,
                          const uint8_t key[32], const uint8_t nonce[12]);
int vendor_boringssl_open(uint8_t *out, const uint8_t *in, size_t len,
                          const uint8_t tag[16], const uint8_t *aad,
                          size_t aad_len, const uint8_t key[32],
                          const uint8_t nonce[12]);

int vendor_openssl_available(void);
int vendor_openssl_seal(uint8_t *out, uint8_t tag[16], const uint8_t *in,
                        size_t len, const uint8_t *aad, size_t aad_len,
                        const uint8_t key[32], const uint8_t nonce[12]);
int vendor_openssl_open(uint8_t *out, const uint8_t *in, size_t len,
                        const uint8_t tag[16], const uint8_t *aad,
                        size_t aad_len, const uint8_t key[32],
                        const uint8_t nonce[12]);

#ifdef __cplusplus
}
#endif
#endif
