#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "../../chacha20poly1305.h"

#define K(n) extern unsigned long calls_##n, bytes_##n, rsi_##n;
K(ChaCha20_16x_mac) K(ChaCha20_16x_mac1024) K(ChaCha20_16x_mac512)
K(ChaCha20_16x_mac256) K(ChaCha20_16x_mac128) K(ChaCha20_17x) K(ChaCha20_17x_key)
K(ChaCha20_tail_avx512) K(ChaCha20_16x) K(ChaCha20_16x_tiered) K(ChaCha20_32x)
K(poly1305_aead_update_fma_avx512) K(poly1305_aead_complete_fma_avx512)
K(poly1305_aead_finish_fma_avx512) K(poly1305_pow32) K(poly1305_pow44) K(poly1305_gmul44_fast)

struct e { const char *nm; unsigned long *c, *b, *s; };
static struct e T[] = {
#define R(n) { #n, &calls_##n, &bytes_##n, &rsi_##n },
 R(ChaCha20_16x_mac) R(ChaCha20_16x_mac1024) R(ChaCha20_16x_mac512)
 R(ChaCha20_16x_mac256) R(ChaCha20_16x_mac128) R(ChaCha20_17x) R(ChaCha20_17x_key)
 R(ChaCha20_tail_avx512) R(ChaCha20_16x) R(ChaCha20_16x_tiered) R(ChaCha20_32x)
 R(poly1305_aead_update_fma_avx512) R(poly1305_aead_complete_fma_avx512)
 R(poly1305_aead_finish_fma_avx512) R(poly1305_pow32) R(poly1305_pow44) R(poly1305_gmul44_fast)
};
#define N (sizeof T / sizeof T[0])

static uint8_t in[70000], out[70100], key[32], nonce[12], ad[13];

int main(void)
{
    size_t L[] = {1280,1420,4096,16384};
    unsigned long c0[N], b0[N], s0[N];
    for (unsigned i = 0; i < sizeof L / sizeof L[0]; i++) {
        size_t ol;
        for (unsigned k = 0; k < N; k++) { c0[k] = *T[k].c; b0[k] = *T[k].b; s0[k] = *T[k].s; }
        chacha20_poly1305_seal(out, &ol, sizeof out, in, L[i], ad, 13, key, nonce);
        printf("payload %zu:\n", L[i]);
        unsigned long tot = 0, big = 0;
        for (unsigned k = 0; k < N; k++) {
            unsigned long c = *T[k].c - c0[k], b = *T[k].b - b0[k], r = *T[k].s - s0[k];
            int poly = T[k].nm[0] == 'p';
            if (!c) continue;
            printf("    %-34s %2lu call%s  len=%lu\n", T[k].nm, c, c == 1 ? " " : "s",
                   poly ? r : b);
            if (!poly) tot += b;
        }
        printf("    cipher bytes %lu\n\n", tot); (void)big;
    }
    return 0;
}
