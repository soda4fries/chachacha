// Copyright 2026 soda4fries
// SPDX-License-Identifier: Apache-2.0

#include <stdint.h>
#include <stdio.h>
#include <string.h>

void poly1305_gmul44(uint64_t x[3], const uint64_t q[5]);
void poly1305_gmul44_fast(uint64_t x[3], const uint64_t q[5]);
void poly1305_gmul44_karatsuba(uint64_t x[3], const uint64_t q[5]);
void poly1305_mkkey44(uint64_t q[5], const uint64_t x[3]);

static uint64_t state = UINT64_C(0x9e3779b97f4a7c15);

static uint64_t rng(void) {
    state ^= state >> 12;
    state ^= state << 25;
    state ^= state >> 27;
    return state * UINT64_C(0x2545f4914f6cdd1d);
}

int main(void) {
    for (unsigned i = 0; i < 1000000; i++) {
        uint64_t x[3] = {rng(), rng(), rng() & 3};
        uint64_t k[3] = {rng(), rng(), rng() & 3};
        uint64_t q[5], reference[3], fast[3], karatsuba[3];

        poly1305_mkkey44(q, k);
        memcpy(reference, x, sizeof(x));
        memcpy(fast, x, sizeof(x));
        memcpy(karatsuba, x, sizeof(x));
        poly1305_gmul44(reference, q);
        poly1305_gmul44_fast(fast, q);
        poly1305_gmul44_karatsuba(karatsuba, q);
        if (memcmp(reference, fast, sizeof(reference)) != 0 ||
            memcmp(reference, karatsuba, sizeof(reference)) != 0) {
            fprintf(stderr, "general multiply mismatch at case %u\n", i);
            return 1;
        }
    }
    puts("poly1305 general multiply: 1000000 cases passed");
    return 0;
}
