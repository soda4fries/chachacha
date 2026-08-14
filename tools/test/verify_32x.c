#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void ChaCha20_16x(uint8_t *out, const uint8_t *inp, size_t len,
                  const uint32_t key[8], const uint32_t counter[4]);
void ChaCha20_32x(uint8_t *out, const uint8_t *inp, size_t len,
                  const uint32_t key[8], const uint32_t counter[4]);

#define MAX (64 * 1024)
static uint8_t in[MAX], a[MAX], b[MAX];

static uint64_t rs = 0x243f6a8885a308d3ull;
static uint32_t rnd(void)
{
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return (uint32_t)(rs >> 32);
}

static int fails;

static void one(size_t len, const uint32_t key[8], const uint32_t ctr[4])
{
    uint32_t k1[4], k2[4];
    memcpy(k1, ctr, 16);
    memcpy(k2, ctr, 16);

    memset(a, 0xa5, sizeof a);
    memset(b, 0x5b, sizeof b);
    ChaCha20_16x(a, in, len, key, k1);
    ChaCha20_32x(b, in, len, key, k2);

    if (memcmp(a, b, len)) {
        size_t i = 0;
        while (i < len && a[i] == b[i]) i++;
        printf("  FAIL len=%zu ctr=%08x first differing byte %zu "
               "(block %zu, offset %zu): 16x=%02x 32x=%02x\n",
               len, ctr[0], i, i / 64, i % 64, a[i], b[i]);
        fails++;
        return;
    }
    if (memcmp(k2, ctr, 16)) {
        printf("  FAIL len=%zu: ChaCha20_32x modified the caller's counter "
               "block (%08x -> %08x)\n", len, ctr[0], k2[0]);
        fails++;
    }
}

int main(void)
{
    uint32_t key[8], ctr[4];
    size_t n = 0;

    for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)rnd();

    static const uint32_t ctr0[] = {
        0, 1, 7, 0x1000, 0x7fffffff, 0xfffffff0, 0xffffffe0, 0xfffffffe
    };

    for (unsigned t = 0; t < sizeof ctr0 / sizeof ctr0[0]; t++) {
        for (int i = 0; i < 8; i++) key[i] = rnd();
        ctr[0] = ctr0[t];
        ctr[1] = rnd(); ctr[2] = rnd(); ctr[3] = rnd();

        for (size_t base = 0; base <= 8192; base += 1024)
            for (int d = -2; d <= 2; d++) {
                long len = (long)base + d;
                if (len < 1 || len > MAX) continue;
                one((size_t)len, key, ctr); n++;
            }
        for (size_t len = 1; len <= 4224; len += 61) { one(len, key, ctr); n++; }
        for (size_t len = 2048; len <= 40960; len += 1021) { one(len, key, ctr); n++; }
        for (int r = 0; r < 64; r++) {
            size_t len = 1 + rnd() % (MAX - 1);
            one(len, key, ctr); n++;
        }
    }

    printf("%s: %zu cases, %d failures\n", fails ? "FAIL" : "PASS", n, fails);
    return fails != 0;
}
