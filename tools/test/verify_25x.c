#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

void ChaCha20_25x_key(uint8_t *out, const uint8_t *inp, size_t len,
                      const uint32_t key[8], const uint32_t ctr[4], uint8_t *pk);

#define MAX 1536
static uint8_t in[MAX], a[MAX + 64], b[MAX + 64], pa[32], pb[32];

#define ROL(v,n) ((uint32_t)(((v) << (n)) | ((v) >> (32 - (n)))))
static void qr(uint32_t *s, int a, int b, int c, int d)
{
    s[a] += s[b]; s[d] = ROL(s[d] ^ s[a], 16);
    s[c] += s[d]; s[b] = ROL(s[b] ^ s[c], 12);
    s[a] += s[b]; s[d] = ROL(s[d] ^ s[a], 8);
    s[c] += s[d]; s[b] = ROL(s[b] ^ s[c], 7);
}
static void chacha_block(const uint32_t key[8], const uint32_t ctr[4], uint8_t out[64])
{
    static const uint32_t sigma[4] = {0x61707865,0x3320646e,0x79622d32,0x6b206574};
    uint32_t s[16], x[16];
    memcpy(s, sigma, 16); memcpy(s + 4, key, 32); memcpy(s + 12, ctr, 16);
    memcpy(x, s, 64);
    for (int i = 0; i < 10; i++) {
        qr(x,0,4,8,12); qr(x,1,5,9,13); qr(x,2,6,10,14); qr(x,3,7,11,15);
        qr(x,0,5,10,15); qr(x,1,6,11,12); qr(x,2,7,8,13); qr(x,3,4,9,14);
    }
    for (int i = 0; i < 16; i++) { uint32_t v = x[i] + s[i]; memcpy(out + 4 * i, &v, 4); }
}

static void reference(const uint32_t key[8], const uint32_t ctr[4],
                      const uint8_t *in, uint8_t *out, size_t len, uint8_t pk[32])
{
    uint32_t c[4]; uint8_t ks[64];
    memcpy(c, ctr, 16);
    chacha_block(key, c, ks);
    memcpy(pk, ks, 32);
    for (size_t off = 0; off < len; off += 64) {
        size_t n = len - off < 64 ? len - off : 64;
        c[0]++;
        chacha_block(key, c, ks);
        for (size_t i = 0; i < n; i++) out[off + i] = in[off + i] ^ ks[i];
    }
}

static uint64_t rs = 0x9e3779b97f4a7c15ull;
static uint32_t rnd(void)
{
    rs ^= rs << 13; rs ^= rs >> 7; rs ^= rs << 17;
    return (uint32_t)(rs >> 32);
}

static int fails, cases;

static void one(size_t len, const uint32_t key[8], const uint32_t ctr[4])
{
    uint32_t k1[4], k2[4];
    memcpy(k1, ctr, 16); memcpy(k2, ctr, 16);
    memset(a, 0xa5, sizeof a); memset(b, 0x5b, sizeof b);
    memset(pa, 0x11, sizeof pa); memset(pb, 0x22, sizeof pb);

    reference(key, k1, in, a, len, pa);
    ChaCha20_25x_key(b, in, len, key, k2, pb);
    cases++;

    if (memcmp(pa, pb, 32)) {
        printf("  FAIL len=%zu ctr=%08x: Poly1305 key block differs\n", len, ctr[0]);
        fails++; return;
    }
    if (memcmp(a, b, len)) {
        size_t i = 0;
        while (i < len && a[i] == b[i]) i++;
        printf("  FAIL len=%zu ctr=%08x: first differing byte %zu "
               "(block %zu, offset %zu): ref=%02x 33x=%02x\n",
               len, ctr[0], i, i / 64, i % 64, a[i], b[i]);
        fails++; return;
    }
    for (size_t i = len; i < len + 64 && i < sizeof b; i++)
        if (b[i] != 0x5b) {
            printf("  FAIL len=%zu: wrote %zu bytes past the end\n", len, i - len + 1);
            fails++; return;
        }
    if (memcmp(k2, ctr, 16)) {
        printf("  FAIL len=%zu: modified the caller's counter block\n", len);
        fails++;
    }
}

int main(void)
{
    uint32_t key[8], ctr[4];
    for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)rnd();

    static const uint32_t ctr0[] = {
        0, 1, 255, 0x10000, 0x7fffffff, 0xffffffe0, 0xffffffef, 0xfffffffe
    };

    for (unsigned t = 0; t < sizeof ctr0 / sizeof ctr0[0]; t++) {
        for (int i = 0; i < 8; i++) key[i] = rnd();
        ctr[0] = ctr0[t];
        ctr[1] = rnd(); ctr[2] = rnd(); ctr[3] = rnd();

        for (size_t len = 1; len <= MAX; len++) one(len, key, ctr);
        for (int r = 0; r < 32; r++) one(1 + rnd() % MAX, key, ctr);
    }

    printf("%s: %d cases, %d failures\n", fails ? "FAIL" : "PASS", cases, fails);
    return fails != 0;
}
