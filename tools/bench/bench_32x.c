#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sched.h>
#include "bench_perf.h"

void ChaCha20_16x(uint8_t *out, const uint8_t *inp, size_t len,
                  const uint32_t key[8], const uint32_t counter[4]);
void ChaCha20_32x(uint8_t *out, const uint8_t *inp, size_t len,
                  const uint32_t key[8], const uint32_t counter[4]);

#define MAXLEN (256 * 1024)
static uint8_t in[MAXLEN], out[MAXLEN];
static uint32_t key[8] = { 1, 2, 3, 4, 5, 6, 7, 8 };
static uint32_t ctr[4] = { 0, 0xdeadbeef, 0xfeedface, 0x0badc0de };

typedef void (*kern)(uint8_t *, const uint8_t *, size_t,
                     const uint32_t *, const uint32_t *);

static double run(kern f, size_t len, int reps)
{
    struct bench_sample s;
    bench_perf_start();
    for (int i = 0; i < reps; i++) f(out, in, len, key, ctr);
    if (bench_perf_stop((uint64_t)len * reps, &s)) return 1e30;
    return s.cycles_per_byte;
}

int main(int argc, char **argv)
{
    int cpu = argc > 1 ? atoi(argv[1]) : 0;
    cpu_set_t set;
    CPU_ZERO(&set); CPU_SET(cpu, &set);
    if (sched_setaffinity(0, sizeof set, &set)) { perror("affinity"); return 2; }
    if (bench_perf_init() > 0) { fprintf(stderr, "no PMU access\n"); return 2; }

    for (size_t i = 0; i < sizeof in; i++) in[i] = (uint8_t)i;

    static const size_t lens[] = { 2048, 4096, 8192, 16384, 32768, 65536, 262144 };

    printf("%9s  %14s %14s   %14s %14s   %7s\n", "length",
           "16x c/B", "16x c/KiB", "32x c/B", "32x c/KiB", "delta");
    for (unsigned t = 0; t < sizeof lens / sizeof lens[0]; t++) {
        size_t len = lens[t];
        int reps = (int)(4u * 1024 * 1024 / len) + 1;
        double b16 = 1e30, b32 = 1e30;

        run(ChaCha20_16x, len, reps);
        run(ChaCha20_32x, len, reps);

        for (int r = 0; r < 9; r++) {
            double x, y;
            if (r & 1) {
                y = run(ChaCha20_32x, len, reps);
                x = run(ChaCha20_16x, len, reps);
            } else {
                x = run(ChaCha20_16x, len, reps);
                y = run(ChaCha20_32x, len, reps);
            }
            if (x < b16) b16 = x;
            if (y < b32) b32 = y;
        }
        printf("%9zu  %14.4f %14.1f   %14.4f %14.1f   %+6.1f%%\n",
               len, b16, b16 * 1024.0, b32, b32 * 1024.0,
               100.0 * (b16 - b32) / b16);
    }
    return 0;
}
