#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sched.h>
#include <stdint.h>
#include "bench_perf.h"

#define N 2000000

#define VEC8(op) op(0) op(1) op(2) op(3) op(4) op(5) op(6) op(7)
#define ZADD(i) "vpaddd %%zmm" #i ", %%zmm" #i ", %%zmm" #i "\n\t"
#define ZXOR(i) "vpxord %%zmm" #i ", %%zmm" #i ", %%zmm" #i "\n\t"
#define ZROL(i) "vprold $7, %%zmm" #i ", %%zmm" #i "\n\t"
#define ZADD_I(i) "vpaddd %%zmm8, %%zmm" #i ", %%zmm" #i "\n\t"
#define ZXOR_I(i) "vpxord %%zmm8, %%zmm" #i ", %%zmm" #i "\n\t"
#define ZROL_I(i) "vprold $7, %%zmm" #i ", %%zmm" #i "\n\t"

static double run(const char *name, void (*fn)(uint64_t), uint64_t n, double ops) {
    double best = 1e30;
    for (int r = 0; r < 7; r++) {
        struct bench_sample s;
        bench_perf_start();
        fn(n);
        if (bench_perf_stop(1, &s)) continue;
        if (s.cycles_per_byte < best) best = s.cycles_per_byte;
    }
    printf("%-26s %10.0f cycles  %6.2f ops/cycle\n", name, best, ops * n / best);
    return ops * n / best;
}

static void vec_add(uint64_t n) {
    __asm__ volatile("1:\n\t" VEC8(ZADD_I) VEC8(ZADD_I) VEC8(ZADD_I) VEC8(ZADD_I)
                     "dec %0\n\tjnz 1b" : "+r"(n) :: "xmm0","xmm1","xmm2","xmm3",
                     "xmm4","xmm5","xmm6","xmm7","xmm8","cc");
}
static void vec_mix(uint64_t n) {
    __asm__ volatile("1:\n\t" VEC8(ZADD_I) VEC8(ZXOR_I) VEC8(ZROL_I) VEC8(ZADD_I)
                     "dec %0\n\tjnz 1b" : "+r"(n) :: "xmm0","xmm1","xmm2","xmm3",
                     "xmm4","xmm5","xmm6","xmm7","xmm8","cc");
}
#define MULX(a,b) "mulx %%r" #a ", %%r" #b ", %%r" #a "\n\t"
static void scalar_mulx(uint64_t n) {
    __asm__ volatile("1:\n\t"
        "mulx %%r8,  %%r9,  %%r10\n\t" "mulx %%r11, %%r12, %%r13\n\t"
        "mulx %%r14, %%r15, %%rax\n\t" "mulx %%rsi, %%rdi, %%rbx\n\t"
        "mulx %%r8,  %%r9,  %%r10\n\t" "mulx %%r11, %%r12, %%r13\n\t"
        "mulx %%r14, %%r15, %%rax\n\t" "mulx %%rsi, %%rdi, %%rbx\n\t"
        "dec %0\n\tjnz 1b" : "+r"(n) :: "r8","r9","r10","r11","r12","r13","r14",
        "r15","rax","rbx","rsi","rdi","cc");
}
static void both(uint64_t n) {
    __asm__ volatile("1:\n\t" VEC8(ZADD_I) VEC8(ZXOR_I)
        "mulx %%r8,  %%r9,  %%r10\n\t" "mulx %%r11, %%r12, %%r13\n\t"
        "mulx %%r14, %%r15, %%rax\n\t" "mulx %%rsi, %%rdi, %%rbx\n\t"
        VEC8(ZROL_I) VEC8(ZADD_I)
        "mulx %%r8,  %%r9,  %%r10\n\t" "mulx %%r11, %%r12, %%r13\n\t"
        "mulx %%r14, %%r15, %%rax\n\t" "mulx %%rsi, %%rdi, %%rbx\n\t"
        "dec %0\n\tjnz 1b" : "+r"(n) :: "xmm0","xmm1","xmm2","xmm3","xmm4","xmm5",
        "xmm6","xmm7","xmm8","r8","r9","r10","r11","r12","r13","r14","r15",
        "rax","rbx","rsi","rdi","cc");
}

int main(int argc, char **argv) {
    int cpu = argc > 1 ? atoi(argv[1]) : 0;
    cpu_set_t s; CPU_ZERO(&s); CPU_SET(cpu, &s);
    if (sched_setaffinity(0, sizeof s, &s)) { perror("aff"); return 2; }
    if (bench_perf_init() > 0) { fprintf(stderr, "no PMU\n"); return 2; }
    double v = run("512b vector int (add)",   vec_add,    N, 32);
    double m = run("512b vector int (mix)",   vec_mix,    N, 32);
    double u = run("scalar mulx",             scalar_mulx, N, 8);
    printf("\n");
    double b = run("vector 32 + mulx 8",      both,       N, 40);
    printf("\n  vector-only peak      : %.2f ops/c\n", m);
    printf("  scalar-only peak      : %.2f mulx/c\n", u);
    printf("  co-issued: vector %.2f ops/c + scalar %.2f mulx/c\n", b*32/40, b*8/40);
    return 0;
}
