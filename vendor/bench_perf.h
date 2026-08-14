#ifndef CHACHACHA_BENCH_PERF_H
#define CHACHACHA_BENCH_PERF_H

#include <errno.h>
#include <fcntl.h>
#include <linux/perf_event.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <x86intrin.h>

struct bench_sample { double cycles_per_byte, instructions_per_byte, tsc_per_byte; };
static int bench_cycle_fd = -1, bench_instruction_fd = -1;
static int bench_tsc_only;
static uint64_t bench_tsc_start;

static int bench_read_int(const char *path) {
    char buf[32];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t n = read(fd, buf, sizeof(buf) - 1);
    close(fd);
    if (n <= 0) return -1;
    buf[n] = 0;
    return atoi(buf);
}

static int bench_perf_open(struct perf_event_attr *attr, int group_fd) {
    return (int)syscall(__NR_perf_event_open, attr, 0, -1, group_fd, 0);
}

static int bench_perf_init(void) {
    int hybrid_type = bench_read_int("/sys/devices/cpu_core/type");
    struct perf_event_attr a;
    memset(&a, 0, sizeof(a));
    a.size = sizeof(a);
    a.disabled = 1;
    a.exclude_kernel = 1;
    a.exclude_hv = 1;
    a.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED |
                    PERF_FORMAT_TOTAL_TIME_RUNNING;
    if (hybrid_type >= 0) {
        /* Generic PERF_TYPE_HARDWARE can silently read zero on Alder Lake's
         * non-native hybrid PMU. Use the cpu_core PMU and architectural event
         * encodings explicitly: cycles=0x3c, instructions=0xc0. */
        a.type = (uint32_t)hybrid_type;
        a.config = 0x3c;
    } else {
        a.type = PERF_TYPE_HARDWARE;
        a.config = PERF_COUNT_HW_CPU_CYCLES;
    }
    bench_cycle_fd = bench_perf_open(&a, -1);
    if (bench_cycle_fd < 0) { bench_tsc_only = 1; return 1; }
    a.disabled = 0;
    a.config = hybrid_type >= 0 ? 0xc0 : PERF_COUNT_HW_INSTRUCTIONS;
    bench_instruction_fd = bench_perf_open(&a, bench_cycle_fd);
    if (bench_instruction_fd < 0) {
        close(bench_cycle_fd); bench_cycle_fd = -1;
        bench_tsc_only = 1;
        return 1;
    }
    return 0;
}

static uint64_t bench_ticks(void) {
    unsigned aux;
    _mm_lfence();
    uint64_t t = __rdtscp(&aux);
    _mm_lfence();
    return t;
}

static void bench_perf_start(void) {
    if (!bench_tsc_only)
        ioctl(bench_cycle_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP);
    bench_tsc_start = bench_ticks();
    if (!bench_tsc_only)
        ioctl(bench_cycle_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP);
}

static int bench_perf_stop(uint64_t bytes, struct bench_sample *out) {
    struct {
        uint64_t nr, time_enabled, time_running;
        uint64_t value[2];
    } result;
    if (!bench_tsc_only)
        ioctl(bench_cycle_fd, PERF_EVENT_IOC_DISABLE, PERF_IOC_FLAG_GROUP);
    uint64_t tsc = bench_ticks() - bench_tsc_start;
    if (bench_tsc_only) {
        out->cycles_per_byte = NAN;
        out->instructions_per_byte = NAN;
        out->tsc_per_byte = (double)tsc / (double)bytes;
        return 0;
    }
    ssize_t n = read(bench_cycle_fd, &result, sizeof(result));
    if (n != (ssize_t)sizeof(result) || result.nr != 2 || result.time_running == 0 ||
        result.value[0] == 0 || result.value[1] == 0)
        return -1;
    double scale = (double)result.time_enabled / (double)result.time_running;
    out->cycles_per_byte = (double)result.value[0] * scale / (double)bytes;
    out->instructions_per_byte = (double)result.value[1] * scale / (double)bytes;
    out->tsc_per_byte = (double)tsc / (double)bytes;
    return 0;
}

static int bench_sample_cmp(const void *va, const void *vb) {
    const struct bench_sample *a = va, *b = vb;
    double av = isnan(a->cycles_per_byte) ? a->tsc_per_byte : a->cycles_per_byte;
    double bv = isnan(b->cycles_per_byte) ? b->tsc_per_byte : b->cycles_per_byte;
    return (av > bv) - (av < bv);
}

/* Handoff discipline: seven repetitions with alternating call order, then the
 * lowest valid core-cycle sample. Instructions and TSC remain from that same
 * repetition rather than being independently cherry-picked. */
static struct bench_sample bench_best(struct bench_sample samples[7]) {
    qsort(samples, 7, sizeof(samples[0]), bench_sample_cmp);
    return samples[0];
}

static void bench_print_sample(const char *algorithm, const char *machine,
                               size_t size, const char *variant,
                               const struct bench_sample *s) {
    printf("%s,%s,%zu,%s,core_cycles_per_byte,%.8f\n",
           algorithm, machine, size, variant, s->cycles_per_byte);
    printf("%s,%s,%zu,%s,instructions_per_byte,%.8f\n",
           algorithm, machine, size, variant, s->instructions_per_byte);
    printf("%s,%s,%zu,%s,tsc_ticks_per_byte,%.8f\n",
           algorithm, machine, size, variant, s->tsc_per_byte);
}

static void bench_print_unsupported(const char *algorithm, const char *machine,
                                    size_t size, const char *variant) {
    printf("%s,%s,%zu,%s,core_cycles_per_byte,nan\n", algorithm, machine, size, variant);
    printf("%s,%s,%zu,%s,instructions_per_byte,nan\n", algorithm, machine, size, variant);
    printf("%s,%s,%zu,%s,tsc_ticks_per_byte,nan\n", algorithm, machine, size, variant);
}

#endif
