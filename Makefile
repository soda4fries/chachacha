# Copyright 2026 soda4fries
# SPDX-License-Identifier: Apache-2.0

ifeq ($(origin CC),default)
CC := gcc
endif
PERL ?= perl
NASM ?= nasm
LD ?= ld
ASFLAGS = -Wa,--noexecstack
CFLAGS ?= -O2 -Wall

BUILD = build
VENDOR_BUILD = $(BUILD)/vendor
INTEL_VENDOR = vendor/intel-ipsec-mb-kernels
BSSL_VENDOR = vendor/boringssl
OSSL_VENDOR = vendor/openssl

OBJS = $(BUILD)/aead512.o $(BUILD)/chacha20poly1305.o
# Keep link order: aead_mac_partial.o must precede aead512_core.o to avoid
# Zen 5 MAC drain alignment regressions (someone can likely do a better layout with more effort).
AEAD_PARTS = $(BUILD)/aead_mac_partial.o $(BUILD)/aead_mac.o \
	$(BUILD)/aead512_core.o $(BUILD)/chacha_kernels_core.o \
	$(BUILD)/poly1305_pow.o $(BUILD)/poly1305_ifma.o $(BUILD)/cap_default.o
VENDOR_INTEL_OBJS = $(VENDOR_BUILD)/intel_chacha512.o \
	$(VENDOR_BUILD)/intel_chacha2.o $(VENDOR_BUILD)/intel_poly512.o

all: $(OBJS)

$(BUILD) $(VENDOR_BUILD):
	mkdir -p $@

check-nasm:
	@command -v $(NASM) >/dev/null || { \
		echo "error: NASM is required (Debian/Ubuntu: apt install nasm; Fedora: dnf install nasm)" >&2; \
		exit 1; \
	}

$(BUILD)/aead512_core.s: aead512.pl x86_64-xlate.pl | $(BUILD)
	CC=$(CC) $(PERL) $< elf $@
$(BUILD)/chacha_kernels_core.s: chacha_kernels.pl x86_64-xlate.pl | $(BUILD)
	CC=$(CC) $(PERL) $< elf $@
$(BUILD)/aead_mac_partial.S: aead_mac_partial.pl aead_mac.S \
		$(BUILD)/chacha_kernels_core.s | $(BUILD)
	$(PERL) $< aead_mac.S $(BUILD)/chacha_kernels_core.s > $@

$(BUILD)/aead512_core.o: $(BUILD)/aead512_core.s
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/chacha_kernels_core.o: $(BUILD)/chacha_kernels_core.s
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/aead_mac.o: aead_mac.S | $(BUILD)
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/aead_mac_partial.o: $(BUILD)/aead_mac_partial.S
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/poly1305_pow.o: poly1305_pow.S | $(BUILD)
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/poly1305_pow_karatsuba.o: poly1305_pow_karatsuba.S | $(BUILD)
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/poly1305_ifma.o: poly1305_ifma.asm | $(BUILD) check-nasm
	$(NASM) -Werror -f elf64 -o $@ $<
$(BUILD)/cap_default.o: cap_default.S | $(BUILD)
	$(CC) $(ASFLAGS) -c -o $@ $<
$(BUILD)/aead512.o: $(AEAD_PARTS)
	$(LD) -r -o $@ $^
$(BUILD)/chacha20poly1305.o: chacha20poly1305.c chacha20poly1305.h | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

# ---- local correctness gates --------------------------------------------
$(BUILD)/test_api: tools/test/test_api.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
$(BUILD)/verify_dispatch: tools/test/verify_dispatch.c $(BUILD)/aead512.o
	$(CC) $(CFLAGS) -o $@ $^
$(BUILD)/test_poly1305_pow: tools/test/test_poly1305_pow.c $(BUILD)/poly1305_pow.o \
		$(BUILD)/poly1305_pow_karatsuba.o
	$(CC) $(CFLAGS) -o $@ $^

test_api: $(BUILD)/test_api
verify_dispatch: $(BUILD)/verify_dispatch
test_poly1305_pow: $(BUILD)/test_poly1305_pow
$(BUILD)/sweep_ranges: tools/test/sweep_ranges.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
sweep_ranges: $(BUILD)/sweep_ranges
$(BUILD)/residue_grid: tools/test/residue_grid.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ -lcrypto
residue_grid: $(BUILD)/residue_grid
$(BUILD)/verify_32x: tools/test/verify_32x.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
verify_32x: $(BUILD)/verify_32x
$(BUILD)/verify_33x: tools/test/verify_33x.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
verify_33x: $(BUILD)/verify_33x
$(BUILD)/verify_25x: tools/test/verify_25x.c $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^
verify_25x: $(BUILD)/verify_25x
test: $(BUILD)/verify_dispatch $(BUILD)/test_api $(BUILD)/test_poly1305_pow \
		$(BUILD)/sweep_ranges $(BUILD)/residue_grid $(BUILD)/verify_32x $(BUILD)/verify_33x $(BUILD)/verify_25x
	$(BUILD)/verify_dispatch
	$(BUILD)/verify_32x
	$(BUILD)/verify_33x
	$(BUILD)/verify_25x
	$(BUILD)/test_api
	$(BUILD)/test_poly1305_pow
	$(BUILD)/sweep_ranges
	$(BUILD)/residue_grid

$(OSSL_VENDOR)/chacha-x86_64.S: $(OSSL_VENDOR)/chacha-x86_64.pl \
		$(OSSL_VENDOR)/x86_64-xlate.pl
	CC=$(CC) $(PERL) $< elf $@
$(OSSL_VENDOR)/poly1305-x86_64.S: $(OSSL_VENDOR)/poly1305-x86_64.pl \
		$(OSSL_VENDOR)/x86_64-xlate.pl
	CC=$(CC) $(PERL) $< elf $@
$(BSSL_VENDOR)/chacha-x86_64.S: $(BSSL_VENDOR)/chacha-x86_64.pl \
		$(BSSL_VENDOR)/x86_64-xlate.pl
	CC=$(CC) $(PERL) $< elf $@
$(BSSL_VENDOR)/chacha20_poly1305_x86_64.S: \
		$(BSSL_VENDOR)/chacha20_poly1305_x86_64.pl $(BSSL_VENDOR)/x86_64-xlate.pl
	CC=$(CC) $(PERL) $< elf $@

$(VENDOR_BUILD)/openssl_chacha.o: $(OSSL_VENDOR)/chacha-x86_64.S | $(VENDOR_BUILD)
	$(CC) $(ASFLAGS) -c -o $@ $<
$(VENDOR_BUILD)/openssl_chacha_namespaced.o: $(OSSL_VENDOR)/chacha-x86_64.S | $(VENDOR_BUILD)
	$(CC) $(ASFLAGS) -DChaCha20_ctr32=vendor_openssl_ChaCha20_ctr32 \
		-DOPENSSL_ia32cap_P=vendor_openssl_ia32cap_P -c -o $@ $<
$(VENDOR_BUILD)/openssl_poly1305_namespaced.o: $(OSSL_VENDOR)/poly1305-x86_64.S | $(VENDOR_BUILD)
	$(CC) $(ASFLAGS) -Dpoly1305_init=vendor_openssl_poly1305_init \
		-Dpoly1305_blocks=vendor_openssl_poly1305_blocks \
		-Dpoly1305_emit=vendor_openssl_poly1305_emit \
		-DOPENSSL_ia32cap_P=vendor_openssl_ia32cap_P -c -o $@ $<
$(VENDOR_BUILD)/boringssl_chacha.o: $(BSSL_VENDOR)/chacha-x86_64.S | $(VENDOR_BUILD)
	$(CC) -I$(BSSL_VENDOR)/include $(ASFLAGS) -c -o $@ $<
$(VENDOR_BUILD)/boringssl_aead.o: $(BSSL_VENDOR)/chacha20_poly1305_x86_64.S | $(VENDOR_BUILD)
	$(CC) -I$(BSSL_VENDOR)/include $(ASFLAGS) -c -o $@ $<
$(VENDOR_BUILD)/intel_chacha512.o: $(INTEL_VENDOR)/avx512_t1/chacha20_avx512.asm | $(VENDOR_BUILD) check-nasm
	$(NASM) -Werror -f elf64 -DAVX_IFMA \
		-Dchacha20_enc_dec_ks_avx512=vendor_intel_chacha20_enc_dec_ks_avx512 \
		-I$(INTEL_VENDOR)/ -o $@ $<
$(VENDOR_BUILD)/intel_chacha2.o: $(INTEL_VENDOR)/avx2_t1/chacha20_avx2.asm | $(VENDOR_BUILD) check-nasm
	$(NASM) -Werror -f elf64 -DAVX_IFMA \
		-Dchacha20_enc_dec_ks_avx2=vendor_intel_chacha20_enc_dec_ks_avx2 \
		-Dpoly1305_key_gen_avx=vendor_intel_poly1305_key_gen_avx \
		-I$(INTEL_VENDOR)/ -o $@ $<
$(VENDOR_BUILD)/intel_poly512.o: $(INTEL_VENDOR)/avx512_t2/poly_fma_avx512.asm | $(VENDOR_BUILD) check-nasm
	$(NASM) -Werror -f elf64 -DAVX_IFMA \
		-Dpoly1305_aead_update_fma_avx512=vendor_intel_poly1305_aead_update_fma_avx512 \
		-Dpoly1305_aead_complete_fma_avx512=vendor_intel_poly1305_aead_complete_fma_avx512 \
		-I$(INTEL_VENDOR)/ -o $@ $<
$(VENDOR_BUILD)/vendor_aead.o: vendor/vendor_aead.c vendor/vendor_aead.h | $(VENDOR_BUILD)
	$(CC) $(CFLAGS) -std=c11 -ffunction-sections -c -o $@ $<

VENDOR_OSSL_OBJS = $(VENDOR_BUILD)/openssl_chacha_namespaced.o \
	$(VENDOR_BUILD)/openssl_poly1305_namespaced.o

vendor-objects: $(VENDOR_OSSL_OBJS) \
	$(VENDOR_BUILD)/boringssl_chacha.o $(VENDOR_BUILD)/boringssl_aead.o \
	$(VENDOR_INTEL_OBJS) $(VENDOR_BUILD)/vendor_aead.o

$(BUILD)/vendor_harness: vendor/test_vendor_aead.c $(OBJS) vendor-objects
	$(CC) $(CFLAGS) -std=c11 -Ivendor -o $@ vendor/test_vendor_aead.c \
		$(OBJS) $(VENDOR_BUILD)/vendor_aead.o $(VENDOR_BUILD)/boringssl_aead.o \
		$(VENDOR_INTEL_OBJS) $(VENDOR_OSSL_OBJS) -lcrypto
$(BUILD)/parts_bench: tools/bench/parts_bench.c vendor/bench_perf.h $(OBJS)
	$(CC) $(CFLAGS) -std=gnu11 -Ivendor -o $@ tools/bench/parts_bench.c $(OBJS)

$(BUILD)/ports: tools/probe/ports.c vendor/bench_perf.h | $(BUILD)
	$(CC) $(CFLAGS) -std=gnu11 -mavx512f -Ivendor -o $@ $<
$(BUILD)/ilp: tools/probe/ilp.c vendor/bench_perf.h | $(BUILD)
	$(CC) $(CFLAGS) -std=gnu11 -mavx512f -Ivendor -o $@ $<
$(BUILD)/kernel_ipc: tools/probe/kernel_ipc.c vendor/bench_perf.h $(OBJS)
	$(CC) $(CFLAGS) -std=gnu11 -Ivendor -o $@ tools/probe/kernel_ipc.c $(OBJS)
$(BUILD)/bench_32x: tools/bench/bench_32x.c vendor/bench_perf.h $(OBJS)
	$(CC) $(CFLAGS) -std=gnu11 -Ivendor -o $@ tools/bench/bench_32x.c $(OBJS)
$(BUILD)/bench_ctr32_sweep: tools/bench/bench_ctr32_sweep.c vendor/bench_perf.h $(BUILD)/aead512.o
	$(CC) $(CFLAGS) -std=gnu11 -Ivendor -o $@ tools/bench/bench_ctr32_sweep.c $(BUILD)/aead512.o
probes: $(BUILD)/ports $(BUILD)/ilp $(BUILD)/kernel_ipc $(BUILD)/bench_32x \
	$(BUILD)/bench_ctr32_sweep

topk: $(BUILD)/parts_bench
	$(BUILD)/parts_bench > $(BUILD)/parts.csv
	tools/report/topk.py $(BUILD)/parts.csv

vendor_harness: $(BUILD)/vendor_harness
vendor-test: $(BUILD)/vendor_harness
	$(BUILD)/vendor_harness --check-only

$(BUILD)/raw_chacha_harness: vendor/bench_raw_chacha.c vendor/bench_perf.h $(BUILD)/aead512.o \
		$(VENDOR_BUILD)/openssl_chacha_namespaced.o $(VENDOR_BUILD)/boringssl_chacha.o \
		$(VENDOR_BUILD)/intel_chacha2.o $(VENDOR_BUILD)/intel_chacha512.o
	$(CC) $(CFLAGS) -std=c11 -o $@ vendor/bench_raw_chacha.c \
		$(BUILD)/aead512.o $(VENDOR_BUILD)/openssl_chacha_namespaced.o \
		$(VENDOR_BUILD)/boringssl_chacha.o $(VENDOR_BUILD)/intel_chacha2.o \
		$(VENDOR_BUILD)/intel_chacha512.o
$(BUILD)/raw_bands_harness: vendor/bench_raw_bands.c vendor/bench_perf.h $(BUILD)/aead512.o \
		$(VENDOR_BUILD)/openssl_chacha_namespaced.o $(VENDOR_BUILD)/boringssl_chacha.o \
		$(VENDOR_BUILD)/intel_chacha2.o $(VENDOR_BUILD)/intel_chacha512.o
	$(CC) $(CFLAGS) -std=c11 -o $@ vendor/bench_raw_bands.c \
		$(BUILD)/aead512.o $(VENDOR_BUILD)/openssl_chacha_namespaced.o \
		$(VENDOR_BUILD)/boringssl_chacha.o $(VENDOR_BUILD)/intel_chacha2.o \
		$(VENDOR_BUILD)/intel_chacha512.o
raw_chacha_harness: $(BUILD)/raw_chacha_harness
raw_bands_harness: $(BUILD)/raw_bands_harness

$(BUILD)/aead_matrix_harness: vendor/bench_aead_matrix.c vendor/bench_perf.h $(OBJS) vendor-objects
	$(CC) $(CFLAGS) -std=c11 -Ivendor -o $@ vendor/bench_aead_matrix.c \
		$(OBJS) $(VENDOR_BUILD)/vendor_aead.o $(VENDOR_BUILD)/boringssl_aead.o \
		$(VENDOR_OSSL_OBJS) -Wl,--gc-sections -ldl -lcrypto
aead_matrix_harness: $(BUILD)/aead_matrix_harness

clean:
	rm -rf -- $(BUILD)

.PHONY: all clean check-nasm test test_api verify_dispatch test_poly1305_pow \
	vendor-objects vendor_harness vendor-test raw_chacha_harness raw_bands_harness aead_matrix_harness \
	topk sweep_ranges residue_grid probes verify_32x verify_33x verify_25x
