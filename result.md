# Results

Cycles per byte, lower is better. GB/s is the same number at a nominal 3.0 GHz
and is there for intuition only — neither host was pinned to that clock, so c/B
is the figure to compare.

## Read this before the tables

**Powers of two flatter us.** A kernel that advances 1024 or 2048 bytes per pass
does its best work at a length that is an exact multiple of that pass, because
nothing is left over to pay for a second dispatch. 2048 B is the extreme case:
our AEAD covers it in a single dispatch where Intel needs two, and the margin
there is roughly double what it is 200 bytes either side. Those lengths are
marked **†** in the sweep.

That is a real advantage for anyone who actually sends 2048-byte payloads, and
it is not a measurement artefact — the number is what the code does. But it is
not what a network sends. So **the band tables and every figure use realistic
protocol sizes**, sampled across each range rather than at one convenient point,
and the boundary lengths appear only in the full sweep where they are labelled.

**Intel is shown at its better of two entry points per size.** IPsec-MB can be
reached through the job API's internal submit or through the documented
single-buffer functions; neither dominates — the job path wins below about 2 KB
and at 9000 B, the direct API wins at 2048, 4096 and 16384. Taking the minimum
is the comparison Intel would want made. Quoting only the job path would have
overstated our margin by up to 16 points at 1280 B.

**OpenSSL has no stitched AEAD.** OpenSSL executes ChaCha20 and Poly1305 as
separate sequential passes rather than a fused schedule. OpenSSL is measured both
directly at the assembly level (`openssl-asm`, calling its vendored `chacha-x86_64` and
`poly1305-x86_64` assembly kernels without API overhead) and through EVP (`openssl-evp`,
the standard application interface).

**BoringSSL has no AVX-512 ChaCha20.** It appears in the AVX2 and AEAD tables
and is absent from the AVX-512 ones.

## Method

Core cycles from `perf_event_open`, never TSC — the TSC runs at a fixed
reference frequency while the core clock moves, and the ratio reached 1.34 on
one host here, larger than most of the effects measured. Pinned to one core.
Implementations alternate order every repetition, and seal/open order alternates
too, so run order and thermal drift cannot masquerade as a result. Best of 7
internal repetitions, then best of 3 whole runs. Every implementation is
round-tripped and checked against the plaintext at every length before any
timing is taken; a mismatch aborts the run.

Intel IPsec-MB 3.0.0-dev (pinned build 6c146bf), BoringSSL
`chacha20_poly1305_x86_64`, OpenSSL direct assembly and OpenSSL via EVP. Regenerate with
`tools/report/result_report.py results/raw > result.md`.

## Per-call overhead, and whether the comparison is fair

Fitting total cycles against length over 64..1024 B gives the fixed cost
of a call before it enciphers anything. This is the check that the
comparison is not measuring scaffolding:

| backend | Zen 5 fixed c | Zen 4 fixed c |
|---|---:|---:|
| ours | 762 | 630 |
| BoringSSL | 643 | 494 |
| Intel job API | 685 | 587 |
| Intel direct API | 1156 | 842 |
| OpenSSL asm | 650 | 550 |
| OpenSSL EVP | 1419 | 1773 |

Ours, BoringSSL, OpenSSL asm and Intel's job API sit in one band — 494 to 762 cycles — so
those comparisons measure cryptography rather than call scaffolding. Two do not,
and both for reasons in the library rather than in this harness:

**Intel's direct API costs about 400 cycles more than its job API.** It is a
streaming interface. `init_chacha20_poly1305_direct` sets `ctx->hash_len = 0`
because it cannot know the message length, where the job path sets it from
`job->msg_len_to_hash_in_bytes` up front — so update and finalize must carry
partial-block state (`remain_ks_bytes`, `remain_ct_bytes`, `last_ks[64]`,
`poly_scratch[16]`) that a one-shot never needs. On top of that the build has
`SAFE_PARAM` on by default, so each of the three entry points re-validates its
arguments and resets the error status, and each is a separate indirect call
through the manager. That is the real cost of that entry point, so it is
reported as measured and Intel is credited with whichever of its two paths is
faster at each size.

**OpenSSL EVP carries provider dispatch overhead, while OpenSSL asm runs bare assembly.**
The EVP wrapper adds re-keying and provider dispatch costs that inflate fixed per-call
overhead. Measuring OpenSSL through direct assembly (`openssl-asm`) using vendored
`chacha-x86_64` and `poly1305-x86_64` assembly kernels isolates the raw two-pass cipher+MAC
performance from EVP scaffolding, putting it on equal footing with BoringSSL and Intel.

## Zen 5 — AMD EPYC 9655 (Turin)

### AEAD seal — real-world bands

| workload | bytes | ours c/B | ours GB/s | Intel | OpenSSL | BoringSSL | vs Intel | vs OpenSSL | vs BoringSSL |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.0125 | 2.96 | 1.2010 | 1.6639 | 2.0007 | +15.7% | +39.1% | +49.4% |
| WireGuard / IPsec | 1360-1420 | 0.9379 | 3.20 | 1.1276 | 1.7185 | 1.9960 | +16.8% | +45.4% | +53.0% |
| Tuned web TLS | 4096-4229 | 0.7885 | 3.80 | 0.8505 | 0.9770 | 1.6267 | +7.3% | +19.3% | +51.5% |
| Jumbo VPN | 8900-9000 | 0.6984 | 4.30 | 0.7260 | 0.9138 | 1.5532 | +3.8% | +23.6% | +55.0% |
| TLS 1.3 record | 16384-16385 | 0.6528 | 4.60 | 0.7224 | 0.8409 | 1.5204 | +9.6% | +22.4% | +57.1% |
| Bulk transfer | 32-64 KiB | 0.6441 | 4.66 | 0.6948 | 0.8182 | 1.4901 | +7.3% | +21.3% | +56.8% |

### AEAD open — real-world bands

| workload | bytes | ours c/B | ours GB/s | Intel | OpenSSL | BoringSSL | vs Intel | vs OpenSSL | vs BoringSSL |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.0262 | 2.92 | 1.2804 | 1.7516 | 2.3178 | +19.9% | +41.4% | +55.7% |
| WireGuard / IPsec | 1360-1420 | 0.9518 | 3.15 | 1.1798 | 1.8154 | 2.1372 | +19.3% | +47.6% | +55.5% |
| Tuned web TLS | 4096-4229 | 0.7976 | 3.76 | 0.8807 | 1.0087 | 1.7155 | +9.4% | +20.9% | +53.5% |
| Jumbo VPN | 8900-9000 | 0.6998 | 4.29 | 0.7347 | 0.9265 | 1.6057 | +4.7% | +24.5% | +56.4% |
| TLS 1.3 record | 16384-16385 | 0.6537 | 4.59 | 0.7301 | 0.8505 | 1.5336 | +10.5% | +23.1% | +57.4% |
| Bulk transfer | 32-64 KiB | 0.6395 | 4.69 | 0.6972 | 0.8205 | 1.4894 | +8.3% | +22.1% | +57.1% |

### AEAD full sweep — every length measured

| bytes | ours seal | vs Intel | vs OpenSSL | vs BoringSSL | ours open | vs Intel | vs OpenSSL | vs BoringSSL |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **64** | 11.3683 | +3.1% | -19.6% | +6.6% | 11.4217 | +5.0% | +0.3% | +9.7% |
| **128** | 6.1986 | +1.8% | -24.0% | +5.2% | 6.1794 | +4.6% | +1.4% | +8.4% |
| **256** | 3.4286 | -3.2% | -21.9% | +9.6% | 3.4502 | +3.8% | -3.9% | +12.6% |
| **512** | 1.8363 | -2.9% | +25.0% | +29.4% | 1.8966 | +0.7% | +30.0% | +34.5% |
| **1024** † | 0.9970 | +26.4% | -1.1% | +52.2% | 1.0281 | +31.1% | +4.6% | +53.0% |
| **1025** | 1.1663 | +17.4% | +23.5% | +44.4% | 1.1701 | +22.4% | +31.3% | +48.0% |
| **1088** | 1.1351 | +15.7% | +31.8% | +43.9% | 1.1494 | +21.0% | +34.0% | +44.9% |
| **1200** | 1.1373 | +10.4% | +39.3% | +43.0% | 1.1496 | +16.2% | +40.7% | +52.4% |
| **1280** | 0.9466 | +19.6% | +25.8% | +52.5% | 0.9639 | +22.9% | +28.2% | +58.7% |
| **1350** | 0.9537 | +17.5% | +48.3% | +52.6% | 0.9651 | +20.8% | +51.1% | +56.2% |
| **1360** | 0.9558 | +16.5% | +49.2% | +52.6% | 0.9700 | +19.8% | +50.1% | +55.1% |
| **1420** | 0.9200 | +17.2% | +40.9% | +53.5% | 0.9335 | +18.9% | +44.7% | +55.9% |
| **1500** | 0.9187 | +16.3% | +49.3% | +52.5% | 0.9322 | +19.3% | +50.0% | +54.8% |
| **1536** | 0.8197 | +20.3% | +26.1% | +56.7% | 0.8351 | +22.9% | +28.4% | +57.3% |
| **1537** | 0.8355 | +20.6% | +42.8% | +56.1% | 0.8518 | +21.4% | +46.2% | +57.4% |
| **1600** | 0.8187 | +19.4% | +37.0% | +55.8% | 0.8356 | +21.0% | +38.4% | +55.8% |
| **1984** | 0.7119 | +18.2% | +38.4% | +60.7% | 0.7262 | +19.9% | +39.6% | +60.7% |
| **2048** † | 0.6518 | +35.7% | +27.3% | +63.6% | 0.6680 | +39.1% | +29.0% | +63.4% |
| **2049** | 0.8486 | +18.9% | +26.9% | +52.8% | 0.8403 | +23.4% | +33.0% | +55.1% |
| **2176** | 0.9469 | +4.3% | +15.1% | +46.6% | 0.9231 | +12.5% | +20.0% | +54.4% |
| **2432** | 0.9178 | +0.8% | +10.7% | +48.0% | 0.9368 | +3.1% | +12.1% | +48.8% |
| **2560** | 0.8914 | -0.5% | +10.2% | +48.4% | 0.9067 | +1.4% | +11.3% | +48.7% |
| **4096** † | 0.7422 | +13.0% | +13.4% | +54.6% | 0.7522 | +14.9% | +14.3% | +54.9% |
| **4229** | 0.8348 | +1.4% | +23.9% | +48.4% | 0.8430 | +3.5% | +26.0% | +52.2% |
| **8192** † | 0.6823 | +10.7% | +18.2% | +56.0% | 0.6886 | +11.7% | +18.7% | +56.2% |
| **9000** | 0.6984 | +3.8% | +23.6% | +55.0% | 0.6998 | +4.7% | +24.5% | +56.4% |
| **16384** † | 0.6503 | +9.8% | +21.1% | +57.1% | 0.6508 | +10.7% | +21.9% | +57.6% |
| **16385** | 0.6553 | +9.5% | +23.5% | +57.0% | 0.6566 | +10.0% | +24.3% | +57.2% |
| **32768** † | 0.6472 | +7.5% | +21.0% | +56.8% | 0.6421 | +8.7% | +22.0% | +57.1% |
| **65536** † | 0.6410 | +7.1% | +21.5% | +56.8% | 0.6368 | +7.8% | +22.1% | +57.1% |

† sits exactly on a kernel batch boundary — see the note above.

### Raw ChaCha20 stream — AVX2

| workload | bytes | ours (9x) c/B | OpenSSL 8x c/B | BoringSSL c/B | Intel c/B | ours GB/s | ours vs best other |
|---|---|---:|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.4702 | 1.5079 | 1.5067 | 1.6032 | 2.04 | +2.4% |
| WireGuard / IPsec | 1360-1420 | 1.3809 | 1.3810 | 1.3804 | 1.5065 | 2.17 | -0.0% |
| Tuned web TLS | 4096-4229 | 1.2072 | 1.3471 | 1.3477 | 1.4360 | 2.49 | +10.4% |
| Jumbo VPN | 8900-9000 | 1.1299 | 1.2680 | 1.2674 | 1.3722 | 2.66 | +10.8% |
| TLS 1.3 record | 16384-16385 | 1.1145 | 1.2404 | 1.2380 | 1.3512 | 2.69 | +10.0% |
| Bulk transfer | 32-64 KiB | 1.0983 | 1.2287 | 1.2279 | 1.3332 | 2.73 | +10.6% |

### Raw ChaCha20 stream — AVX-512

BoringSSL has no AVX-512 ChaCha20, so it is absent here.

| workload | bytes | ours (17x/32x) c/B | OpenSSL 16x c/B | Intel c/B | ours GB/s | ours vs best other |
|---|---|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 0.8827 | 0.8866 | 0.8208 | 3.40 | -7.5% |
| WireGuard / IPsec | 1360-1420 | 0.8102 | 0.8133 | 0.7800 | 3.70 | -3.9% |
| Tuned web TLS | 4096-4229 | 0.4670 | 0.6561 | 0.6230 | 6.42 | +25.0% |
| Jumbo VPN | 8900-9000 | 0.3928 | 0.5621 | 0.5488 | 7.64 | +28.4% |
| TLS 1.3 record | 16384-16385 | 0.3656 | 0.5611 | 0.5465 | 8.21 | +33.1% |
| Bulk transfer | 32-64 KiB | 0.3567 | 0.5440 | 0.5320 | 8.41 | +32.9% |

## Zen 4 — AMD EPYC 4244P

### AEAD seal — real-world bands

| workload | bytes | ours c/B | ours GB/s | Intel | OpenSSL | BoringSSL | vs Intel | vs OpenSSL | vs BoringSSL |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.3464 | 2.23 | 1.4219 | 1.8775 | 1.9452 | +5.3% | +28.3% | +30.8% |
| WireGuard / IPsec | 1360-1420 | 1.2459 | 2.41 | 1.3674 | 1.8602 | 1.9599 | +8.9% | +33.0% | +36.4% |
| Tuned web TLS | 4096-4229 | 1.0497 | 2.86 | 1.0726 | 1.1650 | 1.5710 | +2.1% | +9.9% | +33.2% |
| Jumbo VPN | 8900-9000 | 0.9724 | 3.09 | 0.9603 | 1.0813 | 1.4663 | -1.3% | +10.1% | +33.7% |
| TLS 1.3 record | 16384-16385 | 0.9149 | 3.28 | 0.9539 | 1.0045 | 1.4471 | +4.1% | +8.9% | +36.8% |
| Bulk transfer | 32-64 KiB | 0.8899 | 3.37 | 0.9213 | 0.9810 | 1.4229 | +3.4% | +9.3% | +37.5% |

### AEAD open — real-world bands

| workload | bytes | ours c/B | ours GB/s | Intel | OpenSSL | BoringSSL | vs Intel | vs OpenSSL | vs BoringSSL |
|---|---|---:|---:|---:|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.3602 | 2.21 | 1.4588 | 1.9348 | 1.9697 | +6.8% | +29.7% | +30.9% |
| WireGuard / IPsec | 1360-1420 | 1.2784 | 2.35 | 1.3874 | 1.8928 | 1.8579 | +7.9% | +32.5% | +31.2% |
| Tuned web TLS | 4096-4229 | 1.0537 | 2.85 | 1.0746 | 1.1814 | 1.5685 | +1.9% | +10.8% | +32.8% |
| Jumbo VPN | 8900-9000 | 0.9808 | 3.06 | 0.9744 | 1.0979 | 1.4818 | -0.7% | +10.7% | +33.8% |
| TLS 1.3 record | 16384-16385 | 0.9179 | 3.27 | 0.9539 | 1.0107 | 1.4446 | +3.8% | +9.2% | +36.5% |
| Bulk transfer | 32-64 KiB | 0.8907 | 3.37 | 0.9215 | 0.9806 | 1.4243 | +3.3% | +9.2% | +37.5% |

### AEAD full sweep — every length measured

| bytes | ours seal | vs Intel | vs OpenSSL | vs BoringSSL | ours open | vs Intel | vs OpenSSL | vs BoringSSL |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| **64** | 9.3623 | +7.2% | -9.5% | +0.5% | 9.5919 | +2.5% | -5.3% | +1.7% |
| **128** | 5.4662 | -0.9% | -14.1% | -0.6% | 5.6398 | -4.3% | -8.3% | -4.0% |
| **256** | 3.2372 | +4.4% | -23.4% | +6.5% | 3.2868 | +7.4% | -14.4% | +4.8% |
| **512** | 2.2559 | -3.3% | +2.0% | +12.5% | 2.2825 | -0.5% | +0.6% | +10.2% |
| **1024** † | 1.2556 | +12.9% | -6.6% | +39.3% | 1.2749 | +14.6% | -1.2% | +36.1% |
| **1025** | 1.5409 | +5.5% | +9.2% | +25.6% | 1.5715 | +2.3% | +10.8% | +20.9% |
| **1088** | 1.4964 | +3.3% | +18.4% | +23.9% | 1.5205 | +3.5% | +18.9% | +18.1% |
| **1200** | 1.4895 | -2.3% | +31.0% | +22.9% | 1.5005 | -1.2% | +32.0% | +24.5% |
| **1280** | 1.2762 | +10.0% | +18.5% | +33.4% | 1.2970 | +11.2% | +20.4% | +35.8% |
| **1350** | 1.2736 | +8.4% | +33.2% | +36.0% | 1.2829 | +10.5% | +34.8% | +32.6% |
| **1360** | 1.2766 | +7.5% | +33.5% | +35.3% | 1.3046 | +7.9% | +32.7% | +30.2% |
| **1420** | 1.2152 | +10.3% | +32.5% | +37.6% | 1.2522 | +7.8% | +32.2% | +32.2% |
| **1500** | 1.2202 | +12.6% | +32.8% | +34.6% | 1.2334 | +14.2% | +33.5% | +34.1% |
| **1536** | 1.1162 | +16.3% | +18.4% | +39.8% | 1.1278 | +17.2% | +20.1% | +37.4% |
| **1537** | 1.2836 | +5.8% | +23.4% | +30.8% | 1.3006 | +4.5% | +24.2% | +28.1% |
| **1600** | 1.2613 | +4.3% | +7.1% | +30.3% | 1.2669 | +5.1% | +10.4% | +25.8% |
| **1984** | 1.0862 | +3.6% | +7.5% | +38.6% | 1.0941 | +5.3% | +9.9% | +33.6% |
| **2048** † | 1.0234 | +13.0% | +7.4% | +41.4% | 1.0339 | +14.8% | +6.7% | +38.7% |
| **2049** | 1.1007 | +13.3% | +17.0% | +36.9% | 1.1036 | +13.2% | +20.6% | +35.7% |
| **2176** | 1.2245 | -2.3% | +10.4% | +28.7% | 1.2110 | -0.1% | +14.0% | +31.5% |
| **2432** | 1.1264 | +3.1% | +11.5% | +34.9% | 1.1440 | +2.7% | +10.2% | +30.3% |
| **2560** | 1.0949 | +5.8% | +8.9% | +34.1% | 1.1078 | +5.8% | +7.0% | +33.0% |
| **4096** † | 1.0226 | +1.9% | +1.5% | +35.2% | 1.0242 | +3.7% | +3.6% | +34.1% |
| **4229** | 1.0767 | -1.2% | +16.6% | +31.2% | 1.0833 | -2.2% | +16.7% | +31.6% |
| **8192** † | 0.9503 | +2.5% | +5.9% | +35.7% | 0.9569 | +3.7% | +5.2% | +35.7% |
| **9000** | 0.9724 | -1.3% | +10.1% | +33.7% | 0.9808 | -0.7% | +10.7% | +33.8% |
| **16384** † | 0.9084 | +3.8% | +8.4% | +37.9% | 0.9030 | +5.1% | +9.1% | +37.5% |
| **16385** | 0.9215 | +3.6% | +9.5% | +35.6% | 0.9328 | +2.3% | +9.2% | +35.5% |
| **32768** † | 0.8926 | +3.6% | +9.3% | +37.2% | 0.8832 | +4.7% | +10.1% | +37.9% |
| **65536** † | 0.8872 | +3.2% | +9.3% | +37.7% | 0.8982 | +2.0% | +8.2% | +37.0% |

† sits exactly on a kernel batch boundary — see the note above.

### Raw ChaCha20 stream — AVX2

| workload | bytes | ours (9x) c/B | OpenSSL 8x c/B | BoringSSL c/B | Intel c/B | ours GB/s | ours vs best other |
|---|---|---:|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.2942 | 1.3078 | 1.3121 | 1.2947 | 2.32 | +0.0% |
| WireGuard / IPsec | 1360-1420 | 1.1982 | 1.1975 | 1.2024 | 1.2649 | 2.50 | -0.1% |
| Tuned web TLS | 4096-4229 | 1.0819 | 1.1611 | 1.1646 | 1.1438 | 2.77 | +5.4% |
| Jumbo VPN | 8900-9000 | 1.0010 | 1.0894 | 1.0926 | 1.1034 | 3.00 | +8.1% |
| TLS 1.3 record | 16384-16385 | 0.9858 | 1.0709 | 1.0718 | 1.0851 | 3.04 | +7.9% |
| Bulk transfer | 32-64 KiB | 0.9761 | 1.0536 | 1.0542 | 1.0712 | 3.07 | +7.3% |

### Raw ChaCha20 stream — AVX-512

BoringSSL has no AVX-512 ChaCha20, so it is absent here.

| workload | bytes | ours (17x/32x) c/B | OpenSSL 16x c/B | Intel c/B | ours GB/s | ours vs best other |
|---|---|---:|---:|---:|---:|---:|
| QUIC / HTTP-3 | 1200-1350 | 1.1169 | 1.1321 | 0.8865 | 2.69 | -26.0% |
| WireGuard / IPsec | 1360-1420 | 1.0224 | 1.0340 | 0.8779 | 2.93 | -16.5% |
| Tuned web TLS | 4096-4229 | 0.7028 | 0.8293 | 0.7398 | 4.27 | +5.0% |
| Jumbo VPN | 8900-9000 | 0.6541 | 0.7108 | 0.6931 | 4.59 | +5.6% |
| TLS 1.3 record | 16384-16385 | 0.6318 | 0.7077 | 0.6836 | 4.75 | +7.6% |
| Bulk transfer | 32-64 KiB | 0.6240 | 0.6859 | 0.6713 | 4.81 | +7.0% |

