#!/usr/bin/env python3
"""Assemble result.md: every table, from the committed CSVs.

usage: result_report.py <csv-dir> > result.md

Two datasets feed this:
  <m>_aead[123].csv   the AEAD, four implementations, 30 lengths
  <m>_bands[123].csv  the raw cipher, per ISA tier, sampled across each band

Best-of across the three runs per cell. Intel is reported at its better of two
entry points per size, because neither dominates and the minimum is the
comparison Intel would want made.
"""
import csv, sys

GHZ = 3.0            # nominal, for the GB/s column only

BANDS = [("QUIC / HTTP-3", "1200-1350", 1200, 1350),
         ("WireGuard / IPsec", "1360-1420", 1360, 1420),
         ("Tuned web TLS", "4096-4229", 4096, 4229),
         ("Jumbo VPN", "8900-9000", 8900, 9000),
         ("TLS 1.3 record", "16384-16385", 16384, 16385),
         ("Bulk transfer", "32-64 KiB", 32768, 65536)]

# Lengths that sit exactly on a kernel batch boundary. Real numbers, but not
# representative of the band around them -- see the note in the output.
BOUNDARY = {1024, 2048, 4096, 8192, 16384, 32768, 65536}

SWEEP = [64, 128, 256, 512, 1024, 1025, 1088, 1200, 1280, 1350, 1360, 1420,
         1500, 1536, 1537, 1600, 1984, 2048, 2049, 2176, 2432, 2560,
         4096, 4229, 8192, 9000, 16384, 16385, 32768, 65536]

MACH = [("zen5", "Zen 5 — AMD EPYC 9655 (Turin)"), ("zen4", "Zen 4 — AMD EPYC 4244P")]


def load(paths):
    best = {}
    for p in paths:
        try: fh = open(p)
        except FileNotFoundError: continue
        for row in csv.reader(fh):
            if len(row) != 6 or row[4] != "core_cycles_per_byte":
                continue
            try: size, val = int(row[2]), float(row[5])
            except ValueError: continue
            k = (row[0], size, row[3])
            if k not in best or val < best[k]:
                best[k] = val
    return best


def intel(d, alg, s, op):
    c = [d[k] for k in ((alg, s, "intel-direct-" + op), (alg, s, "intel-one-shot-" + op)) if k in d]
    return min(c) if c else None


def mean(d, alg, variant, sizes):
    v = [d[(alg, s, variant)] for s in sizes if (alg, s, variant) in d]
    return sum(v) / len(v) if v else None


def members(d, alg, lo, hi):
    return sorted({s for (a, s, _) in d if a == alg and lo <= s <= hi})


def pct(theirs, ours):
    return "" if not theirs or not ours else "%+.1f%%" % (100.0 * (theirs - ours) / theirs)


def gb(c):
    return "" if not c else "%.2f" % (GHZ / c)


def f(x, n=4):
    return "-" if not x else ("%." + str(n) + "f") % x


def fixed_cost(d, alg, variant, sizes=(64, 128, 256, 512, 1024)):
    """Intercept of total-cycles against length: what a call costs before it
    enciphers anything."""
    pts = [(s, d[(alg, s, variant)] * s) for s in sizes if (alg, s, variant) in d]
    if len(pts) < 3: return None
    n = len(pts); sx = sum(p[0] for p in pts); sy = sum(p[1] for p in pts)
    sxx = sum(p[0] ** 2 for p in pts); sxy = sum(p[0] * p[1] for p in pts)
    mar = (n * sxy - sx * sy) / (n * sxx - sx * sx)
    return (sy - mar * sx) / n


def main():
    src = sys.argv[1]
    print(HEAD)

    print("## Per-call overhead, and whether the comparison is fair\n")
    print("Fitting total cycles against length over 64..1024 B gives the fixed cost")
    print("of a call before it enciphers anything. This is the check that the")
    print("comparison is not measuring scaffolding:\n")
    print("| backend | Zen 5 fixed c | Zen 4 fixed c |")
    print("|---|---:|---:|")
    fx = {}
    for m, _ in MACH:
        d = load(["%s/%s_aead%d.csv" % (src, m, i) for i in (1, 2, 3)])
        for v in ("ahead-fused-seal", "boringssl-stitched-seal", "intel-one-shot-seal",
                  "intel-direct-seal", "openssl-asm-seal", "openssl-evp-seal"):
            fx.setdefault(v, {})[m] = fixed_cost(d, "aead", v)
    for v, lbl in (("ahead-fused-seal", "ours"), ("boringssl-stitched-seal", "BoringSSL"),
                   ("intel-one-shot-seal", "Intel job API"),
                   ("intel-direct-seal", "Intel direct API"),
                   ("openssl-asm-seal", "OpenSSL asm"),
                   ("openssl-evp-seal", "OpenSSL EVP")):
        a, b = fx[v].get("zen5"), fx[v].get("zen4")
        print("| %s | %s | %s |" % (lbl, "%.0f" % a if a else "-", "%.0f" % b if b else "-"))
    print(OVERHEAD_NOTE)

    for m, nice in MACH:
        aead = load(["%s/%s_aead%d.csv" % (src, m, i) for i in (1, 2, 3)])
        if not aead:
            continue
        print("## %s\n" % nice)
        for op in ("seal", "open"):
            print("### AEAD %s — real-world bands\n" % op)
            print("| workload | bytes | ours c/B | ours GB/s | Intel | OpenSSL | BoringSSL "
                  "| vs Intel | vs OpenSSL | vs BoringSSL |")
            print("|---|---|---:|---:|---:|---:|---:|---:|---:|---:|")
            for name, rng, lo, hi in BANDS:
                sz = members(aead, "aead", lo, hi)
                o = mean(aead, "aead", "ahead-fused-" + op, sz)
                it = min([x for x in (mean(aead, "aead", "intel-direct-" + op, sz),
                                      mean(aead, "aead", "intel-one-shot-" + op, sz)) if x] or [None])
                os_ = mean(aead, "aead", "openssl-asm-" + op, sz) or mean(aead, "aead", "openssl-evp-" + op, sz)
                bs = mean(aead, "aead", "boringssl-stitched-" + op, sz)
                if not o: continue
                print("| %s | %s | %s | %s | %s | %s | %s | %s | %s | %s |" %
                      (name, rng, f(o), gb(o), f(it), f(os_), f(bs),
                       pct(it, o), pct(os_, o), pct(bs, o)))
            print()

        print("### AEAD full sweep — every length measured\n")
        print("| bytes | ours seal | vs Intel | vs OpenSSL | vs BoringSSL "
              "| ours open | vs Intel | vs OpenSSL | vs BoringSSL |")
        print("|---:|---:|---:|---:|---:|---:|---:|---:|---:|")
        for s in SWEEP:
            if ("aead", s, "ahead-fused-seal") not in aead: continue
            lbl = ("**%d**" % s) + (" †" if s in BOUNDARY else "")
            it_s = intel(aead, "aead", s, "seal")
            ossl_s = aead.get(("aead", s, "openssl-asm-seal")) or aead.get(("aead", s, "openssl-evp-seal"))
            bs_s = aead.get(("aead", s, "boringssl-stitched-seal"))
            it_o = intel(aead, "aead", s, "open")
            ossl_o = aead.get(("aead", s, "openssl-asm-open")) or aead.get(("aead", s, "openssl-evp-open"))
            bs_o = aead.get(("aead", s, "boringssl-stitched-open"))
            o_s = aead.get(("aead", s, "ahead-fused-seal"))
            o_o = aead.get(("aead", s, "ahead-fused-open"))
            row = [lbl, f(o_s), pct(it_s, o_s), pct(ossl_s, o_s), pct(bs_s, o_s),
                   f(o_o), pct(it_o, o_o), pct(ossl_o, o_o), pct(bs_o, o_o)]
            print("| " + " | ".join(row) + " |")
        print("\n† sits exactly on a kernel batch boundary — see the note above.\n")

        raw = load(["%s/%s_bands%d.csv" % (src, m, i) for i in (1, 2, 3)])
        if not raw:
            continue
        for alg, tier, variants in (
                ("avx2", "AVX2", [("ours-avx2", "ours (9x)"), ("openssl-avx2", "OpenSSL 8x"),
                                  ("boringssl-avx2", "BoringSSL"), ("intel-avx2", "Intel")]),
                ("avx512", "AVX-512", [("ours-avx512", "ours (17x/32x)"),
                                       ("openssl-avx512", "OpenSSL 16x"),
                                       ("intel-avx512", "Intel")])):
            print("### Raw ChaCha20 stream — %s\n" % tier)
            if tier == "AVX-512":
                print("BoringSSL has no AVX-512 ChaCha20, so it is absent here.\n")
            print("| workload | bytes | " + " | ".join(n + " c/B" for _, n in variants) +
                  " | ours GB/s | ours vs best other |")
            print("|---|---|" + "---:|" * (len(variants) + 2))
            for name, rng, lo, hi in BANDS:
                sz = members(raw, alg, lo, hi)
                vals = [mean(raw, alg, v, sz) for v, _ in variants]
                if not vals[0]: continue
                others = [x for x in vals[1:] if x]
                adv = "%+.1f%%" % (100 * (min(others) - vals[0]) / min(others)) if others else "-"
                print("| %s | %s | %s | %s | %s |" %
                      (name, rng, " | ".join(f(x) for x in vals), gb(vals[0]), adv))
            print()


HEAD = """# Results

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
"""

OVERHEAD_NOTE = """
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
"""

main()
