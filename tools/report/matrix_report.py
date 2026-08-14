#!/usr/bin/env python3
"""Turn bench_aead_matrix CSVs into the comparison tables.

Reports, per size, our cycles/byte against Intel IPsec-MB and BoringSSL, all
measured in the same binary and the same alternating run, so no figure pairs
numbers from different runs.  Best-of-N per cell.

Intel is reported through `imb_chacha20_poly1305_init/enc_update/enc_finalize`
-- the documented single-buffer entry points, which is what an application
encrypting one buffer calls and the fair match for our low-level entry.  The
harness also carries an `intel-one-shot` path that reaches an internal
submit_job by a pinned offset; it is slower, most visibly under 4 KB, and is
kept only for continuity with older result files.
"""
import sys, collections

def load(paths):
    best = {}
    for p in paths:
        for line in open(p):
            f = line.strip().split(',')
            if len(f) != 6 or f[4] != 'core_cycles_per_byte':
                continue
            try: size, val = int(f[2]), float(f[5])
            except ValueError: continue
            k = (size, f[3])
            if k not in best or val < best[k]: best[k] = val
    return best

BANDS = [
    (64,   "tiny"), (128, "tiny"), (256, "tiny"), (512, "tiny"), (1024, "tiny"),
    (1025, "one-dispatch edge"), (1088, "one-dispatch"), (1200, "QUIC"),
    (1280, "QUIC canonical"), (1350, "QUIC"), (1360, "WireGuard"),
    (1420, "WireGuard canonical"), (1500, "Ethernet MTU"),
    (1536, "one-dispatch"), (1537, "one-dispatch"), (1600, "one-dispatch"),
    (1984, "one-dispatch"), (2048, "2K TLS record"),
    (2049, "above the range"), (2176, ""), (2432, ""), (2560, ""),
    (4096, "Tuned TLS"), (4229, "Tuned TLS edge"), (8192, ""),
    (9000, "Jumbo VPN"), (16384, "TLS 1.3 record"), (16385, "TLS 1.3 +1B"),
    (32768, "bulk"), (65536, "bulk"),
]

def pct(a, b):
    return "" if (a is None or b is None) else "%+.1f%%" % (100.0 * (a - b) / a)

def main():
    m = sys.argv[1]
    n = (len(sys.argv) - 2) // 2
    before, after = load(sys.argv[2:2+n]), load(sys.argv[2+n:])
    print("## %s\n" % m)
    for op in ("seal", "open"):
        print("### %s\n" % op)
        print("| size | band | before c/B | after c/B | gain | Intel c/B | vs Intel | BoringSSL c/B | vs BoringSSL |")
        print("|---:|---|---:|---:|---:|---:|---:|---:|---:|")
        for size, band in BANDS:
            b  = before.get((size, 'ahead-fused-'+op))
            a  = after.get((size, 'ahead-fused-'+op))
            _c = [after[k] for k in ((size,'intel-direct-'+op),(size,'intel-one-shot-'+op)) if k in after]
            it = min(_c) if _c else None
            bs = after.get((size, 'boringssl-stitched-'+op))
            if a is None: continue
            row = [str(size), band, "%.4f"%b if b else "-", "%.4f"%a,
                   pct(b, a) if b else "-",
                   "%.4f"%it if it else "-", pct(it, a) if it else "-",
                   "%.4f"%bs if bs else "-", pct(bs, a) if bs else "-"]
            print("| " + " | ".join(row) + " |")
        print()

main()
