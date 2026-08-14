#!/usr/bin/env python3
"""Real-world size summary from bench_aead_matrix CSVs: ours vs Intel vs BoringSSL."""
import sys

def load(paths):
    best = {}
    for p in paths:
        for line in open(p):
            f = line.strip().split(',')
            if len(f) != 6 or f[4] != 'core_cycles_per_byte':
                continue
            try: s, v = int(f[2]), float(f[5])
            except ValueError: continue
            k = (s, f[3])
            if k not in best or v < best[k]: best[k] = v
    return best

REAL = [(1280, "QUIC / HTTP-3"), (1420, "WireGuard IPv4"), (1500, "Ethernet MTU"),
        (2048, "2 KB TLS record"), (4096, "4 KB TLS record"), (9000, "Jumbo VPN"),
        (16384, "TLS 1.3 record"), (16385, "TLS 1.3 + type byte"), (65536, "Bulk transfer")]

def intel(d, s, op):
    """Intel's better of two invocation paths at this size.

    Neither dominates: the job-submit path wins below ~2 KB and at 9000 B, the
    documented single-buffer API wins at 2048, 4096, 16384.  Taking the minimum
    is the comparison Intel would want made."""
    c = [d[k] for k in ((s,'intel-direct-'+op), (s,'intel-one-shot-'+op)) if k in d]
    return min(c) if c else None

def main():
    label = sys.argv[1]
    d = load(sys.argv[2:])
    print("### %s\n" % label)
    print("| size | protocol | ours seal | Intel seal | vs Intel | ours open | Intel open | vs Intel |")
    print("|---:|---|---:|---:|---:|---:|---:|---:|")
    for s, name in REAL:
        os_, oo = d[(s,'ahead-fused-seal')], d[(s,'ahead-fused-open')]
        is_, io = intel(d,s,'seal'), intel(d,s,'open')
        print("| %d | %s | %.3f | %.3f | %+.1f%% | %.3f | %.3f | %+.1f%% |"
              % (s, name, os_, is_, 100*(is_-os_)/is_, oo, io, 100*(io-oo)/io))

main()
