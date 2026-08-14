#!/usr/bin/env python3
"""Average the raw-cipher band sweep into one row per workload band per ISA tier.

Each band is sampled at several lengths rather than one convenient point, because
a length that happens to divide a kernel's batch is not representative of the band
around it.  Reported value is the mean cycles/byte over the band's samples.
"""
import sys, json

BANDS = [
    ("QUIC / HTTP-3",      "1200-1350",  [1200,1220,1240,1260,1280,1300,1330,1350]),
    ("WireGuard / IPsec",  "1360-1420",  [1360,1370,1380,1390,1400,1410,1420]),
    ("Tuned web TLS",      "4096-4229",  [4096,4115,4134,4153,4172,4191,4210,4229]),
    ("Jumbo VPN",          "8900-9000",  [8900,8915,8930,8945,8960,8975,8990,9000]),
    ("TLS 1.3 record",     "16384-16385",[16384,16385]),
    ("Bulk transfer",      "32-64 KiB",  [32768,40960,49152,57344,65536]),
]
TIERS = [("avx2",   "AVX2",    ["ours-avx2","openssl-avx2","boringssl-avx2","intel-avx2"]),
         ("avx512", "AVX-512", ["ours-avx512","openssl-avx512","intel-avx512"])]
LABEL = {"ours-avx2":"ours (9x)","openssl-avx2":"OpenSSL 8x","boringssl-avx2":"BoringSSL",
         "intel-avx2":"Intel IPsec-MB","ours-avx512":"ours (17x/32x)",
         "openssl-avx512":"OpenSSL 16x","intel-avx512":"Intel IPsec-MB"}

def load(paths):
    best = {}
    for p in paths:
        for line in open(p):
            f = line.strip().split(',')
            if len(f) != 6 or f[4] != 'core_cycles_per_byte': continue
            try: s, v = int(f[2]), float(f[5])
            except ValueError: continue
            k = (f[0], s, f[3])
            if k not in best or v < best[k]: best[k] = v
    return best

def mean(d, alg, variant, sizes):
    vals = [d[(alg,s,variant)] for s in sizes if (alg,s,variant) in d]
    return sum(vals)/len(vals) if len(vals) == len(sizes) else None

def main():
    label, out_json = sys.argv[1], sys.argv[2]
    d = load(sys.argv[3:])
    dump = {"machine": label, "tiers": []}
    print("## %s — raw ChaCha20 stream\n" % label)
    for alg, tier, variants in TIERS:
        rows = []
        print("### %s\n" % tier)
        cols = [LABEL[v] for v in variants]
        print("| workload band | bytes | " + " | ".join(c + " c/B" for c in cols) +
              " | ours vs best other |")
        print("|---|---|" + "---:|"*len(cols) + "---:|")
        for name, rng, sizes in BANDS:
            vals = [mean(d, alg, v, sizes) for v in variants]
            if vals[0] is None: continue
            others = [x for x in vals[1:] if x is not None]
            adv = 100*(min(others)-vals[0])/min(others) if others else 0.0
            print("| %s | %s | %s | %+.1f%% |" % (name, rng,
                  " | ".join("%.4f"%x if x else "-" for x in vals), adv))
            rows.append({"band": name, "range": rng,
                         "values": {LABEL[v]: x for v, x in zip(variants, vals)},
                         "advantage": adv})
        print()
        dump["tiers"].append({"tier": tier, "labels": cols, "rows": rows})
    json.dump(dump, open(out_json, "w"), indent=1)

main()
