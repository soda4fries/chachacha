#!/usr/bin/env python3
"""Render the benchmark figures as standalone SVGs.

Bars are cycles per byte. The label on each bar also gives GB/s at a nominal
3.0 GHz, in brackets, because c/B is the honest unit for comparing kernels
(it is frequency-independent) while GB/s is the one people have intuition for.
The clock is nominal and stated as such -- neither host was pinned to it.

Grouped horizontal bars: workload band on the vertical axis, one bar per
implementation. Horizontal because the band labels are phrases, not numbers.
Lower is better, so shorter is better, and every bar carries its own value --
which is also what satisfies the light-mode contrast requirement, since two of
the four series sit under 3:1 against the light surface.

Colour is assigned per implementation and fixed across every figure, so Intel is
the same hue in the AVX-512 charts even though BoringSSL is absent there; a
series' colour never depends on its rank or on who else is present.

Palette is the dataviz reference categorical theme, slots 1-4, validated for
both surfaces (worst adjacent pair protan dE 9.1 light / 8.4 dark).
"""
import csv, sys, os

LIGHT = {"surface": "#fcfcfb", "text": "#0b0b0b", "muted": "#52514e",
         "grid": "#e4e3df", "axis": "#c9c8c2"}
DARK  = {"surface": "#1a1a19", "text": "#ffffff", "muted": "#c3c2b7",
         "grid": "#333331", "axis": "#4a4a47"}
SERIES = {                       # implementation -> (light, dark)
    "ours":      ("#2a78d6", "#3987e5"),
    "openssl":   ("#eb6834", "#d95926"),
    "boringssl": ("#1baf7a", "#199e70"),
    "intel":     ("#eda100", "#c98500"),
}

# Bands are ranges; membership is whatever lengths the dataset actually holds
# inside each range.  The raw sweep samples every band densely, the AEAD matrix
# samples the protocol points -- deriving membership from the data keeps both
# figure sets on one band definition without pretending to samples that are not
# there.
BANDS = [("QUIC / HTTP-3", "1200–1350", 1200, 1350),
         ("WireGuard / IPsec", "1360–1420", 1360, 1420),
         ("Tuned web TLS", "4096–4229", 4096, 4229),
         ("Jumbo VPN", "8900–9000", 8900, 9000),
         ("TLS 1.3 record", "16384–16385", 16384, 16385),
         ("Bulk transfer", "32–64 KiB", 32768, 65536)]


def members(d, alg, lo, hi):
    return sorted({s for (a, s, _) in d if a == alg and lo <= s <= hi})


def load(paths):
    best = {}
    for p in paths:
        for row in csv.reader(open(p)):
            if len(row) != 6 or row[4] != "core_cycles_per_byte":
                continue
            try: size, val = int(row[2]), float(row[5])
            except ValueError: continue
            k = (row[0], size, row[3])
            if k not in best or val < best[k]:
                best[k] = val
    return best


def band_mean(d, alg, variant, sizes):
    v = [d[(alg, s, variant)] for s in sizes if (alg, s, variant) in d]
    return sum(v) / len(v) if v else None


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


GHZ = 3.0   # nominal, for the bracketed GB/s only


def gbps(cpb):
    return GHZ * 1e9 / cpb / 1e9


def svg(title, subtitle, groups, series, path):
    """groups: [(label, sublabel, {series_key: value})]; series: [(key, name)]"""
    n_g, n_s = len(groups), len(series)
    bar, gap, grp_gap = 15, 2, 22
    left, right, top = 168, 150, 96
    row_h = n_s * bar + (n_s - 1) * gap
    plot_h = n_g * row_h + (n_g - 1) * grp_gap
    plot_w = 430
    W, H = left + plot_w + right, top + plot_h + 62
    vmax = max(v for _, _, vals in groups for v in vals.values() if v) * 1.16

    def x(v): return left + plot_w * v / vmax

    ticks = []
    step = 0.1 if vmax <= 0.7 else (0.2 if vmax <= 1.6 else 0.4)
    t = 0.0
    while t <= vmax:
        ticks.append(round(t, 2)); t += step

    o = ['<svg xmlns="http://www.w3.org/2000/svg" width="%d" height="%d" '
         'viewBox="0 0 %d %d" font-family="ui-sans-serif,-apple-system,'
         'Segoe UI,Roboto,Helvetica,Arial,sans-serif">' % (W, H, W, H)]
    css = ["  .sf{fill:%s}.tx{fill:%s}.mu{fill:%s}.gr{stroke:%s}.ax{stroke:%s}"
           % (LIGHT["surface"], LIGHT["text"], LIGHT["muted"], LIGHT["grid"], LIGHT["axis"])]
    for k, (lt, _) in SERIES.items():
        css.append("  .s-%s{fill:%s}" % (k, lt))
    dark = ["    .sf{fill:%s}.tx{fill:%s}.mu{fill:%s}.gr{stroke:%s}.ax{stroke:%s}"
            % (DARK["surface"], DARK["text"], DARK["muted"], DARK["grid"], DARK["axis"])]
    for k, (_, dk) in SERIES.items():
        dark.append("    .s-%s{fill:%s}" % (k, dk))
    o.append("<style>\n" + "\n".join(css) +
             "\n  @media (prefers-color-scheme:dark){\n" + "\n".join(dark) + "\n  }\n</style>")
    o.append('<rect class="sf" width="%d" height="%d"/>' % (W, H))
    o.append('<text class="tx" x="24" y="34" font-size="16" font-weight="600">%s</text>' % esc(title))
    o.append('<text class="mu" x="24" y="54" font-size="11.5">%s</text>' % esc(subtitle))

    # legend, in fixed series order so identity never depends on who is present
    lx = 24
    for k, name in series:
        o.append('<rect class="s-%s" x="%d" y="66" width="9" height="9" rx="2"/>' % (k, lx))
        o.append('<text class="mu" x="%d" y="74.5" font-size="11">%s</text>' % (lx + 14, esc(name)))
        lx += 20 + int(6.1 * len(name))

    for tv in ticks:                       # recessive grid
        o.append('<line class="gr" x1="%.1f" y1="%d" x2="%.1f" y2="%d" stroke-width="1"/>'
                 % (x(tv), top - 8, x(tv), top + plot_h + 4))
        o.append('<text class="mu" x="%.1f" y="%d" font-size="10" text-anchor="middle" '
                 'font-variant-numeric="tabular-nums">%.1f</text>'
                 % (x(tv), top + plot_h + 22, tv))
    o.append('<text class="mu" x="%.1f" y="%d" font-size="10.5" text-anchor="middle">'
             'cycles per byte — lower is better · GB/s in brackets at a nominal 3.0 GHz</text>'
             % (left + plot_w / 2, top + plot_h + 44))
    o.append('<line class="ax" x1="%d" y1="%d" x2="%d" y2="%d" stroke-width="1"/>'
             % (left, top - 8, left, top + plot_h + 4))

    y = top
    for label, sub, vals in groups:
        o.append('<text class="tx" x="%d" y="%.1f" font-size="12" text-anchor="end">%s</text>'
                 % (left - 12, y + row_h / 2 - 2, esc(label)))
        unit = "" if "KiB" in sub else " B"
        o.append('<text class="mu" x="%d" y="%.1f" font-size="10" text-anchor="end">%s%s</text>'
                 % (left - 12, y + row_h / 2 + 12, esc(sub), unit))
        for k, _ in series:
            v = vals.get(k)
            if v:
                w = max(x(v) - left, 3)
                o.append('<rect class="s-%s" x="%d" y="%.1f" width="%.1f" height="%d" rx="4"/>'
                         % (k, left, y, w, bar))
                o.append('<rect class="s-%s" x="%d" y="%.1f" width="4" height="%d"/>'
                         % (k, left, y, bar))     # square off the baseline end
                o.append('<text class="mu" x="%.1f" y="%.1f" font-size="9.5" '
                         'font-variant-numeric="tabular-nums">%.3f (%.1f GB/s)</text>'
                         % (left + w + 6, y + bar - 3.5, v, gbps(v)))
            y += bar + gap
        y += grp_gap - gap
    o.append("</svg>")
    open(path, "w").write("\n".join(o) + "\n")
    return path


def main():
    """usage: make_figures.py <csv-dir> <out-dir>"""
    src, out = sys.argv[1], sys.argv[2]
    os.makedirs(out, exist_ok=True)
    made = []
    for mach, nice in (("zen5", "Zen 5 (EPYC 9655 Turin)"), ("zen4", "Zen 4 (EPYC 4244P)")):
        raw = load(["%s/%s_bands%d.csv" % (src, mach, i) for i in (1, 2, 3)])
        for alg, tier, ser in (
                ("avx2", "AVX2", [("ours", "ours (9x)"), ("openssl", "OpenSSL 8x"),
                                  ("boringssl", "BoringSSL"), ("intel", "Intel IPsec-MB")]),
                ("avx512", "AVX-512", [("ours", "ours (17x/32x)"), ("openssl", "OpenSSL 16x"),
                                       ("intel", "Intel IPsec-MB")])):
            groups = []
            for name, rng, lo, hi in BANDS:
                sizes = members(raw, alg, lo, hi)
                vals = {k: band_mean(raw, alg, "%s-%s" % (k, alg)
                                     if k != "boringssl" else "boringssl-avx2", sizes)
                        for k, _ in ser}
                if vals.get("ours"):
                    groups.append((name, rng, vals))
            if groups:
                made.append(svg("Raw ChaCha20 stream — %s" % tier,
                                "%s · mean over each workload band, core cycles, "
                                "best of 3 alternating runs" % nice,
                                groups, ser, "%s/raw_%s_%s.svg" % (out, alg, mach)))

        aead = load(["%s/%s_aead%d.csv" % (src, mach, i) for i in (1, 2, 3)])
        for op in ("seal", "open"):
            ser = [("ours", "ours"), ("intel", "Intel IPsec-MB"),
                   ("openssl", "OpenSSL"), ("boringssl", "BoringSSL (AVX2)")]
            groups = []
            for name, rng, lo, hi in BANDS:
                sizes = members(aead, "aead", lo, hi)
                def best_of(cands):
                    v = [band_mean(aead, "aead", c, sizes) for c in cands]
                    v = [x for x in v if x]
                    return min(v) if v else None
                vals = {"ours": band_mean(aead, "aead", "ahead-fused-" + op, sizes),
                        "intel": best_of(["intel-direct-" + op, "intel-one-shot-" + op]),
                        "openssl": band_mean(aead, "aead", "openssl-asm-" + op, sizes) or
                                   band_mean(aead, "aead", "openssl-evp-" + op, sizes),
                        "boringssl": band_mean(aead, "aead", "boringssl-stitched-" + op, sizes)}
                if vals["ours"]:
                    groups.append((name, rng, vals))
            if groups:
                made.append(svg("ChaCha20-Poly1305 AEAD — %s" % op,
                                "%s · mean over each workload band; Intel at its "
                                "better entry point per size" % nice,
                                groups, ser, "%s/aead_%s_%s.svg" % (out, op, mach)))
    for m in made:
        print(m)


main()
