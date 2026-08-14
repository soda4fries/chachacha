#!/usr/bin/env python3
# Copyright 2026 soda4fries
# SPDX-License-Identifier: Apache-2.0
"""Compose tools/parts_bench CSV into per-size accounting and a top-k table.

    ./build/parts_bench > parts.csv && tools/topk.py parts.csv

The path models below mirror aead512.pl.  If a dispatch decision there changes,
change it here too -- the residual is the check: it is glue (wrapper, prologue,
frame spills, call overhead) and has run 3-9%.  A residual that jumps means the
model no longer matches the code, not that the code got slower.
"""
import sys, collections

FILL = 1024          # bytes the aligned key+data fill covers
CAP  = 384           # pending bytes the 257..512 residue drain authenticates

def parts(path):
    p, e = {}, {}
    for line in open(path):
        f = line.strip().split(',')
        if f[0] == 'part': p[f[1]] = float(f[2])
        elif f[0] == 'e2e': e[(f[1], int(f[2]))] = float(f[3])
    return p, e

def interp(p, prefix, n):
    """Cost of <prefix><n>, interpolated from the two nearest measured points."""
    pts = sorted((int(k[len(prefix):]), v) for k, v in p.items() if k.startswith(prefix))
    if not pts: raise KeyError(prefix)
    for i, (x, y) in enumerate(pts):
        if x == n: return y
    lo = max([q for q in pts if q[0] < n], default=pts[0])
    hi = min([q for q in pts if q[0] > n], default=pts[-1])
    if lo[0] == hi[0]: return lo[1]
    s = (hi[1] - lo[1]) / (hi[0] - lo[0])
    return lo[1] + s * (n - lo[0])

def finish(exposed):
    """Label the engine aead512.pl actually finishes an exposed suffix with.

    Below 768 bytes it runs the inline scalar poly_add/poly_mul loop, not IFMA.
    parts_bench cannot time that loop -- it has no symbol -- so the term is
    still priced from the smallest measured IFMA finish, which over-charges it.
    That is why the four rows under 1024 bytes carry a large negative residual
    and have done since before the narrow fill; it is a gap in this model, not
    unaccounted time in the kernel.  The rows from 1024 up are the ones whose
    residual is meaningful as a self-check.
    """
    return ('%s finish %d' % ('scalar' if exposed < 768 else 'IFMA', exposed))

def model(p, size):
    """Return [(label, cycles)] for a seal of |size| bytes, aad 13."""
    fill = min(size, FILL)
    it = [('fill %d (%s)' % (fill, 'narrow' if 64 + fill <= 512 else '17x_key'),
           interp(p, 'chacha_fill_', fill)),
          ('AD 13 B', p['ifma_update_13'])]
    rest = size - FILL
    if rest <= 0: return it + [(finish(size), interp(p, 'ifma_finish_', size))]
    if rest > 1024 and rest <= 1536:                    # two-pass branch
        return it + [('ChaCha20 two-pass %d' % rest, interp(p, 'chacha_tail_', min(rest, 1024))),
                     ('IFMA finish %d' % size, interp(p, 'ifma_finish_', 1420))]
    chunks, resid = divmod(rest, 1024)
    if chunks:
        it.append(('pow32', p['pow32']))
        it.append(('%d x ChaCha20_16x_mac' % chunks, chunks * p['chacha_16x_mac_1024']))
        it.append(('%d x gmul44_fast' % chunks, chunks * p['gmul44_fast']))
    if resid == 0:
        it.append(('IFMA finish 1024 (pending)', interp(p, 'ifma_finish_', 1024)))
    else:
        if resid <= 128:   drain, cap = 'mac128_128', 128
        elif resid <= 256: drain, cap = 'mac256_256', 256
        elif resid <= 512: drain, cap = 'mac512_396', CAP
        else:              drain, cap = 'chacha_16x_mac_1024', 1024   # two-chain drain
        it.append(('drain %s (%d B resid)' % (drain, resid), p[drain]))
        if cap == 1024: it.append(('drain gmul44_fast', p['gmul44_fast']))
        it.append((finish(1024 - cap + resid),
                   interp(p, 'ifma_finish_', 1024 - cap + resid)))
    return it

def main(path, k=6):
    p, e = parts(path)
    for (direc, size) in sorted(e):
        if direc != 'seal': continue
        rows = model(p, size)
        tot = e[(direc, size)]
        s = sum(v for _, v in rows)
        rows.append(('glue / prologue / spills (residual)', tot - s))
        print('seal(%d) = %.0f cycles   [parts %.0f, residual %.0f = %.1f%%]'
              % (size, tot, s, tot - s, 100 * (tot - s) / tot))
        for label, v in sorted(rows, key=lambda r: -r[1])[:k]:
            print('    %-38s %8.1f  %5.1f%%' % (label, v, 100 * v / tot))
        print()

if __name__ == '__main__':
    main(sys.argv[1] if len(sys.argv) > 1 else 'parts.csv')
