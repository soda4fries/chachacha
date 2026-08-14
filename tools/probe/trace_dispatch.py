#!/usr/bin/env python3
"""Count cipher bytes per kernel by interposing at the link, not by patching text.

Each traced kernel is renamed inside its object and replaced by a shim that bumps
a call counter, adds %rdx (the length argument for every ChaCha entry here) to a
byte counter, and jumps to the original.  Cross-object calls from aead512_core.o
therefore land on the shim; intra-object jumps are unaffected, which is exactly
the granularity we want -- we are asking which kernels the AEAD *dispatches* to.
"""
import subprocess, sys, os
BUILD = sys.argv[1]
OUT = sys.argv[2]
# symbol -> object that defines it
SYMS = {
 'ChaCha20_16x_mac':      'aead_mac.o',
 'ChaCha20_16x_mac1024':  'aead_mac_partial.o',
 'ChaCha20_16x_mac512':   'aead_mac_partial.o',
 'ChaCha20_16x_mac256':   'aead_mac_partial.o',
 'ChaCha20_16x_mac128':   'aead_mac_partial.o',
 'ChaCha20_17x':          'chacha_kernels_core.o',
 'ChaCha20_17x_key':      'chacha_kernels_core.o',
 'ChaCha20_tail_avx512':  'chacha_kernels_core.o',
 'ChaCha20_16x':          'chacha_kernels_core.o',
 'ChaCha20_16x_tiered':   'chacha_kernels_core.o',
 'ChaCha20_32x':          'chacha_kernels_core.o',
 'poly1305_aead_update_fma_avx512':   'poly1305_ifma.o',
 'poly1305_aead_complete_fma_avx512': 'poly1305_ifma.o',
 'poly1305_aead_finish_fma_avx512':   'poly1305_ifma.o',
 'poly1305_pow32':        'poly1305_pow.o',
 'poly1305_pow44':        'poly1305_pow.o',
 'poly1305_gmul44_fast':  'poly1305_pow.o',
}
objs = sorted(set(SYMS.values()))
os.makedirs(OUT, exist_ok=True)
for o in objs:
    args = []
    for s, obj in SYMS.items():
        if obj == o:
            args += ['--redefine-sym', '%s=real_%s' % (s, s)]
    subprocess.run(['objcopy'] + args + [os.path.join(BUILD, o),
                                         os.path.join(OUT, o)], check=True)
asm = ['.text']
for s in SYMS:
    asm += ['.globl %s' % s, '.type %s,@function' % s, '%s:' % s,
            '\tincq\tcalls_%s(%%rip)' % s,
            '\taddq\t%%rdx,bytes_%s(%%rip)' % s,
            '\taddq\t%%rsi,rsi_%s(%%rip)' % s,
            '\tjmp\treal_%s' % s,
            '.size %s,.-%s' % (s, s)]
asm += ['.data']
for s in SYMS:
    asm += ['.globl calls_%s' % s, 'calls_%s: .quad 0' % s,
            '.globl bytes_%s' % s, 'bytes_%s: .quad 0' % s,
            '.globl rsi_%s' % s, 'rsi_%s: .quad 0' % s]
asm += ['.section .note.GNU-stack,"",@progbits']
open(os.path.join(OUT, 'shim.S'), 'w').write('\n'.join(asm) + '\n')
open(os.path.join(OUT, 'syms.txt'), 'w').write('\n'.join(SYMS) + '\n')
print('shimmed %d symbols across %s' % (len(SYMS), ', '.join(objs)))
