# Intel IPsec Multi-Buffer ChaCha20/Poly1305 kernel snapshot

Selected, unmodified files from Intel IPsec Multi-Buffer commit `6c146bf`.
They are retained here for implementation study and comparison with this
directory's fused ChaCha20-Poly1305 kernel. See `LICENSE` for Intel's license.

## Reading order

1. `x86_64/chacha20_poly1305.c` — orchestration. In
   `aead_chacha20_poly1305()`, encryption calls ChaCha first and Poly1305
   second; decryption calls them in the opposite order.
2. `avx512_t1/chacha20_avx512.asm` — AVX-512 ChaCha20. Search for
   `CHACHA20_ROUND` and `vprold`.
3. `avx512_t2/poly_fma_avx512.asm` — AVX-512 IFMA Poly1305. Search for
   `vpmadd52luq` and `vpmadd52huq`.
4. `avx512_t1/poly_avx512.asm` — non-IFMA AVX-512 Poly1305 fallback.
5. `avx2_t1/chacha20_avx2.asm` — AVX2 ChaCha20 and Poly1305 key generation.

The complete pinned `include/` macro tree is present, so the selected assembly
is a standalone build subset. The top-level project Makefile assembles it into
`build/vendor/` and namespaces the four direct API symbols to prevent collision
with similarly named helpers in the local kernel.

Upstream: https://github.com/intel/intel-ipsec-mb
