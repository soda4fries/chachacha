# Pinned comparison sources

This directory contains source snapshots needed to reproduce the comparison
without linking an installed BoringSSL or Intel IPsec Multi-Buffer library.

| directory | upstream revision | contents |
|---|---|---|
| `openssl` | `bee02b7d509bbd6b49d70a2174f0a8a591883cc1` | raw ChaCha perlasm, translator, generated ELF assembly |
| `boringssl` | `52ba6a143e03e9ac84369f79ac3d06dea0128dab` | raw ChaCha and stitched ChaCha20-Poly1305 perlasm, generated ELF assembly, required assembly headers |
| `intel-ipsec-mb-kernels` | `6c146bf0906853af4f57868d7afe05c189d2739b` | AVX2/AVX-512 ChaCha and AVX-512 IFMA Poly1305 assembly with its NASM include tree |

The generated `.S` files are checked in deliberately. Regenerate and compile
all vendor objects with:

```sh
make vendor-objects
```

Build dependencies are GCC or Clang, Perl, GNU make, and NASM. On common Linux
distributions NASM is a single package (`apt install nasm`, `dnf install nasm`,
or `pacman -S nasm`). Intel's source is deeply tied to NASM macros, and the
local `poly1305_ifma.asm` already uses NASM, so mechanically translating only
the vendor files would add a second fragile assembly dialect without removing
the dependency.

`vendor_aead.c` exposes Intel's assembly directly. It does not construct an
`IMB_JOB`, enter the manager, or link `libIPSec_MB`: it calls Intel's Poly1305
key generation, AVX-512 ChaCha, and AVX-512 IFMA Poly1305 symbols itself.
BoringSSL's stitched AVX2 seal/open assembly is wrapped in the same detached-tag
call shape.

Build and run the correctness gate:

```sh
make vendor-test
```

Run the complete benchmark table (23 lengths, with no losing rows omitted):

```sh
./build/vendor_harness
```

The harness first checks Intel-direct, BoringSSL-stitched, and the local
ahead/fused AEAD against OpenSSL EVP, including corrupted-tag rejection. It then
prints seal and open cycles/byte for every length in the findings table. Intel
rows require AVX2, AVX-512F/BW/VL, and AVX-512IFMA; BoringSSL rows require AVX2
and BMI2. Unsupported backends are printed as `SKIP` rather than silently
removed.

The separately compiled OpenSSL and BoringSSL raw ChaCha objects are retained
for the 9x/17x raw-kernel tests. They are intentionally not linked into the AEAD
harness: OpenSSL raw ChaCha is not a stitched AEAD implementation.
