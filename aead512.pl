#!/usr/bin/env perl

# Copyright (c) 2015, CloudFlare Ltd.
# SPDX-License-Identifier: ISC
#
# Modifications Copyright 2026 soda4fries, SPDX-License-Identifier: Apache-2.0.
# See NOTICE for how this file's ISC-licensed base and its Apache-2.0-licensed
# modifications are attributed together.

if ($#ARGV < 1) { die "Not enough arguments provided.
  Two arguments are necessary: the flavour and the output file path."; }

$flavour = shift;
$output  = shift;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\"";
*STDOUT=*OUT;


$code.=<<___;
.text
.section .rodata
.align 16
.Lclamp:
.quad 0x0FFFFFFC0FFFFFFF, 0x0FFFFFFC0FFFFFFC
.quad 0xFFFFFFFFFFFFFFFF, 0xFFFFFFFFFFFFFFFF
.text
___

my ($oup,$inp,$inl,$adp,$keyp,$adl)=("%rdi","%rsi","%rbx","%rcx","%r9","%r8");
my ($acc0,$acc1,$acc2)=map("%r$_",(10..12));
my ($t0,$t1,$t2,$t3)=("%r13","%r14","%r15","%r9");
my $xmm_storage = $win64 ? 10*16 : 0;
my $xmm_store="0*16(%rbp)";
my $r_store="$xmm_storage+0*16(%rbp)";
my $s_store="$xmm_storage+1*16(%rbp)";
my $len_store="$xmm_storage+2*16(%rbp)";

sub emit_epilogue {
    my ($label,$name)=@_;
    $code.="$label:\n";
    $code.=<<___ if ($win64);
    movaps 16*0+$xmm_store, %xmm6
    movaps 16*1+$xmm_store, %xmm7
    movaps 16*2+$xmm_store, %xmm8
    movaps 16*3+$xmm_store, %xmm9
    movaps 16*4+$xmm_store, %xmm10
    movaps 16*5+$xmm_store, %xmm11
    movaps 16*6+$xmm_store, %xmm12
    movaps 16*7+$xmm_store, %xmm13
    movaps 16*8+$xmm_store, %xmm14
    movaps 16*9+$xmm_store, %xmm15
___
    $code.=<<___;
    add \$1056 + $xmm_storage + 32, %rsp
.cfi_adjust_cfa_offset -(1056 + 32)
    pop $keyp
.cfi_pop $keyp
    mov $acc0, ($keyp)
    mov $acc1, 8($keyp)
    pop %r15
.cfi_pop %r15
    pop %r14
.cfi_pop %r14
    pop %r13
.cfi_pop %r13
    pop %r12
.cfi_pop %r12
    pop %rbx
.cfi_pop %rbx
    pop %rbp
.cfi_pop %rbp
    ret
.cfi_endproc
.size $name,.-$name
___
}

sub poly_add {
my ($src)=@_;
$code.="add 0+$src, $acc0
        adc 8+$src, $acc1
        adc \$1, $acc2\n";
}

sub poly_stage1 {
$code.="mov 0+$r_store, %rax
        mov %rax, $t2
        mul $acc0
        mov %rax, $t0
        mov %rdx, $t1
        mov 0+$r_store, %rax
        mul $acc1
        imulq $acc2, $t2
        add %rax, $t1
        adc %rdx, $t2\n";
}

sub poly_stage2 {
$code.="mov 8+$r_store, %rax
        mov %rax, $t3
        mul $acc0
        add %rax, $t1
        adc \$0, %rdx
        mov %rdx, $acc0
        mov 8+$r_store, %rax
        mul $acc1
        add %rax, $t2
        adc \$0, %rdx\n";
}

sub poly_stage3 {
$code.="imulq $acc2, $t3
        add $acc0, $t2
        adc %rdx, $t3\n";
}

# At the beginning of the reduce stage t = [t3:t2:t1:t0] is a product of
# r = [r1:r0] and acc = [acc2:acc1:acc0]
# r is 124 bits at most (due to clamping) and acc is 131 bits at most
# (acc2 is at most 4 before the addition and can be at most 6 when we add in
# the next block) therefore t is at most 255 bits big, and t3 is 63 bits.
sub poly_reduce_stage {
$code.="mov $t0, $acc0
        mov $t1, $acc1
        mov $t2, $acc2
        and \$3, $acc2 # At this point acc2 is 2 bits at most (value of 3)
        mov $t2, $t0
        and \$-4, $t0
        mov $t3, $t1
        shrd \$2, $t3, $t2
        shr \$2, $t3
        add $t0, $t2
        adc $t1, $t3 # No carry out since t3 is 61 bits and t1 is 63 bits
        add $t2, $acc0
        adc $t3, $acc1
        adc \$0, $acc2\n"; # At this point acc2 has the value of 4 at most
}

sub poly_mul {
    &poly_stage1();
    &poly_stage2();
    &poly_stage3();
    &poly_reduce_stage();
}

{
################################################################################
# void chacha20_poly1305_open_512(uint8_t *out_plaintext, const uint8_t *ciphertext,
#                             size_t plaintext_len, const uint8_t *ad,
#                             size_t ad_len,
#                             union chacha20_poly1305_open_512_data *aead_data)
#
$code.="
.globl chacha20_poly1305_open_512
.hidden chacha20_poly1305_open_512
.type chacha20_poly1305_open_512,\@function,6
.align 64
chacha20_poly1305_open_512:
.cfi_startproc
    endbr64
    push %rbp
.cfi_push %rbp
    push %rbx
.cfi_push %rbx
    push %r12
.cfi_push %r12
    push %r13
.cfi_push %r13
    push %r14
.cfi_push %r14
    push %r15
.cfi_push %r15
    # We write the calculated authenticator back to keyp at the end, so save
    # the pointer on the stack too.
    push $keyp
.cfi_push $keyp
    sub \$1056 + $xmm_storage + 32, %rsp
.cfi_adjust_cfa_offset 1056 + 32

    lea 32(%rsp), %rbp
    and \$-32, %rbp
    mov %r9, 512(%rbp)		# caller key struct\n";
$code.="
    movaps %xmm6,16*0+$xmm_store
    movaps %xmm7,16*1+$xmm_store
    movaps %xmm8,16*2+$xmm_store
    movaps %xmm9,16*3+$xmm_store
    movaps %xmm10,16*4+$xmm_store
    movaps %xmm11,16*5+$xmm_store
    movaps %xmm12,16*6+$xmm_store
    movaps %xmm13,16*7+$xmm_store
    movaps %xmm14,16*8+$xmm_store
    movaps %xmm15,16*9+$xmm_store\n" if ($win64);
$code.="
    mov %rdx, $inl
    mov $adl, 0+$len_store
    mov $inl, 8+$len_store
    jmp .Lopen_range_entry\n";
$code.="
.Lopen_range_entry:
    # Preserve the message and AAD cursors while block zero is generated.
    mov $oup, 312(%rbp)
    mov $inp, 320(%rbp)
    mov $adp, 520(%rbp)
    mov $adl, 528(%rbp)
    movq \$0, 504(%rbp)
    movq \$0, 536(%rbp)		# bytes of pending left out of every MAC chain

    # For disjoint buffers, counter zero and sixteen data counters share one
    # aligned hybrid fill.  In-place open must authenticate ciphertext before
    # overwriting it, so it retains the key-first entry below.
    cmp $oup, $inp
    je .Lopen_range_key_only
    test $inl, $inl
    jz .Lopen_range_key_only
    mov $inl, %rax
    cmp \$1024, %rax
    jbe .Lopen_range_fill_len
    cmp \$2048, %rax
    jbe .Lopen_range_fill_len
    mov \$1024, %eax
.Lopen_range_fill_len:
    mov %rax, 504(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov %rax, %rdx
    mov 512(%rbp), %rcx
    lea 32(%rcx), %r8
    lea 384(%rbp), %r9
    # Same width rule as seal; see .Lfill_narrow.
    lea 64(%rdx), %rax
    cmp \$512, %rax
    ja .Lopen_range_fill_wide
    call .Lfill_narrow
    jmp .Lopen_range_fill_done
.Lopen_range_fill_wide:
    # One dispatch either way; pick the narrowest instance pair that still
    # covers the payload, the same rule .Lfill_narrow follows below 512 bytes.
    cmp \$1024, %rdx
    jbe .Lopen_range_fill_16
    cmp \$1536, %rdx
    ja .Lopen_range_fill_33x
    call ChaCha20_25x_key
    jmp .Lopen_range_fill_done
.Lopen_range_fill_33x:
    call ChaCha20_33x_key
    jmp .Lopen_range_fill_done
.Lopen_range_fill_16:
    call ChaCha20_17x_key
.Lopen_range_fill_done:
    vmovdqu 384(%rbp), %xmm0
    vpand .Lclamp(%rip), %xmm0, %xmm0
    vmovdqa %xmm0, $r_store
    vmovdqu 400(%rbp), %xmm0
    vmovdqa %xmm0, $s_store
    mov 504(%rbp), %rax
    add %rax, 312(%rbp)
    add %rax, 320(%rbp)
    sub %rax, $inl
    jmp .Lopen_range_have_key

    # In-place open cannot use the combined decrypt-before-hash fill. Generate
    # block zero through the narrowest existing vector data kernel instead.
.Lopen_range_key_only:
    vpxor %xmm0, %xmm0, %xmm0
    vmovdqu %xmm0, 384(%rbp)
    vmovdqu %xmm0, 400(%rbp)
    vmovdqu %xmm0, 416(%rbp)
    vmovdqu %xmm0, 432(%rbp)
    lea 384(%rbp), %rdi
    mov %rdi, %rsi
    mov \$64, %rdx
    mov 512(%rbp), %rcx
    lea 32(%rcx), %r8
    call ChaCha20_tail_avx512
    vmovdqu 384(%rbp), %xmm0
    vpand .Lclamp(%rip), %xmm0, %xmm0
    vmovdqa %xmm0, $r_store
    vmovdqu 400(%rbp), %xmm0
    vmovdqa %xmm0, $s_store
.Lopen_range_have_key:

    # Start the single Poly1305 chain with padded AAD.  IFMA handles all AAD
    # lengths, so the data pipeline receives the same accumulator shape for
    # every message range.
    movq \$0, 288(%rbp)
    movq \$0, 296(%rbp)
    movq \$0, 304(%rbp)
    mov 528(%rbp), %rsi
    test %rsi, %rsi
    jz .Lopen_range_ad_done
    mov 520(%rbp), %rdi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
.Lopen_range_ad_done:
    mov 504(%rbp), %rsi
    test %rsi, %rsi
    jz .Lopen_range_fill_hashed
    cmp \$1024, %rsi
    jne .Lopen_range_hash_fill_now
    test $inl, $inl
    jz .Lopen_range_hash_fill_now
    movabs \$0x0000000100000010, %rax
    mov %rax, 504(%rbp)
    jmp .Lopen_range_fill_hashed
.Lopen_range_hash_fill_now:
    mov 320(%rbp), %rdi
    sub %rsi, %rdi
    movq \$16, 504(%rbp)
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
.Lopen_range_fill_hashed:
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    mov 312(%rbp), $oup
    mov 320(%rbp), $inp
    jmp .Lopen_avx512_main

.Lopen_avx512_main:
    mov $acc0, 288(%rbp)
    mov $acc1, 296(%rbp)
    mov $acc2, 304(%rbp)
    mov $oup, 312(%rbp)
    mov $inp, 320(%rbp)
    mov 512(%rbp), %rax
    movdqu 0(%rax), %xmm0
    movdqu %xmm0, 336(%rbp)
    movdqu 16(%rax), %xmm0
    movdqu %xmm0, 352(%rbp)
    mov 32(%rax), %ecx
    add \$1, %ecx
    add 504(%rbp), %ecx
    mov %ecx, 368(%rbp)
    mov 36(%rax), %ecx
    mov %ecx, 372(%rbp)
    mov 40(%rax), %ecx
    mov %ecx, 376(%rbp)
    mov 44(%rax), %ecx
    mov %ecx, 380(%rbp)
    # Disjoint open leaves the input ciphertext intact.  When only one full
    # range plus a residue remains, authenticate the whole contiguous input
    # once and then perform the proportional decrypt; no third range exists to
    # amortize a fused pipeline transition.  State 1 is never used by the
    # in-place key-only entry.
    cmpl \$1, 508(%rbp)
    jne .Lopen_avx512_schedule_overlap
    cmp \$1024, $inl
    jbe .Lopen_avx512_schedule_overlap
    cmp \$1152, $inl
    ja .Lopen_avx512_schedule_overlap
    mov 320(%rbp), %rdi
    subq \$1024, %rdi
    mov $inl, %rsi
    addq \$1024, %rsi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    cmp \$1152, $inl
    ja .Lopen_twopass_16x
    call ChaCha20_17x
    jmp .Lopen_twopass_chacha_done
.Lopen_twopass_16x:
    mov $inl, %rdx
    call ChaCha20_16x
.Lopen_twopass_chacha_done:
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    jmp .Lopen_avx512_out
.Lopen_avx512_schedule_overlap:
    mov 0+$r_store, %rcx
    mov %rcx, 472(%rbp)
    mov 8+$r_store, %rcx
    mov %rcx, 480(%rbp)
    mov %rcx, %rax
    shr \$2, %rax
    add %rax, %rcx
    mov %rcx, 488(%rbp)
    cmpl \$0, 508(%rbp)
    jnz .Lopen_avx512_need_pow
    cmp \$1024, $inl
    jb .Lopen_avx512_rest
.Lopen_avx512_need_pow:
    # The single-chain 256/512-byte pending drains need no split-chain power.
    cmpl \$0, 508(%rbp)
    jz .Lopen_avx512_do_pow
    cmp \$512, $inl
    jbe .Lopen_pending_chunk
    # Seal's single-chain trade applies here too, under the same contiguity
    # rule: one chain over the pending range leaves its second half to the
    # exposed suffix, which stays one interval only while the drain that
    # follows starts where this chain stopped and needs no r^32 of its own.
    # Both hold while what remains after this range fits a narrow drain.
    #
    # A residue is part of the condition, not incidental.  With none, the
    # pending range is authenticated inside the last real ChaCha pass at no
    # cost, so halving that chain would enlarge the IFMA suffix and buy
    # nothing; the two-chain form is right there and is left alone.
    cmp \$1024, $inl
    jbe .Lopen_avx512_do_pow
    cmp \$1536, $inl
    jbe .Lopen_pending_one_chunk
.Lopen_avx512_do_pow:
    lea 384(%rbp), %rdi
    lea 0+$r_store, %rsi
    call poly1305_pow32
    cmpl \$0, 508(%rbp)
    jz .Lopen_avx512_chunk
    movl \$2, 508(%rbp)
    jmp .Lopen_pending_chunk
.Lopen_avx512_chunk:
    cmp \$1024, $inl
    jb .Lopen_avx512_rest
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    xor %eax, %eax
    mov %rax, 448(%rbp)
    mov %rax, 456(%rbp)
    mov %rax, 464(%rbp)
    mov 320(%rbp), %rax
    mov %rax, 496(%rbp)\t\t# macctx.ptr = this chunk's ciphertext
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov \$1024, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac
    lea 424(%rbp), %rdi
    lea 384(%rbp), %rsi
    call poly1305_gmul44_fast
    mov 424(%rbp), %rax
    add 448(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    adc 456(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    adc 464(%rbp), %rax
    mov %rax, 304(%rbp)
    addq \$1024, 312(%rbp)
    addq \$1024, 320(%rbp)
    sub \$1024, $inl
    addl \$16, 368(%rbp)
    jmp .Lopen_avx512_chunk

    # Disjoint-buffer open can keep the previous ciphertext range pending while
    # decrypting the next.  This mirrors seal's look-ahead pipeline, but the MAC
    # source is the input ciphertext rather than the output buffer.
.Lopen_pending_chunk:
    # Same trade as seal, and the same hoisted loop bound: one 17-block pass
    # instead of a fused pass plus a drain whose only cipher work is the residue.
    # The input ciphertext is intact on this path, so the pending range and the
    # residue authenticate together.
    cmp \$1089, $inl
    jae .Lopen_pending_chunk_fused
    cmp \$1024, $inl
    jb .Lopen_pending_drain
    ja .Lopen_pending_tail17
.Lopen_pending_chunk_fused:
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    movq \$0, 448(%rbp)
    movq \$0, 456(%rbp)
    movq \$0, 464(%rbp)
    mov 320(%rbp), %rax
    sub \$1024, %rax
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov \$1024, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac
    lea 424(%rbp), %rdi
    lea 384(%rbp), %rsi
    call poly1305_gmul44_fast
    mov 424(%rbp), %rax
    add 448(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    adc 456(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    adc 464(%rbp), %rax
    mov %rax, 304(%rbp)
    addq \$1024, 312(%rbp)
    addq \$1024, 320(%rbp)
    sub \$1024, $inl
    addl \$16, 368(%rbp)
    jmp .Lopen_pending_chunk

.Lopen_pending_one_chunk:
    # One chain over the pending range: 32 blocks, no r^32, no combine.  508
    # stays 1, which also keeps the drain below off .Lopen_pending_drain16 --
    # that wide drain is only worth its 64 MAC blocks when r^32 already exists.
    movl \$1, 508(%rbp)
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    movq \$0, 448(%rbp)
    movq \$0, 456(%rbp)
    movq \$0, 464(%rbp)
    mov 320(%rbp), %rax
    sub \$1024, %rax
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov \$1024, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac1024
    mov 424(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    mov %rax, 304(%rbp)
    movq \$512, 536(%rbp)	# pending bytes left for the exposed suffix
    addq \$1024, 312(%rbp)
    addq \$1024, 320(%rbp)
    sub \$1024, $inl
    addl \$16, 368(%rbp)

.Lopen_pending_drain:
    test $inl, $inl
    jz .Lopen_pending_exact
    cmp \$128, $inl
    jbe .Lopen_pending_drain128
    cmp \$256, $inl
    jbe .Lopen_pending_drain256
    cmpl \$2, 508(%rbp)
    je .Lopen_pending_drain16
    cmp \$256, $inl
    ja .Lopen_pending_not_serial
    cmpl \$2, 508(%rbp)
    je .Lopen_pending_serial_tail
.Lopen_pending_not_serial:
    cmp \$256, $inl
    jbe .Lopen_pending_drain256
    # Same band and same machine split as seal.  Only the disjoint pipeline
    # reaches here, so decrypting the residue leaves the input ciphertext this
    # suffix authenticates intact.
    cmp \$512, $inl
    jbe .Lopen_pending_drain512
.Lopen_pending_drain16:
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    movq \$0, 448(%rbp)
    movq \$0, 456(%rbp)
    movq \$0, 464(%rbp)
    mov 320(%rbp), %rax
    sub \$1024, %rax
    sub 536(%rbp), %rax		# resume where a single-chain range stopped
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac
    lea 424(%rbp), %rdi
    lea 384(%rbp), %rsi
    call poly1305_gmul44_fast
    mov 424(%rbp), %rax
    add 448(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    adc 456(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    adc 464(%rbp), %rax
    mov %rax, 304(%rbp)
    # The residue ciphertext was not part of the pending MAC range. Continue
    # the same accumulator through it after decryption; input remains intact.
    mov 320(%rbp), %rdi
    mov $inl, %rsi
    jmp .Lopen_pending_suffix

.Lopen_pending_tail17:
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_17x
    mov 320(%rbp), %rdi
    sub \$1024, %rdi
    mov $inl, %rsi
    add \$1024, %rsi
    jmp .Lopen_pending_suffix

.Lopen_pending_serial_tail:
    # After at least one complete fused range, avoid another full-width ChaCha
    # launch for a small residue. Decrypt at its natural width and authenticate
    # the pending range plus residue as one contiguous IFMA suffix.
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_tail_avx512
    mov 320(%rbp), %rdi
    sub \$1024, %rdi
    mov $inl, %rsi
    add \$1024, %rsi
    jmp .Lopen_pending_suffix

.Lopen_pending_drain128:
    mov \$256, %r13d		# 16 blocks; see the density table
    lea ChaCha20_16x_mac128(%rip), %r14
    jmp .Lopen_pending_drain_partial
.Lopen_pending_drain256:
    mov \$256, %r13d
    lea ChaCha20_16x_mac256(%rip), %r14
    jmp .Lopen_pending_drain_partial
.Lopen_pending_drain512:
    mov \$384, %r13d		# 24 blocks
    lea ChaCha20_16x_mac512(%rip), %r14
.Lopen_pending_drain_partial:
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    movq \$0, 448(%rbp)
    movq \$0, 456(%rbp)
    movq \$0, 464(%rbp)
    mov 320(%rbp), %rax
    sub \$1024, %rax
    sub 536(%rbp), %rax		# resume where a single-chain range stopped
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call *%r14
    mov 424(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    mov %rax, 304(%rbp)
    mov \$1024, %rax
    sub %r13, %rax
    mov 320(%rbp), %rdi
    sub %rax, %rdi
    mov $inl, %rsi
    add %rax, %rsi
    jmp .Lopen_pending_suffix

.Lopen_pending_exact:
    mov 320(%rbp), %rdi
    sub \$1024, %rdi
    mov \$1024, %rsi
.Lopen_pending_suffix:
    # Every drain above arrives here with the suffix as (%rdi start, %rsi
    # length) measured from the pending range.  If a single chain left that
    # range's second half unauthenticated, the suffix simply begins that much
    # earlier; it is still one interval, so widening it once here covers all of
    # them.  536 is zero on every path that did not take the single-chain form.
    mov 536(%rbp), %rax
    sub %rax, %rdi
    add %rax, %rsi
    movq \$0, 536(%rbp)
.Lopen_pending_fold:
    mov 304(%rbp), %rcx
    mov %rcx, %rax
    shr \$2, %rcx
    jz .Lopen_pending_folded
    and \$3, %rax
    mov %rax, 304(%rbp)
    lea (%rcx,%rcx,4), %rcx
    add %rcx, 288(%rbp)
    adcq \$0, 296(%rbp)
    adcq \$0, 304(%rbp)
    jmp .Lopen_pending_fold
.Lopen_pending_folded:
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
.Lopen_pending_out:
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    jmp .Lopen_avx512_out
.Lopen_avx512_rest:
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    test $inl, $inl
    jz .Lopen_avx512_out
    # The prefix accumulator is already a normal Poly1305 value.  For a large
    # exposed suffix, continue it directly with IFMA before decrypting.  This
    # replaces sixteen generated fixed-tail schedules with one continuous path.
    # Every exposed range uses the same continuous IFMA continuation.
    mov $acc0, 288(%rbp)
    mov $acc1, 296(%rbp)
    mov $acc2, 304(%rbp)
.Lopen_ifma_fold_prefix:
    mov 304(%rbp), %rcx
    mov %rcx, %rax
    shr \$2, %rcx
    jz .Lopen_ifma_prefix_folded
    and \$3, %rax
    mov %rax, 304(%rbp)
    lea (%rcx,%rcx,4), %rcx       # 2^130 == 5 mod (2^130-5)
    add %rcx, 288(%rbp)
    adcq \$0, 296(%rbp)
    adcq \$0, 304(%rbp)
    jmp .Lopen_ifma_fold_prefix
.Lopen_ifma_prefix_folded:
    mov 320(%rbp), %rdi
    mov $inl, %rsi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
    jmp .Lopen_avx512_decrypt_parked
.Lopen_avx512_hash_setup:
    # hash the remaining ciphertext BEFORE decrypting, so in-place still works
    mov 320(%rbp), %rdi
    mov $inl, %rcx
.Lopen_avx512_hash:
    cmp \$16, %rcx
    jb .Lopen_avx512_hash_tail\n";
    &poly_add("0(%rdi)");
    &poly_mul(); $code.="
    add \$16, %rdi
    sub \$16, %rcx
    jmp .Lopen_avx512_hash
.Lopen_avx512_hash_tail:
    test %rcx, %rcx
    jz .Lopen_avx512_decrypt
    movq \$0, 520(%rbp)
    movq \$0, 528(%rbp)
    xor %rax, %rax
.Lopen_avx512_pad:
    movzbl (%rdi,%rax,1), %r8d
    mov %r8b, 520(%rbp,%rax,1)
    inc %rax
    cmp %rax, %rcx
    jne .Lopen_avx512_pad\n";
    &poly_add("520(%rbp)");
    &poly_mul(); $code.="
.Lopen_avx512_decrypt:
    mov $acc0, 288(%rbp)
    mov $acc1, 296(%rbp)
    mov $acc2, 304(%rbp)
.Lopen_avx512_decrypt_parked:
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_tail_avx512
.Lopen_avx512_rem_done:
    vzeroupper
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
.Lopen_avx512_out:
    # Keep the length block and final reduction in the IFMA domain.  Returning
    # through the legacy scalar finalizer paid a domain transition on every
    # open, which dominates tiny records.
    mov $acc0, 288(%rbp)
    mov $acc1, 296(%rbp)
    mov $acc2, 304(%rbp)
.Lopen_out_fold:
    mov 304(%rbp), %rcx
    mov %rcx, %rax
    shr \$2, %rcx
    jz .Lopen_out_folded
    and \$3, %rax
    mov %rax, 304(%rbp)
    lea (%rcx,%rcx,4), %rcx
    add %rcx, 288(%rbp)
    adcq \$0, 296(%rbp)
    adcq \$0, 304(%rbp)
    jmp .Lopen_out_fold
.Lopen_out_folded:
    lea $len_store, %rdi
    mov \$16, %rsi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
    lea 288(%rbp), %rdi
    lea 0+$r_store, %rsi
    lea 424(%rbp), %rdx
    call poly1305_aead_complete_fma_avx512
    mov 424(%rbp), $acc0
    mov 432(%rbp), $acc1
    vzeroupper
    jmp .Lopen_epilogue
";

emit_epilogue(".Lopen_epilogue", "chacha20_poly1305_open_512");
}

{
$code.="
.globl  chacha20_poly1305_seal_512
.hidden chacha20_poly1305_seal_512
.type chacha20_poly1305_seal_512,\@function,6
.align 64
chacha20_poly1305_seal_512:
.cfi_startproc
    endbr64
    push %rbp
.cfi_push %rbp
    push %rbx
.cfi_push %rbx
    push %r12
.cfi_push %r12
    push %r13
.cfi_push %r13
    push %r14
.cfi_push %r14
    push %r15
.cfi_push %r15   
# We write the calculated authenticator back to keyp at the end, so save
# the pointer on the stack too.
    push $keyp
.cfi_push $keyp
    sub \$1056 + $xmm_storage + 32, %rsp
.cfi_adjust_cfa_offset 1056 + 32
    lea 32(%rsp), %rbp
    and \$-32, %rbp
    mov %r9, 512(%rbp)		# caller key struct\n";
$code.="
    movaps %xmm6,16*0+$xmm_store
    movaps %xmm7,16*1+$xmm_store
    movaps %xmm8,16*2+$xmm_store
    movaps %xmm9,16*3+$xmm_store
    movaps %xmm10,16*4+$xmm_store
    movaps %xmm11,16*5+$xmm_store
    movaps %xmm12,16*6+$xmm_store
    movaps %xmm13,16*7+$xmm_store
    movaps %xmm14,16*8+$xmm_store
    movaps %xmm15,16*9+$xmm_store\n" if ($win64);
$code.="
    mov %rdx, $inl
    mov $adl, 0+$len_store
    mov $inl, 8+$len_store
    jmp .Lseal_range_entry\n";
# ---------------------------------------------------------------------------
# 512-bit seal path:
#   in : $r_store/$s_store set, AD hashed into $acc0..2, $len_store set,
#        nothing encrypted, $oup/$inp at origin, $inl = plaintext length
#   out: jmp .Ldo_length_block, all ciphertext hashed into $acc0..2; that label
#        adds the length block, reduces with cmovc, adds s and writes the tag
#
# Seal is a one-chunk look-ahead pipeline:
#   prologue: encrypt one 1024-byte chunk;
#   steady:   encrypt chunk i while authenticating ciphertext chunk i-1;
#   drain:    use residue ChaCha work to hide the pending chunk when possible,
#             then finish only the exposed suffix with scalar or IFMA Poly1305.
# The drain decision is based on bytes remaining here, never the original size.
#
# Key material comes from the caller's struct, stashed at 512(%rbp) while %r9
# still held it. The struct is unambiguous:
#   0($keyp) key[32]   32($keyp) counter (the DATA counter)   36($keyp) nonce[12]
#
# ChaCha20_16x clobbers %r10-%r12 ($acc0..2) and %r9 ($t3/$keyp), so the
# accumulator is parked. %r9 needs no saving: the epilogue recovers $keyp with
# `pop`. %rbp is untouched by ChaCha20_16x so our frame stays addressable, and
# %rsp is balanced across the call.
#
# Frame slots (ours start at 288; theirs top out there exactly):
#   288 saved $acc0..2   312 saved $oup/$inp   336 key[32]   368 counter+nonce
#   384 r^32 radix-2^44 key   424 macctx (A 424, B 448, key 472, ptr 496)
#   512 caller key struct   520 zero-pad scratch   544 narrow-fill keystream[512]
$code.="
.Lseal_range_entry:
    mov $oup, 312(%rbp)
    mov $inp, 320(%rbp)
    mov $adp, 520(%rbp)
    mov $adl, 528(%rbp)
    movq \$0, 504(%rbp)
    movq \$0, 536(%rbp)		# bytes of pending left out of every MAC chain

    # Aligned hybrid fill: counter zero occupies a vector lane and the existing
    # scalar-overlap state supplies data block sixteen, yielding exactly 1024
    # data bytes without a 960-byte seam.
    test $inl, $inl
    jz .Lseal_range_key_only
    mov $inl, %rax
    cmp \$1024, %rax
    jbe .Lseal_range_fill_len
    cmp \$2048, %rax
    jbe .Lseal_range_fill_len
    mov \$1024, %eax
.Lseal_range_fill_len:
    mov %rax, 504(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov %rax, %rdx
    mov 512(%rbp), %rcx
    lea 32(%rcx), %r8
    lea 384(%rbp), %r9
    # Pick the fill kernel by the keystream the fill actually needs, not by the
    # message size: counter zero plus the data.  Inside 512 bytes the narrow
    # dispatch covers it with 2, 4 or 8 lanes; only above that is the flat
    # 16-lane key kernel the right width.  See .Lfill_narrow.
    lea 64(%rdx), %rax
    cmp \$512, %rax
    ja .Lseal_range_fill_wide
    call .Lfill_narrow
    jmp .Lseal_range_fill_done
.Lseal_range_fill_wide:
    # One dispatch either way; pick the narrowest instance pair that still
    # covers the payload, the same rule .Lfill_narrow follows below 512 bytes.
    cmp \$1024, %rdx
    jbe .Lseal_range_fill_16
    cmp \$1536, %rdx
    ja .Lseal_range_fill_33x
    call ChaCha20_25x_key
    jmp .Lseal_range_fill_done
.Lseal_range_fill_33x:
    call ChaCha20_33x_key
    jmp .Lseal_range_fill_done
.Lseal_range_fill_16:
    call ChaCha20_17x_key
.Lseal_range_fill_done:
    vmovdqu 384(%rbp), %xmm0
    vpand .Lclamp(%rip), %xmm0, %xmm0
    vmovdqa %xmm0, $r_store
    vmovdqu 400(%rbp), %xmm0
    vmovdqa %xmm0, $s_store
    mov 504(%rbp), %rax
    add %rax, 312(%rbp)
    add %rax, 320(%rbp)
    sub %rax, $inl
    jmp .Lseal_range_have_key

.Lseal_range_key_only:
    vpxor %xmm0, %xmm0, %xmm0
    vmovdqu %xmm0, 384(%rbp)
    vmovdqu %xmm0, 400(%rbp)
    vmovdqu %xmm0, 416(%rbp)
    vmovdqu %xmm0, 432(%rbp)
    lea 384(%rbp), %rdi
    mov %rdi, %rsi
    mov \$64, %rdx
    mov 512(%rbp), %rcx
    lea 32(%rcx), %r8
    call ChaCha20_tail_avx512
    vmovdqu 384(%rbp), %xmm0
    vpand .Lclamp(%rip), %xmm0, %xmm0
    vmovdqa %xmm0, $r_store
    vmovdqu 400(%rbp), %xmm0
    vmovdqa %xmm0, $s_store
.Lseal_range_have_key:

    movq \$0, 288(%rbp)
    movq \$0, 296(%rbp)
    movq \$0, 304(%rbp)
    mov 528(%rbp), %rsi
    test %rsi, %rsi
    jz .Lseal_range_ad_done
    mov 520(%rbp), %rdi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
.Lseal_range_ad_done:
    # Continue the same chain across ciphertext produced by the combined fill.
    mov 504(%rbp), %rsi
    test %rsi, %rsi
    jz .Lseal_range_fill_hashed
    cmp \$1024, %rsi
    jne .Lseal_range_hash_fill_now
    test $inl, $inl
    jz .Lseal_range_hash_fill_now
    # Keep a complete initial range pending when future ChaCha work exists.
    # The low dword remains the sixteen-counter advance; the high dword tells
    # the main setup to enter directly at the fused/drain state.
    movabs \$0x0000000100000010, %rax
    mov %rax, 504(%rbp)
    jmp .Lseal_range_fill_hashed
.Lseal_range_hash_fill_now:
    mov 312(%rbp), %rdi
    sub %rsi, %rdi
    # The byte count is dead after the source address is formed.  Reuse this
    # slot for the sixteen data counters consumed by the aligned fill.
    movq \$16, 504(%rbp)
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
.Lseal_range_fill_hashed:
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    mov 312(%rbp), $oup
    mov 320(%rbp), $inp
    jmp .Lseal_avx512_main

.Lseal_avx512_main:
    mov $acc0, 288(%rbp)
    mov $acc1, 296(%rbp)
    mov $acc2, 304(%rbp)
    mov $oup, 312(%rbp)
    mov $inp, 320(%rbp)
    mov 512(%rbp), %rax
    movdqu 0(%rax), %xmm0
    movdqu %xmm0, 336(%rbp)
    movdqu 16(%rax), %xmm0
    movdqu %xmm0, 352(%rbp)
    # The struct counter is the POLY1305 KEY block (callers set 0), so the data
    # keystream starts one block later.
    mov 32(%rax), %ecx
    add \$1, %ecx
    add 504(%rbp), %ecx
    mov %ecx, 368(%rbp)
    mov 36(%rax), %ecx
    mov %ecx, 372(%rbp)
    mov 40(%rax), %ecx
    mov %ecx, 376(%rbp)
    mov 44(%rax), %ecx
    mov %ecx, 380(%rbp)
    # With only one complete range plus a residue after the initial fill there
    # is no third range to sustain overlap.  Finish ChaCha proportionally, then
    # authenticate the contiguous ciphertext once with IFMA.  This is a
    # remaining-work predicate, not an original-message-size dispatch.
    cmpl \$1, 508(%rbp)
    jne .Lseal_avx512_schedule_overlap
    cmp \$1024, $inl
    jbe .Lseal_avx512_schedule_overlap
    cmp \$1152, $inl
    ja .Lseal_avx512_schedule_overlap
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    cmp \$1152, $inl
    ja .Lseal_twopass_16x
    call ChaCha20_17x
    jmp .Lseal_twopass_chacha_done
.Lseal_twopass_16x:
    mov $inl, %rdx
    call ChaCha20_16x_tiered
.Lseal_twopass_chacha_done:
    subq \$1024, 312(%rbp)
    addq \$1024, $inl
    jmp .Lseal_avx512_hash_remainder
.Lseal_avx512_schedule_overlap:
    # ---- MAC key for both chains: r0, r1, s1 = r1 + (r1>>2) ----------------
    mov 0+$r_store, %rcx
    mov %rcx, 472(%rbp)
    mov 8+$r_store, %rcx
    mov %rcx, 480(%rbp)
    mov %rcx, %rax
    shr \$2, %rax
    add %rax, %rcx
    mov %rcx, 488(%rbp)
    cmpl \$0, 508(%rbp)
    jnz .Lseal_avx512_pending
    cmp \$1024, $inl
    jb .Lseal_avx512_short
    # ---- r^32 as a radix-2^44 key, for the per-chunk combine ---------------
    lea 384(%rbp), %rdi
    lea 0+$r_store, %rsi
    call poly1305_pow32
    # ---- chunk 0: encrypt with nothing yet to authenticate -----------------
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov \$1024, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_16x
    addq \$1024, 312(%rbp)
    addq \$1024, 320(%rbp)
    sub \$1024, $inl
    addl \$16, 368(%rbp)
    # ---- fused chunks: encrypt chunk i while authenticating chunk i-1 ------
.Lseal_avx512_pending:
    # A complete range was produced by the aligned key+data fill and deliberately
    # left pending.  Build r^32 once, then consume future ranges normally.
    cmpl \$0, 508(%rbp)
    jz .Lseal_avx512_chunk
    cmp \$512, $inl
    jbe .Lseal_avx512_pending_no_pow
    # One chain over the pending range needs no r^32 and no per-chunk combine,
    # but it covers only pending[0,512) and leaves pending[512,1024) for the
    # exposed suffix.  That is sound exactly while the suffix stays a SINGLE
    # contiguous interval, which puts two conditions on whatever runs next:
    #
    #   - the drain must start its own chain where this chain stopped, not at
    #     the pending chunk, or it authenticates a later range and splits the
    #     exposed region in two.  That is the `sub 536(%rbp)` on macctx.ptr in
    #     the drains below; the roll-back arithmetic already lands right.
    #   - the drain must itself need no r^32, since none was built here.
    #
    # Both hold precisely when what remains after this chunk fits a narrow
    # drain, so the predicate is one chunk plus at most a 512-byte residue.
    # Above that the two-chain form still pays for its r^32.
    cmp \$1024, $inl
    jb .Lseal_avx512_pending_pow
    cmp \$1536, $inl
    jbe .Lseal_avx512_one_chunk
.Lseal_avx512_pending_pow:
    lea 384(%rbp), %rdi
    lea 0+$r_store, %rsi
    call poly1305_pow32
    movl \$2, 508(%rbp)
    jmp .Lseal_avx512_chunk
.Lseal_avx512_pending_no_pow:
    movl \$1, 508(%rbp)
.Lseal_avx512_chunk:
    cmp \$1089, $inl
    jae .Lseal_avx512_chunk_fused
    cmp \$1024, $inl
    jb .Lseal_avx512_drain
    ja .Lseal_avx512_tail17
.Lseal_avx512_chunk_fused:
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    xor %eax, %eax
    mov %rax, 448(%rbp)
    mov %rax, 456(%rbp)
    mov %rax, 464(%rbp)
    mov 312(%rbp), %rax
    sub \$1024, %rax
    mov %rax, 496(%rbp)		# macctx.ptr = previous chunk
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov \$1024, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac
    # combine: acc = A*r^32 + B
    lea 424(%rbp), %rdi
    lea 384(%rbp), %rsi
    call poly1305_gmul44_fast
    # A = A*r^32 + B, in place, then re-arm B for the next chunk.
    mov 424(%rbp), %rax
    add 448(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    adc 456(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    adc 464(%rbp), %rax
    mov %rax, 304(%rbp)
    addq \$1024, 312(%rbp)
    addq \$1024, 320(%rbp)
    sub \$1024, $inl
    addl \$16, 368(%rbp)
    jmp .Lseal_avx512_chunk

.Lseal_avx512_one_chunk:
    movl \$1, 508(%rbp)
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    xor %eax, %eax
    mov %rax, 448(%rbp)
    mov %rax, 456(%rbp)
    mov %rax, 464(%rbp)
    mov 312(%rbp), %rax
    sub \$1024, %rax
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov \$1024, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac1024
    mov 424(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    mov %rax, 304(%rbp)
    # The single chain covered pending[0,512); the rest of it stays exposed and
    # is contiguous with everything after, so the suffix simply starts earlier.
    movq \$512, 536(%rbp)
    addq \$1024, 312(%rbp)
    addq \$1024, 320(%rbp)
    sub \$1024, $inl
    addl \$16, 368(%rbp)
    jmp .Lseal_avx512_drain

.Lseal_avx512_short:
    # No complete look-ahead pair exists. Encrypt this range with the tiered
    # ChaCha tail, then continue the AAD accumulator directly with IFMA.
    test $inl, $inl
    jz .Lseal_avx512_hash_remainder
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_tail_avx512
    jmp .Lseal_avx512_hash_remainder
    # ---- drain: the final chunk has no later vector work to hide behind ----
.Lseal_avx512_drain:
";
$code.="
    # There is always one encrypted 1024-byte chunk pending at the pipeline
    # exit.  A nonempty residue supplies ChaCha work that can hide that chunk's
    # MAC, so retain the fused drain below.  At an exact multiple there is no
    # such work: make the pending chunk the standalone IFMA suffix instead.
    # This decision depends only on work remaining in the pipeline, not on the
    # original message length.
    test $inl, $inl
    jnz .Lseal_avx512_drain_overlap
    subq \$1024, 312(%rbp)
    mov \$1024, $inl
    jmp .Lseal_avx512_hash_remainder
.Lseal_avx512_drain_overlap:
";
$code.="
    cmp \$128, $inl
    jbe .Lseal_avx512_drain128
    cmp \$256, $inl
    jbe .Lseal_avx512_drain256
    # 257..512 B of residue: eight-lane ymm drain authenticating 384 B of the
    # pending chunk.  One schedule for every part -- see aead_mac_partial.pl for
    # the density measurement that picked 24 blocks over 16 or 32.
    cmp \$512, $inl
    jbe .Lseal_avx512_drain512
.Lseal_avx512_drain_overlap16:
    # If a residue exists, use its ChaCha rounds to authenticate the pending
    # complete ciphertext chunk.  Previously we drained that chunk serially,
    # then made a separate cipher call for the residue, leaving those rounds'
    # integer slots idle.  ChaCha20_16x_mac's output tail already honours %rdx,
    # while its MAC side intentionally consumes the complete previous 1024 B.
    test $inl, $inl
    jz .Lseal_avx512_drain_serial
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    xor %eax, %eax
    mov %rax, 448(%rbp)
    mov %rax, 456(%rbp)
    mov %rax, 464(%rbp)
    mov 312(%rbp), %rax
    sub \$1024, %rax
    sub 536(%rbp), %rax		# resume where a single-chain range stopped
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call ChaCha20_16x_mac
    lea 424(%rbp), %rdi
    lea 384(%rbp), %rsi
    call poly1305_gmul44_fast
    mov 424(%rbp), %rax
    add 448(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    adc 456(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    adc 464(%rbp), %rax
    mov %rax, 304(%rbp)
    jmp .Lseal_avx512_hash_remainder

.Lseal_avx512_tail17:
    # (1024, 1152] remaining, one chunk still pending: encrypt all of it in a
    # single 17-block pass and let the pending chunk and the residue leave as
    # one contiguous IFMA suffix.  Nothing here needs r^32 or a combine, and 312
    # already points one chunk past the pending range.
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_17x
    subq \$1024, 312(%rbp)
    add \$1024, $inl
    jmp .Lseal_avx512_hash_remainder

.Lseal_avx512_drain_narrow_serial:
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    call ChaCha20_tail_avx512
    subq \$1024, 312(%rbp)
    add \$1024, $inl
    jmp .Lseal_avx512_hash_remainder

.Lseal_avx512_drain128:
    mov \$256, %r13d		# 16 blocks; see the density table
    lea ChaCha20_16x_mac128(%rip), %r14
    jmp .Lseal_avx512_drain_partial
.Lseal_avx512_drain256:
    mov \$256, %r13d
    lea ChaCha20_16x_mac256(%rip), %r14
    jmp .Lseal_avx512_drain_partial
.Lseal_avx512_drain512:
    mov \$384, %r13d		# 24 blocks
    lea ChaCha20_16x_mac512(%rip), %r14
.Lseal_avx512_drain_partial:
    mov 288(%rbp), %rax
    mov %rax, 424(%rbp)
    mov 296(%rbp), %rax
    mov %rax, 432(%rbp)
    mov 304(%rbp), %rax
    mov %rax, 440(%rbp)
    movq \$0, 448(%rbp)
    movq \$0, 456(%rbp)
    movq \$0, 464(%rbp)
    mov 312(%rbp), %rax
    sub \$1024, %rax
    # Start this chain where the pending range's own chain stopped.  536 is 0
    # after a two-chain range, which authenticated all 1024 pending bytes, and
    # 512 after the single-chain form above, which left the second half of the
    # range for the exposed suffix.  Hashing `cap` bytes from here keeps what
    # the suffix still owns a single interval; the roll-back below then lands on
    # 312 = ptr + cap either way, so it needs no adjustment of its own.
    sub 536(%rbp), %rax
    mov %rax, 496(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    lea 424(%rbp), %r9
    call *%r14
    mov 424(%rbp), %rax
    mov %rax, 288(%rbp)
    mov 432(%rbp), %rax
    mov %rax, 296(%rbp)
    mov 440(%rbp), %rax
    mov %rax, 304(%rbp)
    # exposed suffix = pending[cap..1024] || residue
    mov \$1024, %rax
    sub %r13, %rax
    sub %rax, 312(%rbp)
    add %rax, $inl
    jmp .Lseal_avx512_hash_remainder
.Lseal_avx512_drain_serial:
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    mov 312(%rbp), %rdi
    sub \$1024, %rdi
    mov \$64, %rcx
.Lseal_avx512_drain_loop:\n";
    &poly_add("0(%rdi)");
    &poly_mul(); $code.="
    add \$16, %rdi
    dec %rcx
    jnz .Lseal_avx512_drain_loop
    # ---- remainder below one chunk: encrypt, then hash ---------------------
    test $inl, $inl
    jz .Lseal_avx512_out
    mov $acc0, 288(%rbp)
    mov $acc1, 296(%rbp)
    mov $acc2, 304(%rbp)
    mov 312(%rbp), %rdi
    mov 320(%rbp), %rsi
    mov $inl, %rdx
    lea 336(%rbp), %rcx
    lea 368(%rbp), %r8
    # One tail interface owns the necessary 4/8/16-state width selection.
    call ChaCha20_tail_avx512
.Lseal_avx512_rem_done:
    vzeroupper
.Lseal_avx512_hash_remainder:
    mov 536(%rbp), %rax
    sub %rax, 312(%rbp)
    add %rax, $inl
    movq \$0, 536(%rbp)
";
$code.="
    # Universal exposed-range finish. The suffix is contiguous with the fused
    # prefix, so continue one accumulator instead of creating and bridging a
    # second chain.
.Lseal_ifma_continue_fold:
    mov 304(%rbp), %rcx
    mov %rcx, %rax
    shr \$2, %rcx
    jz .Lseal_ifma_continue_folded
    and \$3, %rax
    mov %rax, 304(%rbp)
    lea (%rcx,%rcx,4), %rcx
    add %rcx, 288(%rbp)
    adcq \$0, 296(%rbp)
    adcq \$0, 304(%rbp)
    jmp .Lseal_ifma_continue_fold
.Lseal_ifma_continue_folded:
    test $inl, $inl
    jz .Lseal_ifma_continue_length
    mov 312(%rbp), %rdi
    mov $inl, %rsi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    cmpl \$1, 508(%rbp)
    jne .Lseal_ifma_continue_ciphertext
    lea $len_store, %r8
    lea 424(%rbp), %r9
    call poly1305_aead_finish_fma_avx512
    jmp .Lseal_ifma_finish_done
.Lseal_ifma_continue_ciphertext:
    call poly1305_aead_update_fma_avx512
.Lseal_ifma_continue_length:
    lea $len_store, %rdi
    mov \$16, %rsi
    lea 288(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512
.Lseal_ifma_continue_complete:
    lea 288(%rbp), %rdi
    lea 0+$r_store, %rsi
    lea 424(%rbp), %rdx
    call poly1305_aead_complete_fma_avx512
.Lseal_ifma_finish_done:
    mov 424(%rbp), $acc0
    mov 432(%rbp), $acc1
    vzeroupper
    jmp .Lseal_epilogue

    cmp \$768, $inl
    jb .Lseal_avx512_hash_remainder_scalar
    movq \$0, 448(%rbp)
    movq \$0, 456(%rbp)
    movq \$0, 464(%rbp)
    mov 312(%rbp), %rdi
    mov $inl, %rsi
    lea 448(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512

    lea $len_store, %rdi
    mov \$16, %rsi
    lea 448(%rbp), %rdx
    lea 0+$r_store, %rcx
    call poly1305_aead_update_fma_avx512

    mov $inl, %rax
    add \$15, %rax
    shr \$4, %rax
    inc %rax
    mov %eax, %edx
    lea 384(%rbp), %rdi
    lea 0+$r_store, %rsi
    call poly1305_pow44
    # The final split-chain combine can leave A one bit wider than the general
    # multiplier's 130-bit input contract.  A following scalar message block
    # normally folds it; this independent bridge has to do that explicitly.
.Lifma_tail_fold_prefix:
    mov 304(%rbp), %rcx
    mov %rcx, %rax
    shr \$2, %rcx
    jz .Lifma_tail_prefix_folded
    and \$3, %rax
    mov %rax, 304(%rbp)
    lea (%rcx,%rcx,4), %rcx
    add %rcx, 288(%rbp)
    adcq \$0, 296(%rbp)
    adcq \$0, 304(%rbp)
    jmp .Lifma_tail_fold_prefix
.Lifma_tail_prefix_folded:
    lea 288(%rbp), %rdi
    lea 384(%rbp), %rsi
    call poly1305_gmul44_fast

    mov 448(%rbp), %rax
    add %rax, 288(%rbp)
    mov 456(%rbp), %rax
    adc %rax, 296(%rbp)
    mov 464(%rbp), %rax
    adc %rax, 304(%rbp)
    lea 288(%rbp), %rdi
    lea 0+$r_store, %rsi
    lea 424(%rbp), %rdx
    call poly1305_aead_complete_fma_avx512
    mov 424(%rbp), $acc0
    mov 432(%rbp), $acc1
    vzeroupper
    jmp .Lseal_epilogue
.Lseal_avx512_hash_remainder_scalar:
";
$code.="
    mov 288(%rbp), $acc0
    mov 296(%rbp), $acc1
    mov 304(%rbp), $acc2
    mov 312(%rbp), %rdi
    mov $inl, %rcx
.Lseal_avx512_hash:
    cmp \$16, %rcx
    jb .Lseal_avx512_hash_tail\n";
    &poly_add("0(%rdi)");
    &poly_mul(); $code.="
    add \$16, %rdi
    sub \$16, %rcx
    jmp .Lseal_avx512_hash
.Lseal_avx512_hash_tail:
    test %rcx, %rcx
    jz .Lseal_avx512_out
    # The AEAD zero-pads the ciphertext to 16 bytes and hashes it as a FULL
    # Poly1305 block, which is why poly_add's unconditional `adc \$1` is right
    # here -- there is no partial-block rule to special-case.
    movq \$0, 520(%rbp)
    movq \$0, 528(%rbp)
    xor %rax, %rax
.Lseal_avx512_pad:
    movzbl (%rdi,%rax,1), %r8d
    mov %r8b, 520(%rbp,%rax,1)
    inc %rax
    cmp %rax, %rcx
    jne .Lseal_avx512_pad\n";
    &poly_add("520(%rbp)");
    &poly_mul(); $code.="
.Lseal_avx512_out:
    jmp .Ldo_length_block

.Ldo_length_block:\n";
    &poly_add($len_store);
    &poly_mul(); $code.="
    # Final reduce
    mov $acc0, $t0
    mov $acc1, $t1
    mov $acc2, $t2
    sub \$-5, $acc0
    sbb \$-1, $acc1
    sbb \$3, $acc2
    cmovc $t0, $acc0
    cmovc $t1, $acc1
    cmovc $t2, $acc2
    # Add in s part of the key
    add 0+$s_store, $acc0
    adc 8+$s_store, $acc1\n";

emit_epilogue(".Lseal_epilogue", "chacha20_poly1305_seal_512");
}

# ---------------------------------------------------------------------------
# The narrow fill, shared by both directions.
#   in : %rdi out, %rsi in, %rdx len (1..448), %rcx key, %r8 counter, %r9 key out
#   out: (%r9)[0,32) = r || s;  out[0,len) = in[0,len) ^ keystream(counters 1..)
{
$code.="
.Lfill_narrow:
    push %rdi
    push %rsi
    push %rdx
    push %r9
    sub \$8, %rsp
    vpxorq %zmm0, %zmm0, %zmm0
    vmovdqu32 %zmm0, 544+64*0(%rbp)
    vmovdqu32 %zmm0, 544+64*1(%rbp)
    vmovdqu32 %zmm0, 544+64*2(%rbp)
    vmovdqu32 %zmm0, 544+64*3(%rbp)
    vmovdqu32 %zmm0, 544+64*4(%rbp)
    vmovdqu32 %zmm0, 544+64*5(%rbp)
    vmovdqu32 %zmm0, 544+64*6(%rbp)
    vmovdqu32 %zmm0, 544+64*7(%rbp)
    lea 544(%rbp), %rdi
    mov %rdi, %rsi
    lea 64(%rdx), %rdx
    call ChaCha20_tail_avx512
    add \$8, %rsp
    pop %r9
    vmovdqu 544(%rbp), %ymm0		# counter zero: r || s
    vmovdqu %ymm0, (%r9)
    pop %rdx
    pop %rsi
    pop %rdi
    lea 544+64(%rbp), %r10		# data keystream, from counter one
    xor %r11d, %r11d
    cmp \$64, %rdx
    jb .Lfill_narrow_tail
.Lfill_narrow_block:
    vmovdqu32 (%rsi,%r11), %zmm0
    vpxorq (%r10,%r11), %zmm0, %zmm0
    vmovdqu32 %zmm0, (%rdi,%r11)
    add \$64, %r11
    sub \$64, %rdx
    cmp \$64, %rdx
    jae .Lfill_narrow_block
.Lfill_narrow_tail:
    # A masked final block, so the helper never writes past out[len).  The load
    # side is masked too: out may be the caller's exact-sized buffer, but in may
    # equally be, and this runs before anything else has touched either.
    test %rdx, %rdx
    jz .Lfill_narrow_done
    mov \$-1, %rax
    bzhi %rdx, %rax, %rax
    kmovq %rax, %k1
    vmovdqu8 (%rsi,%r11), %zmm0\{%k1\}\{z\}
    vpxorq (%r10,%r11), %zmm0, %zmm0
    vmovdqu8 %zmm0, (%rdi,%r11)\{%k1\}
.Lfill_narrow_done:
    vzeroupper
    ret
";
}

$code =~ s/\`([^\`]*)\`/eval $1/gem;

print $code;

close STDOUT or die "error closing STDOUT: $!";
