// Copyright 2026 soda4fries
// SPDX-License-Identifier: Apache-2.0

#define M44 0xfffffffffff
#define M42 0x3ffffffffff

        .text

// poly1305_gmul44_karatsuba: (%rdi = x, %rsi = q)
        .globl  poly1305_gmul44_karatsuba
        .type   poly1305_gmul44_karatsuba,@function
        .align  32
poly1305_gmul44_karatsuba:
        pushq   %rbx
        pushq   %rbp
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        subq    $96, %rsp
        movq    %rdi, %rbx
        movq    %rsi, %rbp

        movq    0(%rbx), %r8
        movq    8(%rbx), %r9
        movq    16(%rbx), %r10
        movabsq $M44, %rax
        movq    %r8, %rcx
        andq    %rax, %rcx
        movq    %rcx, 0(%rsp)
        movq    %r9, %rcx
        shlq    $20, %rcx
        shrq    $44, %r8
        orq     %r8, %rcx
        andq    %rax, %rcx
        movq    %rcx, 8(%rsp)
        shlq    $40, %r10
        shrq    $24, %r9
        orq     %r9, %r10
        movabsq $M42, %rax
        andq    %rax, %r10
        movq    %r10, 16(%rsp)

        movq    0(%rsp), %rdx
        mulxq   0(%rbp), %r8, %r9
        movq    %r8, 24(%rsp)
        movq    %r9, 32(%rsp)
        movq    8(%rsp), %rdx
        mulxq   8(%rbp), %r8, %r9
        movq    %r8, 40(%rsp)
        movq    %r9, 48(%rsp)
        movq    16(%rsp), %rdx
        mulxq   16(%rbp), %r8, %r9
        movq    %r8, 56(%rsp)
        movq    %r9, 64(%rsp)

        movq    8(%rsp), %rdx
        addq    16(%rsp), %rdx
        movq    8(%rbp), %rax
        addq    16(%rbp), %rax
        mulxq   %rax, %r14, %r15
        subq    40(%rsp), %r14
        sbbq    48(%rsp), %r15
        subq    56(%rsp), %r14
        sbbq    64(%rsp), %r15

        movq    %r14, %r8
        movq    %r15, %r9
        shldq   $4, %r8, %r9
        shlq    $4, %r8
        movq    %r14, %r10
        movq    %r15, %r11
        shldq   $2, %r10, %r11
        shlq    $2, %r10
        addq    %r10, %r8
        adcq    %r11, %r9
        addq    24(%rsp), %r8
        adcq    32(%rsp), %r9
        movq    %r8, %rax
        movabsq $M44, %r10
        andq    %r10, %rax
        shrdq   $44, %r9, %r8
        shrq    $44, %r9
        movq    %r8, 72(%rsp)
        movq    %r9, 80(%rsp)

        movq    0(%rsp), %rdx
        addq    8(%rsp), %rdx
        movq    0(%rbp), %r8
        addq    8(%rbp), %r8
        mulxq   %r8, %r14, %r15
        subq    24(%rsp), %r14
        sbbq    32(%rsp), %r15
        subq    40(%rsp), %r14
        sbbq    48(%rsp), %r15

        movq    56(%rsp), %r8
        movq    64(%rsp), %r9
        movq    %r8, %r10
        movq    %r9, %r11
        shldq   $4, %r8, %r9
        shlq    $4, %r8
        shldq   $2, %r10, %r11
        shlq    $2, %r10
        addq    %r10, %r8
        adcq    %r11, %r9
        addq    %r14, %r8
        adcq    %r15, %r9
        addq    72(%rsp), %r8
        adcq    80(%rsp), %r9
        movq    %r8, %rcx
        movabsq $M44, %r10
        andq    %r10, %rcx
        shrdq   $44, %r9, %r8
        shrq    $44, %r9
        movq    %r8, 72(%rsp)
        movq    %r9, 80(%rsp)

        movq    0(%rsp), %rdx
        addq    16(%rsp), %rdx
        movq    0(%rbp), %r8
        addq    16(%rbp), %r8
        mulxq   %r8, %r14, %r15
        subq    24(%rsp), %r14
        sbbq    32(%rsp), %r15
        subq    56(%rsp), %r14
        sbbq    64(%rsp), %r15
        addq    40(%rsp), %r14
        adcq    48(%rsp), %r15
        addq    72(%rsp), %r14
        adcq    80(%rsp), %r15

        movq    %r14, %rdx
        movabsq $M42, %r10
        andq    %r10, %rdx
        shrdq   $42, %r15, %r14
        leaq    (%r14,%r14,4), %r14
        addq    %r14, %rax
        movq    %rax, %r9
        shrq    $44, %r9
        movabsq $M44, %r10
        andq    %r10, %rax
        addq    %r9, %rcx

        movq    %rcx, %r8
        shlq    $44, %r8
        orq     %rax, %r8
        movq    %r8, 0(%rbx)
        shrq    $20, %rcx
        movq    %rdx, %r8
        shlq    $24, %r8
        orq     %r8, %rcx
        movq    %rcx, 8(%rbx)
        shrq    $40, %rdx
        movq    %rdx, 16(%rbx)

        addq    $96, %rsp
        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %rbp
        popq    %rbx
        ret
        .size   poly1305_gmul44_karatsuba,.-poly1305_gmul44_karatsuba
