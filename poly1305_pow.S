// Copyright 2026 soda4fries
// SPDX-License-Identifier: Apache-2.0

#define M44 0xfffffffffff
#define M42 0x3ffffffffff

        .text

// poly1305_mkkey44: (%rdi = q out, %rsi = x in)
        .globl  poly1305_mkkey44
        .type   poly1305_mkkey44,@function
        .align  32
poly1305_mkkey44:
        movq    0(%rsi), %r8
        movq    8(%rsi), %r9
        movq    16(%rsi), %r10
        movabsq $M44, %rax
        movq    %r8, %rcx
        andq    %rax, %rcx
        movq    %rcx, 0(%rdi)
        movq    %r9, %rcx
        shlq    $20, %rcx
        movq    %r8, %rdx
        shrq    $44, %rdx
        orq     %rdx, %rcx
        andq    %rax, %rcx
        movq    %rcx, 8(%rdi)
        leaq    (%rcx,%rcx,4), %rdx
        shlq    $2, %rdx
        movq    %rdx, 24(%rdi)
        movq    %r10, %rcx
        shlq    $40, %rcx
        movq    %r9, %rdx
        shrq    $24, %rdx
        orq     %rdx, %rcx
        movabsq $M42, %rax
        andq    %rax, %rcx
        movq    %rcx, 16(%rdi)
        leaq    (%rcx,%rcx,4), %rdx
        shlq    $2, %rdx
        movq    %rdx, 32(%rdi)
        ret
        .size   poly1305_mkkey44,.-poly1305_mkkey44

// poly1305_gmul44: (%rdi = x, %rsi = q)
        .globl  poly1305_gmul44
        .type   poly1305_gmul44,@function
        .align  32
poly1305_gmul44:
        pushq   %rbp
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        subq    $32, %rsp
        movq    %rsi, %rbp
        movq    %rdi, %rbx

        movq    0(%rbx), %r14
        movq    8(%rbx), %r15
        movq    16(%rbx), %r10
        movabsq $M44, %rax
        movq    %r14, %r8
        andq    %rax, %r8
        movq    %r15, %r9
        shlq    $20, %r9
        shrq    $44, %r14
        orq     %r14, %r9
        andq    %rax, %r9
        shlq    $40, %r10
        shrq    $24, %r15
        orq     %r15, %r10
        movabsq $M42, %rax
        andq    %rax, %r10

        movq    %r8, %rdx
        mulxq   0(%rbp), %r11, %r14
        movq    %r14, 0(%rsp)
        mulxq   8(%rbp), %r12, %r14
        movq    %r14, 8(%rsp)
        mulxq   16(%rbp), %r13, %r14
        movq    %r14, 16(%rsp)

        movq    %r9, %rdx
        mulxq   32(%rbp), %r14, %r15
        addq    %r14, %r11
        adcq    %r15, 0(%rsp)
        mulxq   0(%rbp), %r14, %r15
        addq    %r14, %r12
        adcq    %r15, 8(%rsp)
        mulxq   8(%rbp), %r14, %r15
        addq    %r14, %r13
        adcq    %r15, 16(%rsp)

        movq    %r10, %rdx
        mulxq   24(%rbp), %r14, %r15
        addq    %r14, %r11
        adcq    %r15, 0(%rsp)
        mulxq   32(%rbp), %r14, %r15
        addq    %r14, %r12
        adcq    %r15, 8(%rsp)
        mulxq   0(%rbp), %r14, %r15
        addq    %r14, %r13
        adcq    %r15, 16(%rsp)

        movabsq $M44, %rax
        movq    %r11, %r8
        andq    %rax, %r8
        movq    0(%rsp), %r14
        shrdq   $44, %r14, %r11
        addq    %r11, %r12
        adcq    $0, 8(%rsp)
        movq    %r12, %r9
        andq    %rax, %r9
        movq    8(%rsp), %r14
        shrdq   $44, %r14, %r12
        addq    %r12, %r13
        adcq    $0, 16(%rsp)
        movabsq $M42, %rax
        movq    %r13, %r10
        andq    %rax, %r10
        movq    16(%rsp), %r14
        shrdq   $42, %r14, %r13
        leaq    (%r13,%r13,4), %r14
        addq    %r14, %r8
        movq    %r8, %r15
        shrq    $44, %r15
        movabsq $M44, %rax
        andq    %rax, %r8
        addq    %r15, %r9

        movq    %r9, %r14
        shlq    $44, %r14
        movq    %r8, %r15
        orq     %r14, %r15
        movq    %r15, 0(%rbx)
        movq    %r9, %r14
        shrq    $20, %r14
        movq    %r10, %r15
        shlq    $24, %r15
        orq     %r15, %r14
        movq    %r14, 8(%rbx)
        movq    %r10, %r14
        shrq    $40, %r14
        movq    %r14, 16(%rbx)

        addq    $32, %rsp
        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %rbx
        popq    %rbp
        ret
        .size   poly1305_gmul44,.-poly1305_gmul44

// poly1305_gmul44_fast: (%rdi = x, %rsi = q)
        .globl  poly1305_gmul44_fast
        .type   poly1305_gmul44_fast,@function
        .align  32
poly1305_gmul44_fast:
        movq    0(%rdi), %r8
        movq    8(%rdi), %r9
        movq    16(%rdi), %r10
        movabsq $M44, %rax
        movq    %r8, %rcx
        andq    %rax, %rcx
        movq    %rcx, 0(%rdi)
        movq    %r9, %rcx
        shlq    $20, %rcx
        shrq    $44, %r8
        orq     %r8, %rcx
        andq    %rax, %rcx
        movq    %rcx, 8(%rdi)
        shlq    $40, %r10
        shrq    $24, %r9
        orq     %r9, %r10
        movabsq $M42, %rax
        andq    %rax, %r10
        movq    %r10, 16(%rdi)

        movq    0(%rdi), %rdx
        mulxq   0(%rsi), %r8, %r9
        movq    8(%rdi), %rdx
        mulxq   32(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    16(%rdi), %rdx
        mulxq   24(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    %r8, %rax
        movabsq $M44, %r10
        andq    %r10, %rax
        shrdq   $44, %r9, %r8
        shrq    $44, %r9

        movq    0(%rdi), %rdx
        mulxq   8(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    8(%rdi), %rdx
        mulxq   0(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    16(%rdi), %rdx
        mulxq   32(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    %r8, %rcx
        movabsq $M44, %r10
        andq    %r10, %rcx
        shrdq   $44, %r9, %r8
        shrq    $44, %r9

        movq    0(%rdi), %rdx
        mulxq   16(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    8(%rdi), %rdx
        mulxq   8(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    16(%rdi), %rdx
        mulxq   0(%rsi), %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    %r8, %rdx
        movabsq $M42, %r10
        andq    %r10, %rdx
        shrdq   $42, %r9, %r8

        leaq    (%r8,%r8,4), %r8
        addq    %r8, %rax
        movq    %rax, %r9
        shrq    $44, %r9
        movabsq $M44, %r10
        andq    %r10, %rax
        addq    %r9, %rcx

        movq    %rcx, %r8
        shlq    $44, %r8
        orq     %rax, %r8
        movq    %r8, 0(%rdi)
        shrq    $20, %rcx
        movq    %rdx, %r8
        shlq    $24, %r8
        orq     %r8, %rcx
        movq    %rcx, 8(%rdi)
        shrq    $40, %rdx
        movq    %rdx, 16(%rdi)
        ret
        .size   poly1305_gmul44_fast,.-poly1305_gmul44_fast

// poly1305_pow32: (%rdi = q out, %rsi = r[2])
        .globl  poly1305_pow32
        .type   poly1305_pow32,@function
        .align  32
poly1305_pow32:
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        pushq   %r14
        pushq   %r15
        movq    0(%rsi), %r8
        movq    8(%rsi), %r9
        movabsq $M44, %r15
        movq    %r8, %rbx
        andq    %r15, %rbx
        movq    %r9, %r12
        shlq    $20, %r12
        shrq    $44, %r8
        orq     %r8, %r12
        andq    %r15, %r12
        movq    %r9, %r13
        shrq    $24, %r13
        movl    $5, %r14d

.Lpow32_sqr:
        leaq    (%r13,%r13,4), %rax
        shlq    $3, %rax
        movq    %r12, %rdx
        mulxq   %rax, %r8, %r9
        movq    %rbx, %rdx
        mulxq   %rbx, %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    %r8, %rcx
        andq    %r15, %rcx
        shrdq   $44, %r9, %r8
        shrq    $44, %r9

        leaq    (%r13,%r13,4), %rax
        shlq    $2, %rax
        movq    %r13, %rdx
        mulxq   %rax, %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        leaq    (%rbx,%rbx), %rax
        movq    %r12, %rdx
        mulxq   %rax, %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    %r8, %rsi
        andq    %r15, %rsi
        shrdq   $44, %r9, %r8
        shrq    $44, %r9

        leaq    (%rbx,%rbx), %rax
        movq    %r13, %rdx
        mulxq   %rax, %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movq    %r12, %rdx
        mulxq   %r12, %r10, %r11
        addq    %r10, %r8
        adcq    %r11, %r9
        movabsq $M42, %rax
        movq    %r8, %r13
        andq    %rax, %r13
        shrdq   $42, %r9, %r8

        leaq    (%r8,%r8,4), %r8
        addq    %r8, %rcx
        movq    %rcx, %rax
        shrq    $44, %rax
        andq    %r15, %rcx
        movq    %rcx, %rbx
        addq    %rax, %rsi
        movq    %rsi, %rax
        shrq    $44, %rax
        andq    %r15, %rsi
        movq    %rsi, %r12
        addq    %rax, %r13

        decl    %r14d
        jnz     .Lpow32_sqr

        movq    %rbx, 0(%rdi)
        movq    %r12, 8(%rdi)
        movq    %r13, 16(%rdi)
        leaq    (%r12,%r12,4), %rax
        shlq    $2, %rax
        movq    %rax, 24(%rdi)
        leaq    (%r13,%r13,4), %rax
        shlq    $2, %rax
        movq    %rax, 32(%rdi)
        popq    %r15
        popq    %r14
        popq    %r13
        popq    %r12
        popq    %rbx
        ret
        .size   poly1305_pow32,.-poly1305_pow32

// poly1305_pow44: (%rdi = q out, %rsi = r[2], %edx = n)
        .globl  poly1305_pow44
        .type   poly1305_pow44,@function
        .align  32
poly1305_pow44:
        pushq   %rbx
        pushq   %r12
        pushq   %r13
        subq    $112, %rsp
        movq    %rdi, %rbx
        movl    %edx, %r13d
        movq    $1, 0(%rsp)
        movq    $0, 8(%rsp)
        movq    $0, 16(%rsp)
        movq    0(%rsi), %rax
        movq    %rax, 24(%rsp)
        movq    8(%rsi), %rax
        movq    %rax, 32(%rsp)
        movq    $0, 40(%rsp)
.Lpow44_loop:
        testl   $1, %r13d
        jz      .Lpow44_no_mul
        leaq    48(%rsp), %rdi
        leaq    24(%rsp), %rsi
        call    poly1305_mkkey44
        movq    %rsp, %rdi
        leaq    48(%rsp), %rsi
        call    poly1305_gmul44_fast
.Lpow44_no_mul:
        shrl    $1, %r13d
        jz      .Lpow44_done
        leaq    48(%rsp), %rdi
        leaq    24(%rsp), %rsi
        call    poly1305_mkkey44
        leaq    24(%rsp), %rdi
        leaq    48(%rsp), %rsi
        call    poly1305_gmul44_fast
        jmp     .Lpow44_loop
.Lpow44_done:
        movq    %rbx, %rdi
        movq    %rsp, %rsi
        call    poly1305_mkkey44
        addq    $112, %rsp
        popq    %r13
        popq    %r12
        popq    %rbx
        ret
        .size   poly1305_pow44,.-poly1305_pow44
        .section .note.GNU-stack,"",@progbits
