#! /usr/bin/env perl
# Copyright 2016-2025 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html
#
# Modifications (the 9x/17x schedules and their dispatch) Copyright 2026
# soda4fries, licensed under the same Apache License 2.0.


# $output is the last argument if it looks like a file (it has an extension)
# $flavour is the first argument if it doesn't look like a file
$output = $#ARGV >= 0 && $ARGV[$#ARGV] =~ m|\.\w+$| ? pop : undef;
$flavour = $#ARGV >= 0 && $ARGV[0] !~ m|\.| ? shift : undef;

$win64=0; $win64=1 if ($flavour =~ /[nm]asm|mingw64/ || $output =~ /\.asm$/);

$0 =~ m/(.*[\/\\])[^\/\\]+$/; $dir=$1;
( $xlate="${dir}x86_64-xlate.pl" and -f $xlate ) or
( $xlate="${dir}../../perlasm/x86_64-xlate.pl" and -f $xlate) or
die "can't locate x86_64-xlate.pl";

if (`$ENV{CC} -Wa,-v -c -o /dev/null -x assembler /dev/null 2>&1`
		=~ /GNU assembler version ([0-9]+)\.([0-9]+)/) {
	my $ver = $1 + $2/100.0; # 3.1->3.01, 3.10->3.10
	$avx = ($ver >= 2.19) + ($ver >= 2.22) + ($ver >= 2.25);
}

if (!$avx && $win64 && ($flavour =~ /nasm/ || $ENV{ASM} =~ /nasm/) &&
	   `nasm -v 2>&1` =~ /NASM version ([0-9]+)\.([0-9]+)(?:\.([0-9]+))?/) {
	my $ver = $1 + $2/100.0 + $3/10000.0; # 3.1.0->3.01, 3.10.1->3.1001
	$avx = ($ver >= 2.09) + ($ver >= 2.10) + ($ver >= 2.1108);
}

if (!$avx && $win64 && ($flavour =~ /masm/ || $ENV{ASM} =~ /ml64/) &&
	   `ml64 2>&1` =~ /Version ([0-9]+)\./) {
	$avx = ($1>=10) + ($1>=11);
}

if (!$avx && `$ENV{CC} -v 2>&1` =~ /((?:clang|LLVM) version|.*based on LLVM) ([0-9]+\.[0-9]+)/) {
	$avx = ($2>=3.0) + ($2>3.0);
}

if (!$avx && `$ENV{CC} -x c /dev/null -dM -E|grep __clang_major__`
	=~ /#define __clang_major__.([0-9]+)/) {
	if ($1) {
		$avx = ($1>=11); #icx started with clang 11
	}
}

open OUT,"| \"$^X\" \"$xlate\" $flavour \"$output\""
    or die "can't call $xlate: $!";
*STDOUT=*OUT;

# input parameter block
($out,$inp,$len,$key,$counter)=("%rdi","%rsi","%rdx","%rcx","%r8");

$code.=<<___;
.text

.extern OPENSSL_ia32cap_P

.section .rodata align=64
.align	64
.Lzero:
.long	0,0,0,0
.Lone:
.long	1,0,0,0
.Linc:
.long	0,1,2,3
.Lfour:
.long	4,4,4,4
.Lincy:
.long	0,2,4,6,1,3,5,7
.Leight:
.long	8,8,8,8,8,8,8,8
.Lnine:
.long	9,9,9,9,9,9,9,9
.Lrot16:
.byte	0x2,0x3,0x0,0x1, 0x6,0x7,0x4,0x5, 0xa,0xb,0x8,0x9, 0xe,0xf,0xc,0xd
.Lrot24:
.byte	0x3,0x0,0x1,0x2, 0x7,0x4,0x5,0x6, 0xb,0x8,0x9,0xa, 0xf,0xc,0xd,0xe
.Ltwoy:
.long	2,0,0,0, 2,0,0,0
.align	64
.Lzeroz:
.long	0,0,0,0, 1,0,0,0, 2,0,0,0, 3,0,0,0
.Lfourz:
.long	4,0,0,0, 4,0,0,0, 4,0,0,0, 4,0,0,0
.Lincz:
.long	0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
.Lsixteen:
.long	16,16,16,16,16,16,16,16,16,16,16,16,16,16,16,16
.Lseventeen:
.long	17,17,17,17,17,17,17,17,17,17,17,17,17,17,17,17
.Leighteen:
.long	18,18,18,18,18,18,18,18,18,18,18,18,18,18,18,18
.Lthirtytwo:
.long	32,32,32,32,32,32,32,32,32,32,32,32,32,32,32,32
.Lsigma:
.asciz	"expand 32-byte k"
.asciz	"ChaCha20 for x86_64, CRYPTOGAMS by <https://github.com/dot-asm>"
.previous
___

sub AUTOLOAD()          # thunk [simplified] 32-bit style perlasm
{ my $opcode = $AUTOLOAD; $opcode =~ s/.*:://;
  my $arg = pop;
    $arg = "\$$arg" if ($arg*1 eq $arg);
    $code .= "\t$opcode\t".join(',',$arg,reverse @_)."\n";
}

@x=("%eax","%ebx","%ecx","%edx",map("%r${_}d",(8..11)),
    "%nox","%nox","%nox","%nox",map("%r${_}d",(12..15)));
@t=("%esi","%edi");

sub ROUND {			# critical path is 24 cycles per round
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_)=map("\"$_\"",@t);
my @x=map("\"$_\"",@x);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @x[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# bunch of 'c' stores and loads in the middle, but none in
	# the beginning or end.

	# Normally instructions would be interleaved to favour in-order
	# execution. Generally out-of-order cores manage it gracefully,
	# but not this time for some reason. As in-order execution
	# cores are dying breed, old Atom is the only one around,
	# instructions are left uninterleaved. Besides, Atom is better
	# off executing 1xSSSE3 code anyway...

	(
	"&add	(@x[$a0],@x[$b0])",	# Q1
	"&xor	(@x[$d0],@x[$a0])",
	"&rol	(@x[$d0],16)",
	 "&add	(@x[$a1],@x[$b1])",	# Q2
	 "&xor	(@x[$d1],@x[$a1])",
	 "&rol	(@x[$d1],16)",

	"&add	($xc,@x[$d0])",
	"&xor	(@x[$b0],$xc)",
	"&rol	(@x[$b0],12)",
	 "&add	($xc_,@x[$d1])",
	 "&xor	(@x[$b1],$xc_)",
	 "&rol	(@x[$b1],12)",

	"&add	(@x[$a0],@x[$b0])",
	"&xor	(@x[$d0],@x[$a0])",
	"&rol	(@x[$d0],8)",
	 "&add	(@x[$a1],@x[$b1])",
	 "&xor	(@x[$d1],@x[$a1])",
	 "&rol	(@x[$d1],8)",

	"&add	($xc,@x[$d0])",
	"&xor	(@x[$b0],$xc)",
	"&rol	(@x[$b0],7)",
	 "&add	($xc_,@x[$d1])",
	 "&xor	(@x[$b1],$xc_)",
	 "&rol	(@x[$b1],7)",

	"&mov	(\"4*$c0(%rsp)\",$xc)",	# reload pair of 'c's
	 "&mov	(\"4*$c1(%rsp)\",$xc_)",
	"&mov	($xc,\"4*$c2(%rsp)\")",
	 "&mov	($xc_,\"4*$c3(%rsp)\")",

	"&add	(@x[$a2],@x[$b2])",	# Q3
	"&xor	(@x[$d2],@x[$a2])",
	"&rol	(@x[$d2],16)",
	 "&add	(@x[$a3],@x[$b3])",	# Q4
	 "&xor	(@x[$d3],@x[$a3])",
	 "&rol	(@x[$d3],16)",

	"&add	($xc,@x[$d2])",
	"&xor	(@x[$b2],$xc)",
	"&rol	(@x[$b2],12)",
	 "&add	($xc_,@x[$d3])",
	 "&xor	(@x[$b3],$xc_)",
	 "&rol	(@x[$b3],12)",

	"&add	(@x[$a2],@x[$b2])",
	"&xor	(@x[$d2],@x[$a2])",
	"&rol	(@x[$d2],8)",
	 "&add	(@x[$a3],@x[$b3])",
	 "&xor	(@x[$d3],@x[$a3])",
	 "&rol	(@x[$d3],8)",

	"&add	($xc,@x[$d2])",
	"&xor	(@x[$b2],$xc)",
	"&rol	(@x[$b2],7)",
	 "&add	($xc_,@x[$d3])",
	 "&xor	(@x[$b3],$xc_)",
	 "&rol	(@x[$b3],7)"
	);
}

########################################################################
# Generic code path that handles all lengths on pre-SSSE3 processors.
$code.=<<___;
.globl	ChaCha20_ctr32
.type	ChaCha20_ctr32,\@function,5
.align	64
ChaCha20_ctr32:
.cfi_startproc
	cmp	\$0,$len
	je	.Lno_data
	mov	OPENSSL_ia32cap_P+4(%rip),%r10
___
$code.=<<___	if ($avx>2);
	bt	\$48,%r10		# check for AVX512F
	jc	.LChaCha20_avx512
	test	%r10,%r10		# check for AVX512VL
	js	.LChaCha20_avx512vl
___
$code.=<<___;
	test	\$`1<<(41-32)`,%r10d
	jnz	.LChaCha20_ssse3

	push	%rbx
.cfi_push	%rbx
	push	%rbp
.cfi_push	%rbp
	push	%r12
.cfi_push	%r12
	push	%r13
.cfi_push	%r13
	push	%r14
.cfi_push	%r14
	push	%r15
.cfi_push	%r15
	sub	\$64+24,%rsp
.cfi_adjust_cfa_offset	64+24
.Lctr32_body:

	#movdqa	.Lsigma(%rip),%xmm0
	movdqu	($key),%xmm1
	movdqu	16($key),%xmm2
	movdqu	($counter),%xmm3
	movdqa	.Lone(%rip),%xmm4

	#movdqa	%xmm0,4*0(%rsp)		# key[0]
	movdqa	%xmm1,4*4(%rsp)		# key[1]
	movdqa	%xmm2,4*8(%rsp)		# key[2]
	movdqa	%xmm3,4*12(%rsp)	# key[3]
	mov	$len,%rbp		# reassign $len
	jmp	.Loop_outer

.align	32
.Loop_outer:
	mov	\$0x61707865,@x[0]      # 'expa'
	mov	\$0x3320646e,@x[1]      # 'nd 3'
	mov	\$0x79622d32,@x[2]      # '2-by'
	mov	\$0x6b206574,@x[3]      # 'te k'
	mov	4*4(%rsp),@x[4]
	mov	4*5(%rsp),@x[5]
	mov	4*6(%rsp),@x[6]
	mov	4*7(%rsp),@x[7]
	movd	%xmm3,@x[12]
	mov	4*13(%rsp),@x[13]
	mov	4*14(%rsp),@x[14]
	mov	4*15(%rsp),@x[15]

	mov	%rbp,64+0(%rsp)		# save len
	mov	\$10,%ebp
	mov	$inp,64+8(%rsp)		# save inp
	movq	%xmm2,%rsi		# "@x[8]"
	mov	$out,64+16(%rsp)	# save out
	mov	%rsi,%rdi
	shr	\$32,%rdi		# "@x[9]"
	jmp	.Loop

.align	32
.Loop:
___
	foreach (&ROUND (0, 4, 8,12)) { eval; }
	foreach (&ROUND	(0, 5,10,15)) { eval; }
	&dec	("%ebp");
	&jnz	(".Loop");

$code.=<<___;
	mov	@t[1],4*9(%rsp)		# modulo-scheduled
	mov	@t[0],4*8(%rsp)
	mov	64(%rsp),%rbp		# load len
	movdqa	%xmm2,%xmm1
	mov	64+8(%rsp),$inp		# load inp
	paddd	%xmm4,%xmm3		# increment counter
	mov	64+16(%rsp),$out	# load out

	add	\$0x61707865,@x[0]      # 'expa'
	add	\$0x3320646e,@x[1]      # 'nd 3'
	add	\$0x79622d32,@x[2]      # '2-by'
	add	\$0x6b206574,@x[3]      # 'te k'
	add	4*4(%rsp),@x[4]
	add	4*5(%rsp),@x[5]
	add	4*6(%rsp),@x[6]
	add	4*7(%rsp),@x[7]
	add	4*12(%rsp),@x[12]
	add	4*13(%rsp),@x[13]
	add	4*14(%rsp),@x[14]
	add	4*15(%rsp),@x[15]
	paddd	4*8(%rsp),%xmm1

	cmp	\$64,%rbp
	jb	.Ltail

	xor	4*0($inp),@x[0]		# xor with input
	xor	4*1($inp),@x[1]
	xor	4*2($inp),@x[2]
	xor	4*3($inp),@x[3]
	xor	4*4($inp),@x[4]
	xor	4*5($inp),@x[5]
	xor	4*6($inp),@x[6]
	xor	4*7($inp),@x[7]
	movdqu	4*8($inp),%xmm0
	xor	4*12($inp),@x[12]
	xor	4*13($inp),@x[13]
	xor	4*14($inp),@x[14]
	xor	4*15($inp),@x[15]
	lea	4*16($inp),$inp		# inp+=64
	pxor	%xmm1,%xmm0

	movdqa	%xmm2,4*8(%rsp)
	movd	%xmm3,4*12(%rsp)

	mov	@x[0],4*0($out)		# write output
	mov	@x[1],4*1($out)
	mov	@x[2],4*2($out)
	mov	@x[3],4*3($out)
	mov	@x[4],4*4($out)
	mov	@x[5],4*5($out)
	mov	@x[6],4*6($out)
	mov	@x[7],4*7($out)
	movdqu	%xmm0,4*8($out)
	mov	@x[12],4*12($out)
	mov	@x[13],4*13($out)
	mov	@x[14],4*14($out)
	mov	@x[15],4*15($out)
	lea	4*16($out),$out		# out+=64

	sub	\$64,%rbp
	jnz	.Loop_outer

	jmp	.Ldone

.align	16
.Ltail:
	mov	@x[0],4*0(%rsp)
	mov	@x[1],4*1(%rsp)
	xor	%rbx,%rbx
	mov	@x[2],4*2(%rsp)
	mov	@x[3],4*3(%rsp)
	mov	@x[4],4*4(%rsp)
	mov	@x[5],4*5(%rsp)
	mov	@x[6],4*6(%rsp)
	mov	@x[7],4*7(%rsp)
	movdqa	%xmm1,4*8(%rsp)
	mov	@x[12],4*12(%rsp)
	mov	@x[13],4*13(%rsp)
	mov	@x[14],4*14(%rsp)
	mov	@x[15],4*15(%rsp)

.Loop_tail:
	movzb	($inp,%rbx),%eax
	movzb	(%rsp,%rbx),%edx
	lea	1(%rbx),%rbx
	xor	%edx,%eax
	mov	%al,-1($out,%rbx)
	dec	%rbp
	jnz	.Loop_tail

.Ldone:
	lea	64+24+48(%rsp),%rsi
.cfi_def_cfa	%rsi,8
	mov	-48(%rsi),%r15
.cfi_restore	%r15
	mov	-40(%rsi),%r14
.cfi_restore	%r14
	mov	-32(%rsi),%r13
.cfi_restore	%r13
	mov	-24(%rsi),%r12
.cfi_restore	%r12
	mov	-16(%rsi),%rbp
.cfi_restore	%rbp
	mov	-8(%rsi),%rbx
.cfi_restore	%rbx
	lea	(%rsi),%rsp
.cfi_def_cfa_register	%rsp
.Lno_data:
	ret
.cfi_endproc
.size	ChaCha20_ctr32,.-ChaCha20_ctr32
___

########################################################################
# SSSE3 code path that handles shorter lengths
{
my ($a,$b,$c,$d,$t,$t1,$rot16,$rot24)=map("%xmm$_",(0..7));

sub SSSE3ROUND {	# critical path is 20 "SIMD ticks" per round
	&paddd	($a,$b);
	&pxor	($d,$a);
	&pshufb	($d,$rot16);

	&paddd	($c,$d);
	&pxor	($b,$c);
	&movdqa	($t,$b);
	&psrld	($b,20);
	&pslld	($t,12);
	&por	($b,$t);

	&paddd	($a,$b);
	&pxor	($d,$a);
	&pshufb	($d,$rot24);

	&paddd	($c,$d);
	&pxor	($b,$c);
	&movdqa	($t,$b);
	&psrld	($b,25);
	&pslld	($t,7);
	&por	($b,$t);
}

my $xframe = $win64 ? 160+8 : 8;

$code.=<<___;
.type	ChaCha20_ssse3,\@function,5
.align	32
ChaCha20_ssse3:
.cfi_startproc
.LChaCha20_ssse3:
	mov	%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
___
$code.=<<___	if ($avx);
	test	\$`1<<(43-32)`,%r10d
	jnz	.LChaCha20_4xop		# XOP is fastest even if we use 1/4
___
$code.=<<___;
	cmp	\$128,$len		# we might throw away some data,
	je	.LChaCha20_128
	ja	.LChaCha20_4x		# but overall it won't be slower

.Ldo_sse3_after_all:
	sub	\$64+$xframe,%rsp
___
$code.=<<___	if ($win64);
	movaps	%xmm6,-0x28(%r9)
	movaps	%xmm7,-0x18(%r9)
.Lssse3_body:
___
$code.=<<___;
	movdqa	.Lsigma(%rip),$a
	movdqu	($key),$b
	movdqu	16($key),$c
	movdqu	($counter),$d
	movdqa	.Lrot16(%rip),$rot16
	movdqa	.Lrot24(%rip),$rot24

	movdqa	$a,0x00(%rsp)
	movdqa	$b,0x10(%rsp)
	movdqa	$c,0x20(%rsp)
	movdqa	$d,0x30(%rsp)
	mov	\$10,$counter		# reuse $counter
	jmp	.Loop_ssse3

.align	32
.Loop_outer_ssse3:
	movdqa	.Lone(%rip),$d
	movdqa	0x00(%rsp),$a
	movdqa	0x10(%rsp),$b
	movdqa	0x20(%rsp),$c
	paddd	0x30(%rsp),$d
	mov	\$10,$counter
	movdqa	$d,0x30(%rsp)
	jmp	.Loop_ssse3

.align	32
.Loop_ssse3:
___
	&SSSE3ROUND();
	&pshufd	($c,$c,0b01001110);
	&pshufd	($b,$b,0b00111001);
	&pshufd	($d,$d,0b10010011);
	&nop	();

	&SSSE3ROUND();
	&pshufd	($c,$c,0b01001110);
	&pshufd	($b,$b,0b10010011);
	&pshufd	($d,$d,0b00111001);

	&dec	($counter);
	&jnz	(".Loop_ssse3");

$code.=<<___;
	paddd	0x00(%rsp),$a
	paddd	0x10(%rsp),$b
	paddd	0x20(%rsp),$c
	paddd	0x30(%rsp),$d

	cmp	\$64,$len
	jb	.Ltail_ssse3

	movdqu	0x00($inp),$t
	movdqu	0x10($inp),$t1
	pxor	$t,$a			# xor with input
	movdqu	0x20($inp),$t
	pxor	$t1,$b
	movdqu	0x30($inp),$t1
	lea	0x40($inp),$inp		# inp+=64
	pxor	$t,$c
	pxor	$t1,$d

	movdqu	$a,0x00($out)		# write output
	movdqu	$b,0x10($out)
	movdqu	$c,0x20($out)
	movdqu	$d,0x30($out)
	lea	0x40($out),$out		# out+=64

	sub	\$64,$len
	jnz	.Loop_outer_ssse3

	jmp	.Ldone_ssse3

.align	16
.Ltail_ssse3:
	movdqa	$a,0x00(%rsp)
	movdqa	$b,0x10(%rsp)
	movdqa	$c,0x20(%rsp)
	movdqa	$d,0x30(%rsp)
	xor	$counter,$counter

.Loop_tail_ssse3:
	movzb	($inp,$counter),%eax
	movzb	(%rsp,$counter),%ecx
	lea	1($counter),$counter
	xor	%ecx,%eax
	mov	%al,-1($out,$counter)
	dec	$len
	jnz	.Loop_tail_ssse3

.Ldone_ssse3:
___
$code.=<<___	if ($win64);
	movaps	-0x28(%r9),%xmm6
	movaps	-0x18(%r9),%xmm7
___
$code.=<<___;
	lea	(%r9),%rsp
.cfi_def_cfa_register	%rsp
.Lssse3_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_ssse3,.-ChaCha20_ssse3
___
}

########################################################################
# SSSE3 code path that handles 128-byte inputs
{
my ($a,$b,$c,$d,$t,$t1,$rot16,$rot24)=map("%xmm$_",(8,9,2..7));
my ($a1,$b1,$c1,$d1)=map("%xmm$_",(10,11,0,1));

sub SSSE3ROUND_2x {
	&paddd	($a,$b);
	&pxor	($d,$a);
	 &paddd	($a1,$b1);
	 &pxor	($d1,$a1);
	&pshufb	($d,$rot16);
	 &pshufb($d1,$rot16);

	&paddd	($c,$d);
	 &paddd	($c1,$d1);
	&pxor	($b,$c);
	 &pxor	($b1,$c1);
	&movdqa	($t,$b);
	&psrld	($b,20);
	 &movdqa($t1,$b1);
	&pslld	($t,12);
	 &psrld	($b1,20);
	&por	($b,$t);
	 &pslld	($t1,12);
	 &por	($b1,$t1);

	&paddd	($a,$b);
	&pxor	($d,$a);
	 &paddd	($a1,$b1);
	 &pxor	($d1,$a1);
	&pshufb	($d,$rot24);
	 &pshufb($d1,$rot24);

	&paddd	($c,$d);
	 &paddd	($c1,$d1);
	&pxor	($b,$c);
	 &pxor	($b1,$c1);
	&movdqa	($t,$b);
	&psrld	($b,25);
	 &movdqa($t1,$b1);
	&pslld	($t,7);
	 &psrld	($b1,25);
	&por	($b,$t);
	 &pslld	($t1,7);
	 &por	($b1,$t1);
}

my $xframe = $win64 ? 0x68 : 8;

$code.=<<___;
.type	ChaCha20_128,\@function,5
.align	32
ChaCha20_128:
.cfi_startproc
.LChaCha20_128:
	mov	%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	sub	\$64+$xframe,%rsp
___
$code.=<<___	if ($win64);
	movaps	%xmm6,-0x68(%r9)
	movaps	%xmm7,-0x58(%r9)
	movaps	%xmm8,-0x48(%r9)
	movaps	%xmm9,-0x38(%r9)
	movaps	%xmm10,-0x28(%r9)
	movaps	%xmm11,-0x18(%r9)
.L128_body:
___
$code.=<<___;
	movdqa	.Lsigma(%rip),$a
	movdqu	($key),$b
	movdqu	16($key),$c
	movdqu	($counter),$d
	movdqa	.Lone(%rip),$d1
	movdqa	.Lrot16(%rip),$rot16
	movdqa	.Lrot24(%rip),$rot24

	movdqa	$a,$a1
	movdqa	$a,0x00(%rsp)
	movdqa	$b,$b1
	movdqa	$b,0x10(%rsp)
	movdqa	$c,$c1
	movdqa	$c,0x20(%rsp)
	paddd	$d,$d1
	movdqa	$d,0x30(%rsp)
	mov	\$10,$counter		# reuse $counter
	jmp	.Loop_128

.align	32
.Loop_128:
___
	&SSSE3ROUND_2x();
	&pshufd	($c,$c,0b01001110);
	&pshufd	($b,$b,0b00111001);
	&pshufd	($d,$d,0b10010011);
	&pshufd	($c1,$c1,0b01001110);
	&pshufd	($b1,$b1,0b00111001);
	&pshufd	($d1,$d1,0b10010011);

	&SSSE3ROUND_2x();
	&pshufd	($c,$c,0b01001110);
	&pshufd	($b,$b,0b10010011);
	&pshufd	($d,$d,0b00111001);
	&pshufd	($c1,$c1,0b01001110);
	&pshufd	($b1,$b1,0b10010011);
	&pshufd	($d1,$d1,0b00111001);

	&dec	($counter);
	&jnz	(".Loop_128");

$code.=<<___;
	paddd	0x00(%rsp),$a
	paddd	0x10(%rsp),$b
	paddd	0x20(%rsp),$c
	paddd	0x30(%rsp),$d
	paddd	.Lone(%rip),$d1
	paddd	0x00(%rsp),$a1
	paddd	0x10(%rsp),$b1
	paddd	0x20(%rsp),$c1
	paddd	0x30(%rsp),$d1

	movdqu	0x00($inp),$t
	movdqu	0x10($inp),$t1
	pxor	$t,$a			# xor with input
	movdqu	0x20($inp),$t
	pxor	$t1,$b
	movdqu	0x30($inp),$t1
	pxor	$t,$c
	movdqu	0x40($inp),$t
	pxor	$t1,$d
	movdqu	0x50($inp),$t1
	pxor	$t,$a1
	movdqu	0x60($inp),$t
	pxor	$t1,$b1
	movdqu	0x70($inp),$t1
	pxor	$t,$c1
	pxor	$t1,$d1

	movdqu	$a,0x00($out)		# write output
	movdqu	$b,0x10($out)
	movdqu	$c,0x20($out)
	movdqu	$d,0x30($out)
	movdqu	$a1,0x40($out)
	movdqu	$b1,0x50($out)
	movdqu	$c1,0x60($out)
	movdqu	$d1,0x70($out)
___
$code.=<<___	if ($win64);
	movaps	-0x68(%r9),%xmm6
	movaps	-0x58(%r9),%xmm7
	movaps	-0x48(%r9),%xmm8
	movaps	-0x38(%r9),%xmm9
	movaps	-0x28(%r9),%xmm10
	movaps	-0x18(%r9),%xmm11
___
$code.=<<___;
	lea	(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L128_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_128,.-ChaCha20_128
___
}

########################################################################
# SSSE3 code path that handles longer messages.
{
# assign variables to favor Atom front-end
my ($xd0,$xd1,$xd2,$xd3, $xt0,$xt1,$xt2,$xt3,
    $xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3)=map("%xmm$_",(0..15));
my  @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	"%nox","%nox","%nox","%nox", $xd0,$xd1,$xd2,$xd3);

sub SSSE3_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_,$t0,$t1)=map("\"$_\"",$xt0,$xt1,$xt2,$xt3);
my @x=map("\"$_\"",@xx);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @x[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# bunch of 'c' stores and loads in the middle, but none in
	# the beginning or end.

	(
	"&paddd		(@x[$a0],@x[$b0])",	# Q1
	 "&paddd	(@x[$a1],@x[$b1])",	# Q2
	"&pxor		(@x[$d0],@x[$a0])",
	 "&pxor		(@x[$d1],@x[$a1])",
	"&pshufb	(@x[$d0],$t1)",
	 "&pshufb	(@x[$d1],$t1)",

	"&paddd		($xc,@x[$d0])",
	 "&paddd	($xc_,@x[$d1])",
	"&pxor		(@x[$b0],$xc)",
	 "&pxor		(@x[$b1],$xc_)",
	"&movdqa	($t0,@x[$b0])",
	"&pslld		(@x[$b0],12)",
	"&psrld		($t0,20)",
	 "&movdqa	($t1,@x[$b1])",
	 "&pslld	(@x[$b1],12)",
	"&por		(@x[$b0],$t0)",
	 "&psrld	($t1,20)",
	"&movdqa	($t0,'(%r11)')",	# .Lrot24(%rip)
	 "&por		(@x[$b1],$t1)",

	"&paddd		(@x[$a0],@x[$b0])",
	 "&paddd	(@x[$a1],@x[$b1])",
	"&pxor		(@x[$d0],@x[$a0])",
	 "&pxor		(@x[$d1],@x[$a1])",
	"&pshufb	(@x[$d0],$t0)",
	 "&pshufb	(@x[$d1],$t0)",

	"&paddd		($xc,@x[$d0])",
	 "&paddd	($xc_,@x[$d1])",
	"&pxor		(@x[$b0],$xc)",
	 "&pxor		(@x[$b1],$xc_)",
	"&movdqa	($t1,@x[$b0])",
	"&pslld		(@x[$b0],7)",
	"&psrld		($t1,25)",
	 "&movdqa	($t0,@x[$b1])",
	 "&pslld	(@x[$b1],7)",
	"&por		(@x[$b0],$t1)",
	 "&psrld	($t0,25)",
	"&movdqa	($t1,'(%r10)')",	# .Lrot16(%rip)
	 "&por		(@x[$b1],$t0)",

	"&movdqa	(\"`16*($c0-8)`(%rsp)\",$xc)",	# reload pair of 'c's
	 "&movdqa	(\"`16*($c1-8)`(%rsp)\",$xc_)",
	"&movdqa	($xc,\"`16*($c2-8)`(%rsp)\")",
	 "&movdqa	($xc_,\"`16*($c3-8)`(%rsp)\")",

	"&paddd		(@x[$a2],@x[$b2])",	# Q3
	 "&paddd	(@x[$a3],@x[$b3])",	# Q4
	"&pxor		(@x[$d2],@x[$a2])",
	 "&pxor		(@x[$d3],@x[$a3])",
	"&pshufb	(@x[$d2],$t1)",
	 "&pshufb	(@x[$d3],$t1)",

	"&paddd		($xc,@x[$d2])",
	 "&paddd	($xc_,@x[$d3])",
	"&pxor		(@x[$b2],$xc)",
	 "&pxor		(@x[$b3],$xc_)",
	"&movdqa	($t0,@x[$b2])",
	"&pslld		(@x[$b2],12)",
	"&psrld		($t0,20)",
	 "&movdqa	($t1,@x[$b3])",
	 "&pslld	(@x[$b3],12)",
	"&por		(@x[$b2],$t0)",
	 "&psrld	($t1,20)",
	"&movdqa	($t0,'(%r11)')",	# .Lrot24(%rip)
	 "&por		(@x[$b3],$t1)",

	"&paddd		(@x[$a2],@x[$b2])",
	 "&paddd	(@x[$a3],@x[$b3])",
	"&pxor		(@x[$d2],@x[$a2])",
	 "&pxor		(@x[$d3],@x[$a3])",
	"&pshufb	(@x[$d2],$t0)",
	 "&pshufb	(@x[$d3],$t0)",

	"&paddd		($xc,@x[$d2])",
	 "&paddd	($xc_,@x[$d3])",
	"&pxor		(@x[$b2],$xc)",
	 "&pxor		(@x[$b3],$xc_)",
	"&movdqa	($t1,@x[$b2])",
	"&pslld		(@x[$b2],7)",
	"&psrld		($t1,25)",
	 "&movdqa	($t0,@x[$b3])",
	 "&pslld	(@x[$b3],7)",
	"&por		(@x[$b2],$t1)",
	 "&psrld	($t0,25)",
	"&movdqa	($t1,'(%r10)')",	# .Lrot16(%rip)
	 "&por		(@x[$b3],$t0)"
	);
}

my $xframe = $win64 ? 0xa8 : 8;

$code.=<<___;
.type	ChaCha20_4x,\@function,5
.align	32
ChaCha20_4x:
.cfi_startproc
.LChaCha20_4x:
	mov		%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	mov		%r10,%r11
___
$code.=<<___	if ($avx>1);
	shr		\$32,%r10		# OPENSSL_ia32cap_P+8
	test		\$`1<<5`,%r10		# test AVX2
	jnz		.LChaCha20_9x
___
$code.=<<___;
	cmp		\$192,$len
	ja		.Lproceed4x

	and		\$`1<<26|1<<22`,%r11	# isolate XSAVE+MOVBE
	cmp		\$`1<<22`,%r11		# check for MOVBE without XSAVE
	je		.Ldo_sse3_after_all	# to detect Atom

.Lproceed4x:
	sub		\$0x140+$xframe,%rsp
___
	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x40		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x100	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x140
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
.L4x_body:
___
$code.=<<___;
	movdqa		.Lsigma(%rip),$xa3	# key[0]
	movdqu		($key),$xb3		# key[1]
	movdqu		16($key),$xt3		# key[2]
	movdqu		($counter),$xd3		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization
	lea		.Lrot16(%rip),%r10
	lea		.Lrot24(%rip),%r11

	pshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	pshufd		\$0x55,$xa3,$xa1
	movdqa		$xa0,0x40(%rsp)		# ... and offload
	pshufd		\$0xaa,$xa3,$xa2
	movdqa		$xa1,0x50(%rsp)
	pshufd		\$0xff,$xa3,$xa3
	movdqa		$xa2,0x60(%rsp)
	movdqa		$xa3,0x70(%rsp)

	pshufd		\$0x00,$xb3,$xb0
	pshufd		\$0x55,$xb3,$xb1
	movdqa		$xb0,0x80-0x100(%rcx)
	pshufd		\$0xaa,$xb3,$xb2
	movdqa		$xb1,0x90-0x100(%rcx)
	pshufd		\$0xff,$xb3,$xb3
	movdqa		$xb2,0xa0-0x100(%rcx)
	movdqa		$xb3,0xb0-0x100(%rcx)

	pshufd		\$0x00,$xt3,$xt0	# "$xc0"
	pshufd		\$0x55,$xt3,$xt1	# "$xc1"
	movdqa		$xt0,0xc0-0x100(%rcx)
	pshufd		\$0xaa,$xt3,$xt2	# "$xc2"
	movdqa		$xt1,0xd0-0x100(%rcx)
	pshufd		\$0xff,$xt3,$xt3	# "$xc3"
	movdqa		$xt2,0xe0-0x100(%rcx)
	movdqa		$xt3,0xf0-0x100(%rcx)

	pshufd		\$0x00,$xd3,$xd0
	pshufd		\$0x55,$xd3,$xd1
	paddd		.Linc(%rip),$xd0	# don't save counters yet
	pshufd		\$0xaa,$xd3,$xd2
	movdqa		$xd1,0x110-0x100(%rcx)
	pshufd		\$0xff,$xd3,$xd3
	movdqa		$xd2,0x120-0x100(%rcx)
	movdqa		$xd3,0x130-0x100(%rcx)

	jmp		.Loop_enter4x

.align	32
.Loop_outer4x:
	movdqa		0x40(%rsp),$xa0		# re-load smashed key
	movdqa		0x50(%rsp),$xa1
	movdqa		0x60(%rsp),$xa2
	movdqa		0x70(%rsp),$xa3
	movdqa		0x80-0x100(%rcx),$xb0
	movdqa		0x90-0x100(%rcx),$xb1
	movdqa		0xa0-0x100(%rcx),$xb2
	movdqa		0xb0-0x100(%rcx),$xb3
	movdqa		0xc0-0x100(%rcx),$xt0	# "$xc0"
	movdqa		0xd0-0x100(%rcx),$xt1	# "$xc1"
	movdqa		0xe0-0x100(%rcx),$xt2	# "$xc2"
	movdqa		0xf0-0x100(%rcx),$xt3	# "$xc3"
	movdqa		0x100-0x100(%rcx),$xd0
	movdqa		0x110-0x100(%rcx),$xd1
	movdqa		0x120-0x100(%rcx),$xd2
	movdqa		0x130-0x100(%rcx),$xd3
	paddd		.Lfour(%rip),$xd0	# next SIMD counters

.Loop_enter4x:
	movdqa		$xt2,0x20(%rsp)		# SIMD equivalent of "@x[10]"
	movdqa		$xt3,0x30(%rsp)		# SIMD equivalent of "@x[11]"
	movdqa		(%r10),$xt3		# .Lrot16(%rip)
	mov		\$10,%eax
	movdqa		$xd0,0x100-0x100(%rcx)	# save SIMD counters
	jmp		.Loop4x

.align	32
.Loop4x:
___
	foreach (&SSSE3_lane_ROUND(0, 4, 8,12)) { eval; }
	foreach (&SSSE3_lane_ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	dec		%eax
	jnz		.Loop4x

	paddd		0x40(%rsp),$xa0		# accumulate key material
	paddd		0x50(%rsp),$xa1
	paddd		0x60(%rsp),$xa2
	paddd		0x70(%rsp),$xa3

	movdqa		$xa0,$xt2		# "de-interlace" data
	punpckldq	$xa1,$xa0
	movdqa		$xa2,$xt3
	punpckldq	$xa3,$xa2
	punpckhdq	$xa1,$xt2
	punpckhdq	$xa3,$xt3
	movdqa		$xa0,$xa1
	punpcklqdq	$xa2,$xa0		# "a0"
	movdqa		$xt2,$xa3
	punpcklqdq	$xt3,$xt2		# "a2"
	punpckhqdq	$xa2,$xa1		# "a1"
	punpckhqdq	$xt3,$xa3		# "a3"
___
	($xa2,$xt2)=($xt2,$xa2);
$code.=<<___;
	paddd		0x80-0x100(%rcx),$xb0
	paddd		0x90-0x100(%rcx),$xb1
	paddd		0xa0-0x100(%rcx),$xb2
	paddd		0xb0-0x100(%rcx),$xb3

	movdqa		$xa0,0x00(%rsp)		# offload $xaN
	movdqa		$xa1,0x10(%rsp)
	movdqa		0x20(%rsp),$xa0		# "xc2"
	movdqa		0x30(%rsp),$xa1		# "xc3"

	movdqa		$xb0,$xt2
	punpckldq	$xb1,$xb0
	movdqa		$xb2,$xt3
	punpckldq	$xb3,$xb2
	punpckhdq	$xb1,$xt2
	punpckhdq	$xb3,$xt3
	movdqa		$xb0,$xb1
	punpcklqdq	$xb2,$xb0		# "b0"
	movdqa		$xt2,$xb3
	punpcklqdq	$xt3,$xt2		# "b2"
	punpckhqdq	$xb2,$xb1		# "b1"
	punpckhqdq	$xt3,$xb3		# "b3"
___
	($xb2,$xt2)=($xt2,$xb2);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	paddd		0xc0-0x100(%rcx),$xc0
	paddd		0xd0-0x100(%rcx),$xc1
	paddd		0xe0-0x100(%rcx),$xc2
	paddd		0xf0-0x100(%rcx),$xc3

	movdqa		$xa2,0x20(%rsp)		# keep offloading $xaN
	movdqa		$xa3,0x30(%rsp)

	movdqa		$xc0,$xt2
	punpckldq	$xc1,$xc0
	movdqa		$xc2,$xt3
	punpckldq	$xc3,$xc2
	punpckhdq	$xc1,$xt2
	punpckhdq	$xc3,$xt3
	movdqa		$xc0,$xc1
	punpcklqdq	$xc2,$xc0		# "c0"
	movdqa		$xt2,$xc3
	punpcklqdq	$xt3,$xt2		# "c2"
	punpckhqdq	$xc2,$xc1		# "c1"
	punpckhqdq	$xt3,$xc3		# "c3"
___
	($xc2,$xt2)=($xt2,$xc2);
	($xt0,$xt1)=($xa2,$xa3);		# use $xaN as temporary
$code.=<<___;
	paddd		0x100-0x100(%rcx),$xd0
	paddd		0x110-0x100(%rcx),$xd1
	paddd		0x120-0x100(%rcx),$xd2
	paddd		0x130-0x100(%rcx),$xd3

	movdqa		$xd0,$xt2
	punpckldq	$xd1,$xd0
	movdqa		$xd2,$xt3
	punpckldq	$xd3,$xd2
	punpckhdq	$xd1,$xt2
	punpckhdq	$xd3,$xt3
	movdqa		$xd0,$xd1
	punpcklqdq	$xd2,$xd0		# "d0"
	movdqa		$xt2,$xd3
	punpcklqdq	$xt3,$xt2		# "d2"
	punpckhqdq	$xd2,$xd1		# "d1"
	punpckhqdq	$xt3,$xd3		# "d3"
___
	($xd2,$xt2)=($xt2,$xd2);
$code.=<<___;
	cmp		\$64*4,$len
	jb		.Ltail4x

	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# $xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	lea		0x80($inp),$inp		# size optimization
	pxor		0x10(%rsp),$xt0
	pxor		$xb1,$xt1
	pxor		$xc1,$xt2
	pxor		$xd1,$xt3

	 movdqu		$xt0,0x40($out)
	movdqu		0x00($inp),$xt0
	 movdqu		$xt1,0x50($out)
	movdqu		0x10($inp),$xt1
	 movdqu		$xt2,0x60($out)
	movdqu		0x20($inp),$xt2
	 movdqu		$xt3,0x70($out)
	 lea		0x80($out),$out		# size optimization
	movdqu		0x30($inp),$xt3
	pxor		0x20(%rsp),$xt0
	pxor		$xb2,$xt1
	pxor		$xc2,$xt2
	pxor		$xd2,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	lea		0x80($inp),$inp		# inp+=64*4
	pxor		0x30(%rsp),$xt0
	pxor		$xb3,$xt1
	pxor		$xc3,$xt2
	pxor		$xd3,$xt3
	movdqu		$xt0,0x40($out)
	movdqu		$xt1,0x50($out)
	movdqu		$xt2,0x60($out)
	movdqu		$xt3,0x70($out)
	lea		0x80($out),$out		# out+=64*4

	sub		\$64*4,$len
	jnz		.Loop_outer4x

	jmp		.Ldone4x

.Ltail4x:
	cmp		\$192,$len
	jae		.L192_or_more4x
	cmp		\$128,$len
	jae		.L128_or_more4x
	cmp		\$64,$len
	jae		.L64_or_more4x

	#movdqa		0x00(%rsp),$xt0		# $xaN is offloaded, remember?
	xor		%r10,%r10
	#movdqa		$xt0,0x00(%rsp)
	movdqa		$xb0,0x10(%rsp)
	movdqa		$xc0,0x20(%rsp)
	movdqa		$xd0,0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L64_or_more4x:
	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# $xaxN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3
	movdqu		$xt0,0x00($out)
	movdqu		$xt1,0x10($out)
	movdqu		$xt2,0x20($out)
	movdqu		$xt3,0x30($out)
	je		.Ldone4x

	movdqa		0x10(%rsp),$xt0		# $xaN is offloaded, remember?
	lea		0x40($inp),$inp		# inp+=64*1
	xor		%r10,%r10
	movdqa		$xt0,0x00(%rsp)
	movdqa		$xb1,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*1
	movdqa		$xc1,0x20(%rsp)
	sub		\$64,$len		# len-=64*1
	movdqa		$xd1,0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L128_or_more4x:
	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# $xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	pxor		0x10(%rsp),$xt0
	pxor		$xb1,$xt1
	pxor		$xc1,$xt2
	pxor		$xd1,$xt3
	movdqu		$xt0,0x40($out)
	movdqu		$xt1,0x50($out)
	movdqu		$xt2,0x60($out)
	movdqu		$xt3,0x70($out)
	je		.Ldone4x

	movdqa		0x20(%rsp),$xt0		# $xaN is offloaded, remember?
	lea		0x80($inp),$inp		# inp+=64*2
	xor		%r10,%r10
	movdqa		$xt0,0x00(%rsp)
	movdqa		$xb2,0x10(%rsp)
	lea		0x80($out),$out		# out+=64*2
	movdqa		$xc2,0x20(%rsp)
	sub		\$128,$len		# len-=64*2
	movdqa		$xd2,0x30(%rsp)
	jmp		.Loop_tail4x

.align	32
.L192_or_more4x:
	movdqu		0x00($inp),$xt0		# xor with input
	movdqu		0x10($inp),$xt1
	movdqu		0x20($inp),$xt2
	movdqu		0x30($inp),$xt3
	pxor		0x00(%rsp),$xt0		# $xaN is offloaded, remember?
	pxor		$xb0,$xt1
	pxor		$xc0,$xt2
	pxor		$xd0,$xt3

	 movdqu		$xt0,0x00($out)
	movdqu		0x40($inp),$xt0
	 movdqu		$xt1,0x10($out)
	movdqu		0x50($inp),$xt1
	 movdqu		$xt2,0x20($out)
	movdqu		0x60($inp),$xt2
	 movdqu		$xt3,0x30($out)
	movdqu		0x70($inp),$xt3
	lea		0x80($inp),$inp		# size optimization
	pxor		0x10(%rsp),$xt0
	pxor		$xb1,$xt1
	pxor		$xc1,$xt2
	pxor		$xd1,$xt3

	 movdqu		$xt0,0x40($out)
	movdqu		0x00($inp),$xt0
	 movdqu		$xt1,0x50($out)
	movdqu		0x10($inp),$xt1
	 movdqu		$xt2,0x60($out)
	movdqu		0x20($inp),$xt2
	 movdqu		$xt3,0x70($out)
	 lea		0x80($out),$out		# size optimization
	movdqu		0x30($inp),$xt3
	pxor		0x20(%rsp),$xt0
	pxor		$xb2,$xt1
	pxor		$xc2,$xt2
	pxor		$xd2,$xt3
	movdqu		$xt0,0x00($out)
	movdqu		$xt1,0x10($out)
	movdqu		$xt2,0x20($out)
	movdqu		$xt3,0x30($out)
	je		.Ldone4x

	movdqa		0x30(%rsp),$xt0		# $xaN is offloaded, remember?
	lea		0x40($inp),$inp		# inp+=64*3
	xor		%r10,%r10
	movdqa		$xt0,0x00(%rsp)
	movdqa		$xb3,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*3
	movdqa		$xc3,0x20(%rsp)
	sub		\$192,$len		# len-=64*3
	movdqa		$xd3,0x30(%rsp)

.Loop_tail4x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail4x

.Ldone4x:
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L4x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_4x,.-ChaCha20_4x
___
}

########################################################################
# XOP code path that handles all lengths.
if ($avx) {
# There is some "anomaly" observed depending on instructions' size or
# alignment. If you look closely at below code you'll notice that
# sometimes argument order varies. The order affects instruction
# encoding by making it larger, and such fiddling gives 5% performance
# improvement. This is on FX-4100...

my ($xb0,$xb1,$xb2,$xb3, $xd0,$xd1,$xd2,$xd3,
    $xa0,$xa1,$xa2,$xa3, $xt0,$xt1,$xt2,$xt3)=map("%xmm$_",(0..15));
my  @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	 $xt0,$xt1,$xt2,$xt3, $xd0,$xd1,$xd2,$xd3);

sub XOP_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my @x=map("\"$_\"",@xx);

	(
	"&vpaddd	(@x[$a0],@x[$a0],@x[$b0])",	# Q1
	 "&vpaddd	(@x[$a1],@x[$a1],@x[$b1])",	# Q2
	  "&vpaddd	(@x[$a2],@x[$a2],@x[$b2])",	# Q3
	   "&vpaddd	(@x[$a3],@x[$a3],@x[$b3])",	# Q4
	"&vpxor		(@x[$d0],@x[$a0],@x[$d0])",
	 "&vpxor	(@x[$d1],@x[$a1],@x[$d1])",
	  "&vpxor	(@x[$d2],@x[$a2],@x[$d2])",
	   "&vpxor	(@x[$d3],@x[$a3],@x[$d3])",
	"&vprotd	(@x[$d0],@x[$d0],16)",
	 "&vprotd	(@x[$d1],@x[$d1],16)",
	  "&vprotd	(@x[$d2],@x[$d2],16)",
	   "&vprotd	(@x[$d3],@x[$d3],16)",

	"&vpaddd	(@x[$c0],@x[$c0],@x[$d0])",
	 "&vpaddd	(@x[$c1],@x[$c1],@x[$d1])",
	  "&vpaddd	(@x[$c2],@x[$c2],@x[$d2])",
	   "&vpaddd	(@x[$c3],@x[$c3],@x[$d3])",
	"&vpxor		(@x[$b0],@x[$c0],@x[$b0])",
	 "&vpxor	(@x[$b1],@x[$c1],@x[$b1])",
	  "&vpxor	(@x[$b2],@x[$b2],@x[$c2])",	# flip
	   "&vpxor	(@x[$b3],@x[$b3],@x[$c3])",	# flip
	"&vprotd	(@x[$b0],@x[$b0],12)",
	 "&vprotd	(@x[$b1],@x[$b1],12)",
	  "&vprotd	(@x[$b2],@x[$b2],12)",
	   "&vprotd	(@x[$b3],@x[$b3],12)",

	"&vpaddd	(@x[$a0],@x[$b0],@x[$a0])",	# flip
	 "&vpaddd	(@x[$a1],@x[$b1],@x[$a1])",	# flip
	  "&vpaddd	(@x[$a2],@x[$a2],@x[$b2])",
	   "&vpaddd	(@x[$a3],@x[$a3],@x[$b3])",
	"&vpxor		(@x[$d0],@x[$a0],@x[$d0])",
	 "&vpxor	(@x[$d1],@x[$a1],@x[$d1])",
	  "&vpxor	(@x[$d2],@x[$a2],@x[$d2])",
	   "&vpxor	(@x[$d3],@x[$a3],@x[$d3])",
	"&vprotd	(@x[$d0],@x[$d0],8)",
	 "&vprotd	(@x[$d1],@x[$d1],8)",
	  "&vprotd	(@x[$d2],@x[$d2],8)",
	   "&vprotd	(@x[$d3],@x[$d3],8)",

	"&vpaddd	(@x[$c0],@x[$c0],@x[$d0])",
	 "&vpaddd	(@x[$c1],@x[$c1],@x[$d1])",
	  "&vpaddd	(@x[$c2],@x[$c2],@x[$d2])",
	   "&vpaddd	(@x[$c3],@x[$c3],@x[$d3])",
	"&vpxor		(@x[$b0],@x[$c0],@x[$b0])",
	 "&vpxor	(@x[$b1],@x[$c1],@x[$b1])",
	  "&vpxor	(@x[$b2],@x[$b2],@x[$c2])",	# flip
	   "&vpxor	(@x[$b3],@x[$b3],@x[$c3])",	# flip
	"&vprotd	(@x[$b0],@x[$b0],7)",
	 "&vprotd	(@x[$b1],@x[$b1],7)",
	  "&vprotd	(@x[$b2],@x[$b2],7)",
	   "&vprotd	(@x[$b3],@x[$b3],7)"
	);
}

my $xframe = $win64 ? 0xa8 : 8;

$code.=<<___;
.type	ChaCha20_4xop,\@function,5
.align	32
ChaCha20_4xop:
.cfi_startproc
.LChaCha20_4xop:
	mov		%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	sub		\$0x140+$xframe,%rsp
___
	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x40		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x100	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x140
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
.L4xop_body:
___
$code.=<<___;
	vzeroupper

	vmovdqa		.Lsigma(%rip),$xa3	# key[0]
	vmovdqu		($key),$xb3		# key[1]
	vmovdqu		16($key),$xt3		# key[2]
	vmovdqu		($counter),$xd3		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vmovdqa		$xa0,0x40(%rsp)		# ... and offload
	vpshufd		\$0xaa,$xa3,$xa2
	vmovdqa		$xa1,0x50(%rsp)
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa		$xa2,0x60(%rsp)
	vmovdqa		$xa3,0x70(%rsp)

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vmovdqa		$xb0,0x80-0x100(%rcx)
	vpshufd		\$0xaa,$xb3,$xb2
	vmovdqa		$xb1,0x90-0x100(%rcx)
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa		$xb2,0xa0-0x100(%rcx)
	vmovdqa		$xb3,0xb0-0x100(%rcx)

	vpshufd		\$0x00,$xt3,$xt0	# "$xc0"
	vpshufd		\$0x55,$xt3,$xt1	# "$xc1"
	vmovdqa		$xt0,0xc0-0x100(%rcx)
	vpshufd		\$0xaa,$xt3,$xt2	# "$xc2"
	vmovdqa		$xt1,0xd0-0x100(%rcx)
	vpshufd		\$0xff,$xt3,$xt3	# "$xc3"
	vmovdqa		$xt2,0xe0-0x100(%rcx)
	vmovdqa		$xt3,0xf0-0x100(%rcx)

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpaddd		.Linc(%rip),$xd0,$xd0	# don't save counters yet
	vpshufd		\$0xaa,$xd3,$xd2
	vmovdqa		$xd1,0x110-0x100(%rcx)
	vpshufd		\$0xff,$xd3,$xd3
	vmovdqa		$xd2,0x120-0x100(%rcx)
	vmovdqa		$xd3,0x130-0x100(%rcx)

	jmp		.Loop_enter4xop

.align	32
.Loop_outer4xop:
	vmovdqa		0x40(%rsp),$xa0		# re-load smashed key
	vmovdqa		0x50(%rsp),$xa1
	vmovdqa		0x60(%rsp),$xa2
	vmovdqa		0x70(%rsp),$xa3
	vmovdqa		0x80-0x100(%rcx),$xb0
	vmovdqa		0x90-0x100(%rcx),$xb1
	vmovdqa		0xa0-0x100(%rcx),$xb2
	vmovdqa		0xb0-0x100(%rcx),$xb3
	vmovdqa		0xc0-0x100(%rcx),$xt0	# "$xc0"
	vmovdqa		0xd0-0x100(%rcx),$xt1	# "$xc1"
	vmovdqa		0xe0-0x100(%rcx),$xt2	# "$xc2"
	vmovdqa		0xf0-0x100(%rcx),$xt3	# "$xc3"
	vmovdqa		0x100-0x100(%rcx),$xd0
	vmovdqa		0x110-0x100(%rcx),$xd1
	vmovdqa		0x120-0x100(%rcx),$xd2
	vmovdqa		0x130-0x100(%rcx),$xd3
	vpaddd		.Lfour(%rip),$xd0,$xd0	# next SIMD counters

.Loop_enter4xop:
	mov		\$10,%eax
	vmovdqa		$xd0,0x100-0x100(%rcx)	# save SIMD counters
	jmp		.Loop4xop

.align	32
.Loop4xop:
___
	foreach (&XOP_lane_ROUND(0, 4, 8,12)) { eval; }
	foreach (&XOP_lane_ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	dec		%eax
	jnz		.Loop4xop

	vpaddd		0x40(%rsp),$xa0,$xa0	# accumulate key material
	vpaddd		0x50(%rsp),$xa1,$xa1
	vpaddd		0x60(%rsp),$xa2,$xa2
	vpaddd		0x70(%rsp),$xa3,$xa3

	vmovdqa		$xt2,0x20(%rsp)		# offload $xc2,3
	vmovdqa		$xt3,0x30(%rsp)

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
        ($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		0x80-0x100(%rcx),$xb0,$xb0
	vpaddd		0x90-0x100(%rcx),$xb1,$xb1
	vpaddd		0xa0-0x100(%rcx),$xb2,$xb2
	vpaddd		0xb0-0x100(%rcx),$xb3,$xb3

	vmovdqa		$xa0,0x00(%rsp)		# offload $xa0,1
	vmovdqa		$xa1,0x10(%rsp)
	vmovdqa		0x20(%rsp),$xa0		# "xc2"
	vmovdqa		0x30(%rsp),$xa1		# "xc3"

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	vpaddd		0xc0-0x100(%rcx),$xc0,$xc0
	vpaddd		0xd0-0x100(%rcx),$xc1,$xc1
	vpaddd		0xe0-0x100(%rcx),$xc2,$xc2
	vpaddd		0xf0-0x100(%rcx),$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		0x100-0x100(%rcx),$xd0,$xd0
	vpaddd		0x110-0x100(%rcx),$xd1,$xd1
	vpaddd		0x120-0x100(%rcx),$xd2,$xd2
	vpaddd		0x130-0x100(%rcx),$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
	($xa0,$xa1)=($xt2,$xt3);
$code.=<<___;
	vmovdqa		0x00(%rsp),$xa0		# restore $xa0,1
	vmovdqa		0x10(%rsp),$xa1

	cmp		\$64*4,$len
	jb		.Ltail4xop

	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vpxor		0x40($inp),$xa1,$xa1
	vpxor		0x50($inp),$xb1,$xb1
	vpxor		0x60($inp),$xc1,$xc1
	vpxor		0x70($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x10($inp),$xb2,$xb2
	vpxor		0x20($inp),$xc2,$xc2
	vpxor		0x30($inp),$xd2,$xd2
	vpxor		0x40($inp),$xa3,$xa3
	vpxor		0x50($inp),$xb3,$xb3
	vpxor		0x60($inp),$xc3,$xc3
	vpxor		0x70($inp),$xd3,$xd3
	lea		0x80($inp),$inp		# inp+=64*4

	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	vmovdqu		$xa1,0x40($out)
	vmovdqu		$xb1,0x50($out)
	vmovdqu		$xc1,0x60($out)
	vmovdqu		$xd1,0x70($out)
	lea		0x80($out),$out		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x10($out)
	vmovdqu		$xc2,0x20($out)
	vmovdqu		$xd2,0x30($out)
	vmovdqu		$xa3,0x40($out)
	vmovdqu		$xb3,0x50($out)
	vmovdqu		$xc3,0x60($out)
	vmovdqu		$xd3,0x70($out)
	lea		0x80($out),$out		# out+=64*4

	sub		\$64*4,$len
	jnz		.Loop_outer4xop

	jmp		.Ldone4xop

.align	32
.Ltail4xop:
	cmp		\$192,$len
	jae		.L192_or_more4xop
	cmp		\$128,$len
	jae		.L128_or_more4xop
	cmp		\$64,$len
	jae		.L64_or_more4xop

	xor		%r10,%r10
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xb0,0x10(%rsp)
	vmovdqa		$xc0,0x20(%rsp)
	vmovdqa		$xd0,0x30(%rsp)
	jmp		.Loop_tail4xop

.align	32
.L64_or_more4xop:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	je		.Ldone4xop

	lea		0x40($inp),$inp		# inp+=64*1
	vmovdqa		$xa1,0x00(%rsp)
	xor		%r10,%r10
	vmovdqa		$xb1,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*1
	vmovdqa		$xc1,0x20(%rsp)
	sub		\$64,$len		# len-=64*1
	vmovdqa		$xd1,0x30(%rsp)
	jmp		.Loop_tail4xop

.align	32
.L128_or_more4xop:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vpxor		0x40($inp),$xa1,$xa1
	vpxor		0x50($inp),$xb1,$xb1
	vpxor		0x60($inp),$xc1,$xc1
	vpxor		0x70($inp),$xd1,$xd1

	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	vmovdqu		$xa1,0x40($out)
	vmovdqu		$xb1,0x50($out)
	vmovdqu		$xc1,0x60($out)
	vmovdqu		$xd1,0x70($out)
	je		.Ldone4xop

	lea		0x80($inp),$inp		# inp+=64*2
	vmovdqa		$xa2,0x00(%rsp)
	xor		%r10,%r10
	vmovdqa		$xb2,0x10(%rsp)
	lea		0x80($out),$out		# out+=64*2
	vmovdqa		$xc2,0x20(%rsp)
	sub		\$128,$len		# len-=64*2
	vmovdqa		$xd2,0x30(%rsp)
	jmp		.Loop_tail4xop

.align	32
.L192_or_more4xop:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x10($inp),$xb0,$xb0
	vpxor		0x20($inp),$xc0,$xc0
	vpxor		0x30($inp),$xd0,$xd0
	vpxor		0x40($inp),$xa1,$xa1
	vpxor		0x50($inp),$xb1,$xb1
	vpxor		0x60($inp),$xc1,$xc1
	vpxor		0x70($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x10($inp),$xb2,$xb2
	vpxor		0x20($inp),$xc2,$xc2
	vpxor		0x30($inp),$xd2,$xd2

	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x10($out)
	vmovdqu		$xc0,0x20($out)
	vmovdqu		$xd0,0x30($out)
	vmovdqu		$xa1,0x40($out)
	vmovdqu		$xb1,0x50($out)
	vmovdqu		$xc1,0x60($out)
	vmovdqu		$xd1,0x70($out)
	lea		0x80($out),$out		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x10($out)
	vmovdqu		$xc2,0x20($out)
	vmovdqu		$xd2,0x30($out)
	je		.Ldone4xop

	lea		0x40($inp),$inp		# inp+=64*3
	vmovdqa		$xa3,0x00(%rsp)
	xor		%r10,%r10
	vmovdqa		$xb3,0x10(%rsp)
	lea		0x40($out),$out		# out+=64*3
	vmovdqa		$xc3,0x20(%rsp)
	sub		\$192,$len		# len-=64*3
	vmovdqa		$xd3,0x30(%rsp)

.Loop_tail4xop:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail4xop

.Ldone4xop:
	vzeroupper
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L4xop_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_4xop,.-ChaCha20_4xop
___
}

########################################################################
# AVX2 code path
if ($avx>1) {

my ($mp,$d0l,$d0h,$d1l,$d1h,$t0,$t1)=("%r11","%rax","%rcx","%r8","%r10","%rsi","%rdi");
my ($kr0,$kr1,$ks1)=("96(%rsp)","104(%rsp)","112(%rsp)");
my $bhalf=512;

our $hyb = 0;
our $hybmode = $ENV{HYB_MODE} || "int";
our $hybchunk = $ENV{HYB_CHUNK} || 4;

my @sx=("%eax","%ebx","%ecx","%edx","%r8d","%r10d","%r11d","%ebp","%nox","%nox","%nox","%nox","%r12d","%r13d","%r14d","%r15d");
my @st=("%esi","%edi");

sub SCALAR_ROUND {		# extra block in scalar GPRs, mirrors ROUND()
my ($wbase,$a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_)=map("\"$_\"",@st);
my @x=map("\"$_\"",@sx);
my ($m0,$m1,$m2,$m3)=map(sprintf("%d(%%rsp)",$wbase+4*$_),($c0,$c1,$c2,$c3));

	(
	"&add	(@x[$a0],@x[$b0])",	# Q1
	"&xor	(@x[$d0],@x[$a0])",
	"&rol	(@x[$d0],16)",
	 "&add	(@x[$a1],@x[$b1])",	# Q2
	 "&xor	(@x[$d1],@x[$a1])",
	 "&rol	(@x[$d1],16)",

	"&add	($xc,@x[$d0])",
	"&xor	(@x[$b0],$xc)",
	"&rol	(@x[$b0],12)",
	 "&add	($xc_,@x[$d1])",
	 "&xor	(@x[$b1],$xc_)",
	 "&rol	(@x[$b1],12)",

	"&add	(@x[$a0],@x[$b0])",
	"&xor	(@x[$d0],@x[$a0])",
	"&rol	(@x[$d0],8)",
	 "&add	(@x[$a1],@x[$b1])",
	 "&xor	(@x[$d1],@x[$a1])",
	 "&rol	(@x[$d1],8)",

	"&add	($xc,@x[$d0])",
	"&xor	(@x[$b0],$xc)",
	"&rol	(@x[$b0],7)",
	 "&add	($xc_,@x[$d1])",
	 "&xor	(@x[$b1],$xc_)",
	 "&rol	(@x[$b1],7)",

	"&mov	(\"$m0\",$xc)",		# rotate the pair of 'c's
	 "&mov	(\"$m1\",$xc_)",
	"&mov	($xc,\"$m2\")",
	 "&mov	($xc_,\"$m3\")",

	"&add	(@x[$a2],@x[$b2])",	# Q3
	"&xor	(@x[$d2],@x[$a2])",
	"&rol	(@x[$d2],16)",
	 "&add	(@x[$a3],@x[$b3])",	# Q4
	 "&xor	(@x[$d3],@x[$a3])",
	 "&rol	(@x[$d3],16)",

	"&add	($xc,@x[$d2])",
	"&xor	(@x[$b2],$xc)",
	"&rol	(@x[$b2],12)",
	 "&add	($xc_,@x[$d3])",
	 "&xor	(@x[$b3],$xc_)",
	 "&rol	(@x[$b3],12)",

	"&add	(@x[$a2],@x[$b2])",
	"&xor	(@x[$d2],@x[$a2])",
	"&rol	(@x[$d2],8)",
	 "&add	(@x[$a3],@x[$b3])",
	 "&xor	(@x[$d3],@x[$a3])",
	 "&rol	(@x[$d3],8)",

	"&add	($xc,@x[$d2])",
	"&xor	(@x[$b2],$xc)",
	"&rol	(@x[$b2],7)",
	 "&add	($xc_,@x[$d3])",
	 "&xor	(@x[$b3],$xc_)",
	 "&rol	(@x[$b3],7)"
	);
}


sub SCALAR_ROUND_M {		# memory-backed extra block, one temp register
my ($wbase,$t,$a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my @m=map(sprintf("%d(%%rsp)",$wbase+4*$_),(0..15));
my @o;
foreach my $q ([$a0,$b0,$c0,$d0],[$a1,$b1,$c1,$d1],
	       [$a2,$b2,$c2,$d2],[$a3,$b3,$c3,$d3]) {
  my ($a,$b,$c,$d)=@$q;
  foreach my $r ([16,12],[8,7]) {
    my ($r1,$r2)=@$r;
    push @o, "&mov (\"$t\",\"$m[$b]\")",  "&add (\"$m[$a]\",\"$t\")";
    push @o, "&mov (\"$t\",\"$m[$a]\")",  "&xor (\"$m[$d]\",\"$t\")";
    push @o, "&roll(\"$m[$d]\",$r1)";
    push @o, "&mov (\"$t\",\"$m[$d]\")",  "&add (\"$m[$c]\",\"$t\")";
    push @o, "&mov (\"$t\",\"$m[$c]\")",  "&xor (\"$m[$b]\",\"$t\")";
    push @o, "&roll(\"$m[$b]\",$r2)";
  }
}
return @o;
}


sub SCALAR_ROUND_QR {		# QR-blocked: load 4 words, 12 register ops, store 4
my ($wbase,$ra,$rb,$rc,$rd,$a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my @m=map(sprintf("%d(%%rsp)",$wbase+4*$_),(0..15));
my @o;
foreach my $q ([$a0,$b0,$c0,$d0],[$a1,$b1,$c1,$d1],
	       [$a2,$b2,$c2,$d2],[$a3,$b3,$c3,$d3]) {
  my ($a,$b,$c,$d)=@$q;
  push @o, "&mov (\"$ra\",\"$m[$a]\")", "&mov (\"$rb\",\"$m[$b]\")",
	   "&mov (\"$rc\",\"$m[$c]\")", "&mov (\"$rd\",\"$m[$d]\")";
  push @o, "&add (\"$ra\",\"$rb\")", "&xor (\"$rd\",\"$ra\")", "&rol (\"$rd\",16)";
  push @o, "&add (\"$rc\",\"$rd\")", "&xor (\"$rb\",\"$rc\")", "&rol (\"$rb\",12)";
  push @o, "&add (\"$ra\",\"$rb\")", "&xor (\"$rd\",\"$ra\")", "&rol (\"$rd\",8)";
  push @o, "&add (\"$rc\",\"$rd\")", "&xor (\"$rb\",\"$rc\")", "&rol (\"$rb\",7)";
  push @o, "&mov (\"$m[$a]\",\"$ra\")", "&mov (\"$m[$b]\",\"$rb\")",
	   "&mov (\"$m[$c]\",\"$rc\")", "&mov (\"$m[$d]\",\"$rd\")";
}
return @o;
}

sub MERGE2 {			# blend two scalar streams proportionally
my ($p,$q)=@_;
my @p=@$p; my @q=@$q; my @o; my $j=0; my $n=scalar(@q);
for my $i (0..$#p) {
	push @o,$p[$i];
	my $want=int(($i+1)*$n/scalar(@p));
	while ($j<$want) { push @o,$q[$j++]; }
}
while ($j<$n) { push @o,$q[$j++]; }
return @o;
}

sub HYBRID_WEAVE {		# distribute @$s evenly through @$v
my ($v,$s,$chunk)=@_;
my @v=@$v; my @s=@$s;
my $n=scalar(@v); my $m=scalar(@s);
my @o; my $si=0;
for my $i (0..$#v) {
	push @o,$v[$i];
	my $want=int(($i+1)*$m/$n);
	# only flush once $chunk instructions are pending (or at the very end)
	if ($want-$si >= $chunk || ($i==$#v)) {
		while ($si < $want) { push @o,$s[$si++]; }
	}
}
while ($si < $m) { push @o,$s[$si++]; }
return @o;
}
my ($xb0,$xb1,$xb2,$xb3, $xd0,$xd1,$xd2,$xd3,
    $xa0,$xa1,$xa2,$xa3, $xt0,$xt1,$xt2,$xt3)=map("%ymm$_",(0..15));
my @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	"%nox","%nox","%nox","%nox", $xd0,$xd1,$xd2,$xd3);

sub AVX2_lane_ROUND {
my $rot16 = $hyb ? ".Lrot16(%rip)" : "(%r10)";
my $rot24 = $hyb ? ".Lrot24(%rip)" : "(%r11)";
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my ($xc,$xc_,$t0,$t1)=map("\"$_\"",$xt0,$xt1,$xt2,$xt3);
my @x=map("\"$_\"",@xx);

	# Consider order in which variables are addressed by their
	# index:
	#
	#	a   b   c   d
	#
	#	0   4   8  12 < even round
	#	1   5   9  13
	#	2   6  10  14
	#	3   7  11  15
	#	0   5  10  15 < odd round
	#	1   6  11  12
	#	2   7   8  13
	#	3   4   9  14
	#
	# 'a', 'b' and 'd's are permanently allocated in registers,
	# @x[0..7,12..15], while 'c's are maintained in memory. If
	# you observe 'c' column, you'll notice that pair of 'c's is
	# invariant between rounds. This means that we have to reload
	# them once per round, in the middle. This is why you'll see
	# bunch of 'c' stores and loads in the middle, but none in
	# the beginning or end.

	(
	"&vpaddd	(@x[$a0],@x[$a0],@x[$b0])",	# Q1
	"&vpxor		(@x[$d0],@x[$a0],@x[$d0])",
	"&vpshufb	(@x[$d0],@x[$d0],$t1)",
	 "&vpaddd	(@x[$a1],@x[$a1],@x[$b1])",	# Q2
	 "&vpxor	(@x[$d1],@x[$a1],@x[$d1])",
	 "&vpshufb	(@x[$d1],@x[$d1],$t1)",

	"&vpaddd	($xc,$xc,@x[$d0])",
	"&vpxor		(@x[$b0],$xc,@x[$b0])",
	"&vpslld	($t0,@x[$b0],12)",
	"&vpsrld	(@x[$b0],@x[$b0],20)",
	"&vpor		(@x[$b0],$t0,@x[$b0])",
	"&vbroadcasti128($t0,'$rot24')",		# .Lrot24(%rip)
	 "&vpaddd	($xc_,$xc_,@x[$d1])",
	 "&vpxor	(@x[$b1],$xc_,@x[$b1])",
	 "&vpslld	($t1,@x[$b1],12)",
	 "&vpsrld	(@x[$b1],@x[$b1],20)",
	 "&vpor		(@x[$b1],$t1,@x[$b1])",

	"&vpaddd	(@x[$a0],@x[$a0],@x[$b0])",
	"&vpxor		(@x[$d0],@x[$a0],@x[$d0])",
	"&vpshufb	(@x[$d0],@x[$d0],$t0)",
	 "&vpaddd	(@x[$a1],@x[$a1],@x[$b1])",
	 "&vpxor	(@x[$d1],@x[$a1],@x[$d1])",
	 "&vpshufb	(@x[$d1],@x[$d1],$t0)",

	"&vpaddd	($xc,$xc,@x[$d0])",
	"&vpxor		(@x[$b0],$xc,@x[$b0])",
	"&vpslld	($t1,@x[$b0],7)",
	"&vpsrld	(@x[$b0],@x[$b0],25)",
	"&vpor		(@x[$b0],$t1,@x[$b0])",
	"&vbroadcasti128($t1,'$rot16')",		# .Lrot16(%rip)
	 "&vpaddd	($xc_,$xc_,@x[$d1])",
	 "&vpxor	(@x[$b1],$xc_,@x[$b1])",
	 "&vpslld	($t0,@x[$b1],7)",
	 "&vpsrld	(@x[$b1],@x[$b1],25)",
	 "&vpor		(@x[$b1],$t0,@x[$b1])",

	"&vmovdqa	(\"`32*($c0-8)`(%rsp)\",$xc)",	# reload pair of 'c's
	 "&vmovdqa	(\"`32*($c1-8)`(%rsp)\",$xc_)",
	"&vmovdqa	($xc,\"`32*($c2-8)`(%rsp)\")",
	 "&vmovdqa	($xc_,\"`32*($c3-8)`(%rsp)\")",

	"&vpaddd	(@x[$a2],@x[$a2],@x[$b2])",	# Q3
	"&vpxor		(@x[$d2],@x[$a2],@x[$d2])",
	"&vpshufb	(@x[$d2],@x[$d2],$t1)",
	 "&vpaddd	(@x[$a3],@x[$a3],@x[$b3])",	# Q4
	 "&vpxor	(@x[$d3],@x[$a3],@x[$d3])",
	 "&vpshufb	(@x[$d3],@x[$d3],$t1)",

	"&vpaddd	($xc,$xc,@x[$d2])",
	"&vpxor		(@x[$b2],$xc,@x[$b2])",
	"&vpslld	($t0,@x[$b2],12)",
	"&vpsrld	(@x[$b2],@x[$b2],20)",
	"&vpor		(@x[$b2],$t0,@x[$b2])",
	"&vbroadcasti128($t0,'$rot24')",		# .Lrot24(%rip)
	 "&vpaddd	($xc_,$xc_,@x[$d3])",
	 "&vpxor	(@x[$b3],$xc_,@x[$b3])",
	 "&vpslld	($t1,@x[$b3],12)",
	 "&vpsrld	(@x[$b3],@x[$b3],20)",
	 "&vpor		(@x[$b3],$t1,@x[$b3])",

	"&vpaddd	(@x[$a2],@x[$a2],@x[$b2])",
	"&vpxor		(@x[$d2],@x[$a2],@x[$d2])",
	"&vpshufb	(@x[$d2],@x[$d2],$t0)",
	 "&vpaddd	(@x[$a3],@x[$a3],@x[$b3])",
	 "&vpxor	(@x[$d3],@x[$a3],@x[$d3])",
	 "&vpshufb	(@x[$d3],@x[$d3],$t0)",

	"&vpaddd	($xc,$xc,@x[$d2])",
	"&vpxor		(@x[$b2],$xc,@x[$b2])",
	"&vpslld	($t1,@x[$b2],7)",
	"&vpsrld	(@x[$b2],@x[$b2],25)",
	"&vpor		(@x[$b2],$t1,@x[$b2])",
	"&vbroadcasti128($t1,'$rot16')",		# .Lrot16(%rip)
	 "&vpaddd	($xc_,$xc_,@x[$d3])",
	 "&vpxor	(@x[$b3],$xc_,@x[$b3])",
	 "&vpslld	($t0,@x[$b3],7)",
	 "&vpsrld	(@x[$b3],@x[$b3],25)",
	 "&vpor		(@x[$b3],$t0,@x[$b3])"
	);
}

my $xframe = $win64 ? 0xa8 : 8;

$code.=<<___;
.type	ChaCha20_8x,\@function,5
.align	32
ChaCha20_8x:
.cfi_startproc
.LChaCha20_8x:
	mov		%rsp,%r9		# frame register
.cfi_def_cfa_register	%r9
	sub		\$0x280+$xframe,%rsp
	and		\$-32,%rsp
___
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
.L8x_body:
___
$code.=<<___;
	vzeroupper

	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x80		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x200	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x280

	vbroadcasti128	.Lsigma(%rip),$xa3	# key[0]
	vbroadcasti128	($key),$xb3		# key[1]
	vbroadcasti128	16($key),$xt3		# key[2]
	vbroadcasti128	($counter),$xd3		# key[3]
	lea		0x100(%rsp),%rcx	# size optimization
	lea		0x200(%rsp),%rax	# size optimization
	lea		.Lrot16(%rip),%r10
	lea		.Lrot24(%rip),%r11

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vmovdqa		$xa0,0x80-0x100(%rcx)	# ... and offload
	vpshufd		\$0xaa,$xa3,$xa2
	vmovdqa		$xa1,0xa0-0x100(%rcx)
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa		$xa2,0xc0-0x100(%rcx)
	vmovdqa		$xa3,0xe0-0x100(%rcx)

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vmovdqa		$xb0,0x100-0x100(%rcx)
	vpshufd		\$0xaa,$xb3,$xb2
	vmovdqa		$xb1,0x120-0x100(%rcx)
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa		$xb2,0x140-0x100(%rcx)
	vmovdqa		$xb3,0x160-0x100(%rcx)

	vpshufd		\$0x00,$xt3,$xt0	# "xc0"
	vpshufd		\$0x55,$xt3,$xt1	# "xc1"
	vmovdqa		$xt0,0x180-0x200(%rax)
	vpshufd		\$0xaa,$xt3,$xt2	# "xc2"
	vmovdqa		$xt1,0x1a0-0x200(%rax)
	vpshufd		\$0xff,$xt3,$xt3	# "xc3"
	vmovdqa		$xt2,0x1c0-0x200(%rax)
	vmovdqa		$xt3,0x1e0-0x200(%rax)

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpaddd		.Lincy(%rip),$xd0,$xd0	# don't save counters yet
	vpshufd		\$0xaa,$xd3,$xd2
	vmovdqa		$xd1,0x220-0x200(%rax)
	vpshufd		\$0xff,$xd3,$xd3
	vmovdqa		$xd2,0x240-0x200(%rax)
	vmovdqa		$xd3,0x260-0x200(%rax)

	jmp		.Loop_enter8x

.align	32
.Loop_outer8x:
	vmovdqa		0x80-0x100(%rcx),$xa0	# re-load smashed key
	vmovdqa		0xa0-0x100(%rcx),$xa1
	vmovdqa		0xc0-0x100(%rcx),$xa2
	vmovdqa		0xe0-0x100(%rcx),$xa3
	vmovdqa		0x100-0x100(%rcx),$xb0
	vmovdqa		0x120-0x100(%rcx),$xb1
	vmovdqa		0x140-0x100(%rcx),$xb2
	vmovdqa		0x160-0x100(%rcx),$xb3
	vmovdqa		0x180-0x200(%rax),$xt0	# "xc0"
	vmovdqa		0x1a0-0x200(%rax),$xt1	# "xc1"
	vmovdqa		0x1c0-0x200(%rax),$xt2	# "xc2"
	vmovdqa		0x1e0-0x200(%rax),$xt3	# "xc3"
	vmovdqa		0x200-0x200(%rax),$xd0
	vmovdqa		0x220-0x200(%rax),$xd1
	vmovdqa		0x240-0x200(%rax),$xd2
	vmovdqa		0x260-0x200(%rax),$xd3
	vpaddd		.Leight(%rip),$xd0,$xd0	# next SIMD counters

.Loop_enter8x:
	vmovdqa		$xt2,0x40(%rsp)		# SIMD equivalent of "@x[10]"
	vmovdqa		$xt3,0x60(%rsp)		# SIMD equivalent of "@x[11]"
	vbroadcasti128	(%r10),$xt3
	vmovdqa		$xd0,0x200-0x200(%rax)	# save SIMD counters
	mov		\$10,%eax
	jmp		.Loop8x

.align	32
.Loop8x:
___
	foreach (&AVX2_lane_ROUND(0, 4, 8,12)) { eval; }
	foreach (&AVX2_lane_ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	dec		%eax
	jnz		.Loop8x

	lea		0x200(%rsp),%rax	# size optimization
	vpaddd		0x80-0x100(%rcx),$xa0,$xa0	# accumulate key
	vpaddd		0xa0-0x100(%rcx),$xa1,$xa1
	vpaddd		0xc0-0x100(%rcx),$xa2,$xa2
	vpaddd		0xe0-0x100(%rcx),$xa3,$xa3

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
	($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		0x100-0x100(%rcx),$xb0,$xb0
	vpaddd		0x120-0x100(%rcx),$xb1,$xb1
	vpaddd		0x140-0x100(%rcx),$xb2,$xb2
	vpaddd		0x160-0x100(%rcx),$xb3,$xb3

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
$code.=<<___;
	vperm2i128	\$0x20,$xb0,$xa0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xb0,$xa0,$xb0
	vperm2i128	\$0x20,$xb1,$xa1,$xa0
	vperm2i128	\$0x31,$xb1,$xa1,$xb1
	vperm2i128	\$0x20,$xb2,$xa2,$xa1
	vperm2i128	\$0x31,$xb2,$xa2,$xb2
	vperm2i128	\$0x20,$xb3,$xa3,$xa2
	vperm2i128	\$0x31,$xb3,$xa3,$xb3
___
	($xa0,$xa1,$xa2,$xa3,$xt3)=($xt3,$xa0,$xa1,$xa2,$xa3);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	vmovdqa		$xa0,0x00(%rsp)		# offload $xaN
	vmovdqa		$xa1,0x20(%rsp)
	vmovdqa		0x40(%rsp),$xc2		# $xa0
	vmovdqa		0x60(%rsp),$xc3		# $xa1

	vpaddd		0x180-0x200(%rax),$xc0,$xc0
	vpaddd		0x1a0-0x200(%rax),$xc1,$xc1
	vpaddd		0x1c0-0x200(%rax),$xc2,$xc2
	vpaddd		0x1e0-0x200(%rax),$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		0x200-0x200(%rax),$xd0,$xd0
	vpaddd		0x220-0x200(%rax),$xd1,$xd1
	vpaddd		0x240-0x200(%rax),$xd2,$xd2
	vpaddd		0x260-0x200(%rax),$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
$code.=<<___;
	vperm2i128	\$0x20,$xd0,$xc0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xd0,$xc0,$xd0
	vperm2i128	\$0x20,$xd1,$xc1,$xc0
	vperm2i128	\$0x31,$xd1,$xc1,$xd1
	vperm2i128	\$0x20,$xd2,$xc2,$xc1
	vperm2i128	\$0x31,$xd2,$xc2,$xd2
	vperm2i128	\$0x20,$xd3,$xc3,$xc2
	vperm2i128	\$0x31,$xd3,$xc3,$xd3
___
	($xc0,$xc1,$xc2,$xc3,$xt3)=($xt3,$xc0,$xc1,$xc2,$xc3);
	($xb0,$xb1,$xb2,$xb3,$xc0,$xc1,$xc2,$xc3)=
	($xc0,$xc1,$xc2,$xc3,$xb0,$xb1,$xb2,$xb3);
	($xa0,$xa1)=($xt2,$xt3);
$code.=<<___;
	vmovdqa		0x00(%rsp),$xa0		# $xaN was offloaded, remember?
	vmovdqa		0x20(%rsp),$xa1

	cmp		\$64*8,$len
	jb		.Ltail8x

	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa1,$xa1
	vpxor		0x20($inp),$xb1,$xb1
	vpxor		0x40($inp),$xc1,$xc1
	vpxor		0x60($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa1,0x00($out)
	vmovdqu		$xb1,0x20($out)
	vmovdqu		$xc1,0x40($out)
	vmovdqu		$xd1,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x20($inp),$xb2,$xb2
	vpxor		0x40($inp),$xc2,$xc2
	vpxor		0x60($inp),$xd2,$xd2
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x20($out)
	vmovdqu		$xc2,0x40($out)
	vmovdqu		$xd2,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa3,$xa3
	vpxor		0x20($inp),$xb3,$xb3
	vpxor		0x40($inp),$xc3,$xc3
	vpxor		0x60($inp),$xd3,$xd3
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa3,0x00($out)
	vmovdqu		$xb3,0x20($out)
	vmovdqu		$xc3,0x40($out)
	vmovdqu		$xd3,0x60($out)
	lea		0x80($out),$out		# size optimization

	sub		\$64*8,$len
	jnz		.Loop_outer8x

	jmp		.Ldone8x

.Ltail8x:
	cmp		\$448,$len
	jae		.L448_or_more8x
	cmp		\$384,$len
	jae		.L384_or_more8x
	cmp		\$320,$len
	jae		.L320_or_more8x
	cmp		\$256,$len
	jae		.L256_or_more8x
	cmp		\$192,$len
	jae		.L192_or_more8x
	cmp		\$128,$len
	jae		.L128_or_more8x
	cmp		\$64,$len
	jae		.L64_or_more8x

	xor		%r10,%r10
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xb0,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L64_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	je		.Ldone8x

	lea		0x40($inp),$inp		# inp+=64*1
	xor		%r10,%r10
	vmovdqa		$xc0,0x00(%rsp)
	lea		0x40($out),$out		# out+=64*1
	sub		\$64,$len		# len-=64*1
	vmovdqa		$xd0,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L128_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	je		.Ldone8x

	lea		0x80($inp),$inp		# inp+=64*2
	xor		%r10,%r10
	vmovdqa		$xa1,0x00(%rsp)
	lea		0x80($out),$out		# out+=64*2
	sub		\$128,$len		# len-=64*2
	vmovdqa		$xb1,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L192_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	je		.Ldone8x

	lea		0xc0($inp),$inp		# inp+=64*3
	xor		%r10,%r10
	vmovdqa		$xc1,0x00(%rsp)
	lea		0xc0($out),$out		# out+=64*3
	sub		\$192,$len		# len-=64*3
	vmovdqa		$xd1,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L256_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	je		.Ldone8x

	lea		0x100($inp),$inp	# inp+=64*4
	xor		%r10,%r10
	vmovdqa		$xa2,0x00(%rsp)
	lea		0x100($out),$out	# out+=64*4
	sub		\$256,$len		# len-=64*4
	vmovdqa		$xb2,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L320_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	je		.Ldone8x

	lea		0x140($inp),$inp	# inp+=64*5
	xor		%r10,%r10
	vmovdqa		$xc2,0x00(%rsp)
	lea		0x140($out),$out	# out+=64*5
	sub		\$320,$len		# len-=64*5
	vmovdqa		$xd2,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L384_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vpxor		0x140($inp),$xc2,$xc2
	vpxor		0x160($inp),$xd2,$xd2
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	vmovdqu		$xc2,0x140($out)
	vmovdqu		$xd2,0x160($out)
	je		.Ldone8x

	lea		0x180($inp),$inp	# inp+=64*6
	xor		%r10,%r10
	vmovdqa		$xa3,0x00(%rsp)
	lea		0x180($out),$out	# out+=64*6
	sub		\$384,$len		# len-=64*6
	vmovdqa		$xb3,0x20(%rsp)
	jmp		.Loop_tail8x

.align	32
.L448_or_more8x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vpxor		0x140($inp),$xc2,$xc2
	vpxor		0x160($inp),$xd2,$xd2
	vpxor		0x180($inp),$xa3,$xa3
	vpxor		0x1a0($inp),$xb3,$xb3
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	vmovdqu		$xc2,0x140($out)
	vmovdqu		$xd2,0x160($out)
	vmovdqu		$xa3,0x180($out)
	vmovdqu		$xb3,0x1a0($out)
	je		.Ldone8x

	lea		0x1c0($inp),$inp	# inp+=64*7
	xor		%r10,%r10
	vmovdqa		$xc3,0x00(%rsp)
	lea		0x1c0($out),$out	# out+=64*7
	sub		\$448,$len		# len-=64*7
	vmovdqa		$xd3,0x20(%rsp)

.Loop_tail8x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail8x

.Ldone8x:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L8x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_8x,.-ChaCha20_8x
___
($xb0,$xb1,$xb2,$xb3, $xd0,$xd1,$xd2,$xd3, $xa0,$xa1,$xa2,$xa3, $xt0,$xt1,$xt2,$xt3)=map("%ymm$_",(0..15));
@xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3, "%nox","%nox","%nox","%nox", $xd0,$xd1,$xd2,$xd3);
$hyb = 1;
$code.=<<___;
.type	ChaCha20_9x,\@function,5
.align	32
ChaCha20_9x:
.cfi_startproc
.LChaCha20_9x:
	# A vector pass is saved only where the 576-byte batches cross fewer
	# 512-byte boundaries than stock. With q = (len-1)/512, that fails exactly
	# when len >= 576*q + 65 -- 7 intervals, none above 3584. The 65 is the
	# in-frame scalar remainder: a single leftover block costs no vector pass.
	lea		-1(%rdx),%rax
	shr		\$9,%rax		# q
	imul		\$576,%rax,%rax
	add		\$65,%rax
	cmp		%rax,%rdx
	jae		.LChaCha20_8x
	push		%rbx
.cfi_push	%rbx
	push		%rbp
.cfi_push	%rbp
	push		%r12
.cfi_push	%r12
	push		%r13
.cfi_push	%r13
	push		%r14
.cfi_push	%r14
	push		%r15
.cfi_push	%r15
	mov		%rsp,%r9		# frame register
.cfi_def_cfa_register	%r9
	sub		\$0x280+192+$xframe,%rsp
	and		\$-32,%rsp
___
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
.L9x_body:
___
$code.=<<___;
	vzeroupper

	################ stack layout
	# +0x00		SIMD equivalent of @x[8-12]
	# ...
	# +0x80		constant copy of key[0-2] smashed by lanes
	# ...
	# +0x200	SIMD counters (with nonce smashed by lanes)
	# ...
	# +0x280

	vbroadcasti128	.Lsigma(%rip),$xa3	# key[0]
	vbroadcasti128	($key),$xb3		# key[1]
	vbroadcasti128	16($key),$xt3		# key[2]
	vbroadcasti128	($counter),$xd3		# key[3]
	# 9th block: build original state (counter starts at +8)
	mov		\$0x61707865,%eax
	mov		%eax,640(%rsp)
	mov		\$0x3320646e,%eax
	mov		%eax,644(%rsp)
	mov		\$0x79622d32,%eax
	mov		%eax,648(%rsp)
	mov		\$0x6b206574,%eax
	mov		%eax,652(%rsp)
	mov		0(%rcx),%eax
	mov		%eax,656(%rsp)
	mov		4(%rcx),%eax
	mov		%eax,660(%rsp)
	mov		8(%rcx),%eax
	mov		%eax,664(%rsp)
	mov		12(%rcx),%eax
	mov		%eax,668(%rsp)
	mov		16(%rcx),%eax
	mov		%eax,672(%rsp)
	mov		20(%rcx),%eax
	mov		%eax,676(%rsp)
	mov		24(%rcx),%eax
	mov		%eax,680(%rsp)
	mov		28(%rcx),%eax
	mov		%eax,684(%rsp)
	mov		0(%r8),%eax
	add		\$8,%eax
	mov		%eax,688(%rsp)
	mov		4(%r8),%eax
	mov		%eax,692(%rsp)
	mov		8(%r8),%eax
	mov		%eax,696(%rsp)
	mov		12(%r8),%eax
	mov		%eax,700(%rsp)
	lea		0x100(%rsp),%rcx	# size optimization
	lea		0x200(%rsp),%rax	# size optimization

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vmovdqa		$xa0,0x80-0x100(%rcx)	# ... and offload
	vpshufd		\$0xaa,$xa3,$xa2
	vmovdqa		$xa1,0xa0-0x100(%rcx)
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa		$xa2,0xc0-0x100(%rcx)
	vmovdqa		$xa3,0xe0-0x100(%rcx)

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vmovdqa		$xb0,0x100-0x100(%rcx)
	vpshufd		\$0xaa,$xb3,$xb2
	vmovdqa		$xb1,0x120-0x100(%rcx)
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa		$xb2,0x140-0x100(%rcx)
	vmovdqa		$xb3,0x160-0x100(%rcx)

	vpshufd		\$0x00,$xt3,$xt0	# "xc0"
	vpshufd		\$0x55,$xt3,$xt1	# "xc1"
	vmovdqa		$xt0,0x180-0x200(%rax)
	vpshufd		\$0xaa,$xt3,$xt2	# "xc2"
	vmovdqa		$xt1,0x1a0-0x200(%rax)
	vpshufd		\$0xff,$xt3,$xt3	# "xc3"
	vmovdqa		$xt2,0x1c0-0x200(%rax)
	vmovdqa		$xt3,0x1e0-0x200(%rax)

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpaddd		.Lincy(%rip),$xd0,$xd0	# don't save counters yet
	vpshufd		\$0xaa,$xd3,$xd2
	vmovdqa		$xd1,0x220-0x200(%rax)
	vpshufd		\$0xff,$xd3,$xd3
	vmovdqa		$xd2,0x240-0x200(%rax)
	vmovdqa		$xd3,0x260-0x200(%rax)

	jmp		.Loop_enter9x

.align	32
.Loop_outer9x:
	cmp		\$64,%rdx
	jbe		.Lscalar_remainder9x
	vmovdqa		0x80-0x100(%rcx),$xa0	# re-load smashed key
	vmovdqa		0xa0-0x100(%rcx),$xa1
	vmovdqa		0xc0-0x100(%rcx),$xa2
	vmovdqa		0xe0-0x100(%rcx),$xa3
	vmovdqa		0x100-0x100(%rcx),$xb0
	vmovdqa		0x120-0x100(%rcx),$xb1
	vmovdqa		0x140-0x100(%rcx),$xb2
	vmovdqa		0x160-0x100(%rcx),$xb3
	vmovdqa		0x180-0x200(%rax),$xt0	# "xc0"
	vmovdqa		0x1a0-0x200(%rax),$xt1	# "xc1"
	vmovdqa		0x1c0-0x200(%rax),$xt2	# "xc2"
	vmovdqa		0x1e0-0x200(%rax),$xt3	# "xc3"
	vmovdqa		0x200-0x200(%rax),$xd0
	vmovdqa		0x220-0x200(%rax),$xd1
	vmovdqa		0x240-0x200(%rax),$xd2
	vmovdqa		0x260-0x200(%rax),$xd3
	vpaddd		.Lnine(%rip),$xd0,$xd0	# next SIMD counters

.Loop_enter9x:
	vmovdqa		$xt2,0x40(%rsp)		# SIMD equivalent of "@x[10]"
	vmovdqa		$xt3,0x60(%rsp)		# SIMD equivalent of "@x[11]"
	vbroadcasti128	.Lrot16(%rip),$xt3
	vmovdqa		$xd0,0x200-0x200(%rax)	# save SIMD counters
	# 9th block: spill the pointers the vector loop keeps live
	mov		%rcx,776(%rsp)
	mov		%rdi,784(%rsp)
	mov		%rsi,792(%rsp)
	mov		%rdx,800(%rsp)
	# 9th block: load working state
	mov		640(%rsp),%eax
	mov		644(%rsp),%ebx
	mov		648(%rsp),%ecx
	mov		652(%rsp),%edx
	mov		656(%rsp),%r8d
	mov		660(%rsp),%r10d
	mov		664(%rsp),%r11d
	mov		668(%rsp),%ebp
	mov		672(%rsp),%esi
	mov		676(%rsp),%edi
	mov		680(%rsp),%r12d
	mov		%r12d,744(%rsp)
	mov		684(%rsp),%r13d
	mov		%r13d,748(%rsp)
	mov		688(%rsp),%r12d
	mov		692(%rsp),%r13d
	mov		696(%rsp),%r14d
	mov		700(%rsp),%r15d
	movl		\$10,768(%rsp)
	jmp		.Loop9x

.align	32
.Loop9x:
___
	{
	my @v = (&AVX2_lane_ROUND(0, 4, 8,12), &AVX2_lane_ROUND(0, 5,10,15));
	my @s = (&SCALAR_ROUND(704, 0, 4, 8,12), &SCALAR_ROUND(704, 0, 5,10,15));
	if ($hybmode eq "seq") {
		foreach (@v) { eval; }
	} else {
		foreach (&HYBRID_WEAVE(\@v,\@s,$hybchunk)) { eval; }
	}
	}
$code.=<<___;
	subl		\$1,768(%rsp)
	jnz		.Loop9x
___
if ($hybmode eq "seq") {
$code.=<<___;
	movl		\$10,772(%rsp)
.Lscalar9x:
___
	foreach (&SCALAR_ROUND(704, 0, 4, 8,12)) { eval; }
	foreach (&SCALAR_ROUND(704, 0, 5,10,15)) { eval; }
$code.=<<___;
	subl		\$1,772(%rsp)
	jnz		.Lscalar9x
___
}
$code.=<<___;
	# 9th block: park working state, restore vector pointers
	mov		%eax,704(%rsp)
	mov		%ebx,708(%rsp)
	mov		%ecx,712(%rsp)
	mov		%edx,716(%rsp)
	mov		%r8d,720(%rsp)
	mov		%r10d,724(%rsp)
	mov		%r11d,728(%rsp)
	mov		%ebp,732(%rsp)
	mov		%r12d,752(%rsp)
	mov		%r13d,756(%rsp)
	mov		%r14d,760(%rsp)
	mov		%r15d,764(%rsp)
	mov		%esi,736(%rsp)
	mov		%edi,740(%rsp)
	mov		776(%rsp),%rcx
	mov		784(%rsp),%rdi
	mov		792(%rsp),%rsi
	mov		800(%rsp),%rdx

	lea		0x200(%rsp),%rax	# size optimization
	vpaddd		0x80-0x100(%rcx),$xa0,$xa0	# accumulate key
	vpaddd		0xa0-0x100(%rcx),$xa1,$xa1
	vpaddd		0xc0-0x100(%rcx),$xa2,$xa2
	vpaddd		0xe0-0x100(%rcx),$xa3,$xa3

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
	($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		0x100-0x100(%rcx),$xb0,$xb0
	vpaddd		0x120-0x100(%rcx),$xb1,$xb1
	vpaddd		0x140-0x100(%rcx),$xb2,$xb2
	vpaddd		0x160-0x100(%rcx),$xb3,$xb3

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
$code.=<<___;
	vperm2i128	\$0x20,$xb0,$xa0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xb0,$xa0,$xb0
	vperm2i128	\$0x20,$xb1,$xa1,$xa0
	vperm2i128	\$0x31,$xb1,$xa1,$xb1
	vperm2i128	\$0x20,$xb2,$xa2,$xa1
	vperm2i128	\$0x31,$xb2,$xa2,$xb2
	vperm2i128	\$0x20,$xb3,$xa3,$xa2
	vperm2i128	\$0x31,$xb3,$xa3,$xb3
___
	($xa0,$xa1,$xa2,$xa3,$xt3)=($xt3,$xa0,$xa1,$xa2,$xa3);
	my ($xc0,$xc1,$xc2,$xc3)=($xt0,$xt1,$xa0,$xa1);
$code.=<<___;
	vmovdqa		$xa0,0x00(%rsp)		# offload $xaN
	vmovdqa		$xa1,0x20(%rsp)
	vmovdqa		0x40(%rsp),$xc2		# $xa0
	vmovdqa		0x60(%rsp),$xc3		# $xa1

	vpaddd		0x180-0x200(%rax),$xc0,$xc0
	vpaddd		0x1a0-0x200(%rax),$xc1,$xc1
	vpaddd		0x1c0-0x200(%rax),$xc2,$xc2
	vpaddd		0x1e0-0x200(%rax),$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		0x200-0x200(%rax),$xd0,$xd0
	vpaddd		0x220-0x200(%rax),$xd1,$xd1
	vpaddd		0x240-0x200(%rax),$xd2,$xd2
	vpaddd		0x260-0x200(%rax),$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
$code.=<<___;
	vperm2i128	\$0x20,$xd0,$xc0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xd0,$xc0,$xd0
	vperm2i128	\$0x20,$xd1,$xc1,$xc0
	vperm2i128	\$0x31,$xd1,$xc1,$xd1
	vperm2i128	\$0x20,$xd2,$xc2,$xc1
	vperm2i128	\$0x31,$xd2,$xc2,$xd2
	vperm2i128	\$0x20,$xd3,$xc3,$xc2
	vperm2i128	\$0x31,$xd3,$xc3,$xd3
___
	($xc0,$xc1,$xc2,$xc3,$xt3)=($xt3,$xc0,$xc1,$xc2,$xc3);
	($xb0,$xb1,$xb2,$xb3,$xc0,$xc1,$xc2,$xc3)=
	($xc0,$xc1,$xc2,$xc3,$xb0,$xb1,$xb2,$xb3);
	($xa0,$xa1)=($xt2,$xt3);
$code.=<<___;
	vmovdqa		0x00(%rsp),$xa0		# $xaN was offloaded, remember?
	vmovdqa		0x20(%rsp),$xa1

	cmp		\$64*8,$len
	jb		.Ltail9x

	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa1,$xa1
	vpxor		0x20($inp),$xb1,$xb1
	vpxor		0x40($inp),$xc1,$xc1
	vpxor		0x60($inp),$xd1,$xd1
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa1,0x00($out)
	vmovdqu		$xb1,0x20($out)
	vmovdqu		$xc1,0x40($out)
	vmovdqu		$xd1,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa2,$xa2
	vpxor		0x20($inp),$xb2,$xb2
	vpxor		0x40($inp),$xc2,$xc2
	vpxor		0x60($inp),$xd2,$xd2
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa2,0x00($out)
	vmovdqu		$xb2,0x20($out)
	vmovdqu		$xc2,0x40($out)
	vmovdqu		$xd2,0x60($out)
	lea		0x80($out),$out		# size optimization

	vpxor		0x00($inp),$xa3,$xa3
	vpxor		0x20($inp),$xb3,$xb3
	vpxor		0x40($inp),$xc3,$xc3
	vpxor		0x60($inp),$xd3,$xd3
	lea		0x80($inp),$inp		# size optimization
	vmovdqu		$xa3,0x00($out)
	vmovdqu		$xb3,0x20($out)
	vmovdqu		$xc3,0x40($out)
	vmovdqu		$xd3,0x60($out)
	lea		0x80($out),$out		# size optimization

	sub		\$64*8,$len
	jz		.Ldone9x
	cmp		\$64,$len
	jb		.Lscalar_tail9x
	# 9th block: add state, xor, store the 64-byte tail
	vmovdqa		704(%rsp),%ymm0
	vpaddd		640(%rsp),%ymm0,%ymm0
	vpxor		0x00(%rsi),%ymm0,%ymm0
	vmovdqu		%ymm0,0x00(%rdi)
	vmovdqa		736(%rsp),%ymm1
	vpaddd		672(%rsp),%ymm1,%ymm1
	vpxor		0x20(%rsi),%ymm1,%ymm1
	vmovdqu		%ymm1,0x20(%rdi)
	lea		0x40(%rsi),%rsi
	lea		0x40(%rdi),%rdi
	addl		\$9,688(%rsp)		# block 9 counter += 9
	sub		\$64,$len
	jnz		.Loop_outer9x
	jmp		.Ldone9x

.Lscalar_remainder9x:
	subl		\$8,688(%rsp)
	# 9th block: spill the pointers the vector loop keeps live
	mov		%rcx,776(%rsp)
	mov		%rdi,784(%rsp)
	mov		%rsi,792(%rsp)
	mov		%rdx,800(%rsp)
	# 9th block: load working state
	mov		640(%rsp),%eax
	mov		644(%rsp),%ebx
	mov		648(%rsp),%ecx
	mov		652(%rsp),%edx
	mov		656(%rsp),%r8d
	mov		660(%rsp),%r10d
	mov		664(%rsp),%r11d
	mov		668(%rsp),%ebp
	mov		672(%rsp),%esi
	mov		676(%rsp),%edi
	mov		680(%rsp),%r12d
	mov		%r12d,744(%rsp)
	mov		684(%rsp),%r13d
	mov		%r13d,748(%rsp)
	mov		688(%rsp),%r12d
	mov		692(%rsp),%r13d
	mov		696(%rsp),%r14d
	mov		700(%rsp),%r15d
	movl		\$10,772(%rsp)
.Lscalar_remainder_rounds9x:
___
	foreach (&SCALAR_ROUND(704, 0, 4, 8,12)) { eval; }
	foreach (&SCALAR_ROUND(704, 0, 5,10,15)) { eval; }
$code.=<<___;
	subl		\$1,772(%rsp)
	jnz		.Lscalar_remainder_rounds9x
	# 9th block: park working state, restore vector pointers
	mov		%eax,704(%rsp)
	mov		%ebx,708(%rsp)
	mov		%ecx,712(%rsp)
	mov		%edx,716(%rsp)
	mov		%r8d,720(%rsp)
	mov		%r10d,724(%rsp)
	mov		%r11d,728(%rsp)
	mov		%ebp,732(%rsp)
	mov		%r12d,752(%rsp)
	mov		%r13d,756(%rsp)
	mov		%r14d,760(%rsp)
	mov		%r15d,764(%rsp)
	mov		%esi,736(%rsp)
	mov		%edi,740(%rsp)
	mov		776(%rsp),%rcx
	mov		784(%rsp),%rdi
	mov		792(%rsp),%rsi
	mov		800(%rsp),%rdx
	cmp		\$64,%rdx
	jb		.Lscalar_remainder_partial9x
	# 9th block: add state, xor, store the 64-byte tail
	vmovdqa		704(%rsp),%ymm0
	vpaddd		640(%rsp),%ymm0,%ymm0
	vpxor		0x00(%rsi),%ymm0,%ymm0
	vmovdqu		%ymm0,0x00(%rdi)
	vmovdqa		736(%rsp),%ymm1
	vpaddd		672(%rsp),%ymm1,%ymm1
	vpxor		0x20(%rsi),%ymm1,%ymm1
	vmovdqu		%ymm1,0x20(%rdi)
	lea		0x40(%rsi),%rsi
	lea		0x40(%rdi),%rdi
	addl		\$9,688(%rsp)		# block 9 counter += 9
	jmp		.Ldone9x
.Lscalar_remainder_partial9x:
	# 9th block: spill keystream for a partial (<64 byte) tail
	vmovdqa		704(%rsp),%ymm0
	vpaddd		640(%rsp),%ymm0,%ymm0
	vmovdqa		%ymm0,0x00(%rsp)
	vmovdqa		736(%rsp),%ymm1
	vpaddd		672(%rsp),%ymm1,%ymm1
	vmovdqa		%ymm1,0x20(%rsp)
	xor		%r10,%r10
	jmp		.Loop_tail9x

.Lscalar_tail9x:
	# 9th block: spill keystream for a partial (<64 byte) tail
	vmovdqa		704(%rsp),%ymm0
	vpaddd		640(%rsp),%ymm0,%ymm0
	vmovdqa		%ymm0,0x00(%rsp)
	vmovdqa		736(%rsp),%ymm1
	vpaddd		672(%rsp),%ymm1,%ymm1
	vmovdqa		%ymm1,0x20(%rsp)
	xor		%r10,%r10
	jmp		.Loop_tail9x

.Ltail9x:
	cmp		\$448,$len
	jae		.L448_or_more9x
	cmp		\$384,$len
	jae		.L384_or_more9x
	cmp		\$320,$len
	jae		.L320_or_more9x
	cmp		\$256,$len
	jae		.L256_or_more9x
	cmp		\$192,$len
	jae		.L192_or_more9x
	cmp		\$128,$len
	jae		.L128_or_more9x
	cmp		\$64,$len
	jae		.L64_or_more9x

	xor		%r10,%r10
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xb0,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L64_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	je		.Ldone9x

	lea		0x40($inp),$inp		# inp+=64*1
	xor		%r10,%r10
	vmovdqa		$xc0,0x00(%rsp)
	lea		0x40($out),$out		# out+=64*1
	sub		\$64,$len		# len-=64*1
	vmovdqa		$xd0,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L128_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	je		.Ldone9x

	lea		0x80($inp),$inp		# inp+=64*2
	xor		%r10,%r10
	vmovdqa		$xa1,0x00(%rsp)
	lea		0x80($out),$out		# out+=64*2
	sub		\$128,$len		# len-=64*2
	vmovdqa		$xb1,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L192_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	je		.Ldone9x

	lea		0xc0($inp),$inp		# inp+=64*3
	xor		%r10,%r10
	vmovdqa		$xc1,0x00(%rsp)
	lea		0xc0($out),$out		# out+=64*3
	sub		\$192,$len		# len-=64*3
	vmovdqa		$xd1,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L256_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	je		.Ldone9x

	lea		0x100($inp),$inp	# inp+=64*4
	xor		%r10,%r10
	vmovdqa		$xa2,0x00(%rsp)
	lea		0x100($out),$out	# out+=64*4
	sub		\$256,$len		# len-=64*4
	vmovdqa		$xb2,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L320_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	je		.Ldone9x

	lea		0x140($inp),$inp	# inp+=64*5
	xor		%r10,%r10
	vmovdqa		$xc2,0x00(%rsp)
	lea		0x140($out),$out	# out+=64*5
	sub		\$320,$len		# len-=64*5
	vmovdqa		$xd2,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L384_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vpxor		0x140($inp),$xc2,$xc2
	vpxor		0x160($inp),$xd2,$xd2
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	vmovdqu		$xc2,0x140($out)
	vmovdqu		$xd2,0x160($out)
	je		.Ldone9x

	lea		0x180($inp),$inp	# inp+=64*6
	xor		%r10,%r10
	vmovdqa		$xa3,0x00(%rsp)
	lea		0x180($out),$out	# out+=64*6
	sub		\$384,$len		# len-=64*6
	vmovdqa		$xb3,0x20(%rsp)
	jmp		.Loop_tail9x

.align	32
.L448_or_more9x:
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	vpxor		0x80($inp),$xa1,$xa1
	vpxor		0xa0($inp),$xb1,$xb1
	vpxor		0xc0($inp),$xc1,$xc1
	vpxor		0xe0($inp),$xd1,$xd1
	vpxor		0x100($inp),$xa2,$xa2
	vpxor		0x120($inp),$xb2,$xb2
	vpxor		0x140($inp),$xc2,$xc2
	vpxor		0x160($inp),$xd2,$xd2
	vpxor		0x180($inp),$xa3,$xa3
	vpxor		0x1a0($inp),$xb3,$xb3
	vmovdqu		$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	vmovdqu		$xa1,0x80($out)
	vmovdqu		$xb1,0xa0($out)
	vmovdqu		$xc1,0xc0($out)
	vmovdqu		$xd1,0xe0($out)
	vmovdqu		$xa2,0x100($out)
	vmovdqu		$xb2,0x120($out)
	vmovdqu		$xc2,0x140($out)
	vmovdqu		$xd2,0x160($out)
	vmovdqu		$xa3,0x180($out)
	vmovdqu		$xb3,0x1a0($out)
	je		.Ldone9x

	lea		0x1c0($inp),$inp	# inp+=64*7
	xor		%r10,%r10
	vmovdqa		$xc3,0x00(%rsp)
	lea		0x1c0($out),$out	# out+=64*7
	sub		\$448,$len		# len-=64*7
	vmovdqa		$xd3,0x20(%rsp)

.Loop_tail9x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail9x

.Ldone9x:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
	pop		%r15
.cfi_pop	%r15
	pop		%r14
.cfi_pop	%r14
	pop		%r13
.cfi_pop	%r13
	pop		%r12
.cfi_pop	%r12
	pop		%rbp
.cfi_pop	%rbp
	pop		%rbx
.cfi_pop	%rbx
.L9x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_9x,.-ChaCha20_9x
___
}

########################################################################
# AVX512 code paths
if ($avx>2) {
# This one handles shorter inputs...

my ($a,$b,$c,$d, $a_,$b_,$c_,$d_,$fourz) = map("%zmm$_",(0..3,16..20));
my ($t0,$t1,$t2,$t3) = map("%xmm$_",(4..7));

sub vpxord()		# size optimization
{ my $opcode = "vpxor";	# adhere to vpxor when possible

    foreach (@_) {
	if (/%([zy])mm([0-9]+)/ && ($1 eq "z" || $2>=16)) {
	    $opcode = "vpxord";
	    last;
	}
    }

    $code .= "\t$opcode\t".join(',',reverse @_)."\n";
}

sub AVX512ROUND {	# critical path is 14 "SIMD ticks" per round
	&vpaddd	($a,$a,$b);
	&vpxord	($d,$d,$a);
	&vprold	($d,$d,16);

	&vpaddd	($c,$c,$d);
	&vpxord	($b,$b,$c);
	&vprold	($b,$b,12);

	&vpaddd	($a,$a,$b);
	&vpxord	($d,$d,$a);
	&vprold	($d,$d,8);

	&vpaddd	($c,$c,$d);
	&vpxord	($b,$b,$c);
	&vprold	($b,$b,7);
}

my $xframe = $win64 ? 160+8 : 8;

$code.=<<___;
.globl	ChaCha20_tail_avx512
.type	ChaCha20_tail_avx512,\@function,5
.align	16
ChaCha20_tail_avx512:
	cmp	\$128,%rdx
	jbe	ChaCha20_2xvl
	cmp	\$256,%rdx
	jbe	ChaCha20_4xvl
	cmp	\$512,%rdx
	jbe	ChaCha20_8xvl
	cmp	\$2048,%rdx
	jae	ChaCha20_32x		# two interleaved instances, ILP 8
	jmp	ChaCha20_16x
.size	ChaCha20_tail_avx512,.-ChaCha20_tail_avx512

.globl	ChaCha20_4xvl
.type	ChaCha20_4xvl,\@function,5
.type	ChaCha20_avx512,\@function,5
.align	32
ChaCha20_4xvl:
ChaCha20_avx512:
.cfi_startproc
.LChaCha20_avx512:
	mov	%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	cmp	\$2240,$len
	jae	ChaCha20_32x
	cmp	\$2048,$len
	je	ChaCha20_32x
	cmp	\$512,$len
	ja	.LChaCha20_17x

	sub	\$64+$xframe,%rsp
___
$code.=<<___	if ($win64);
	movaps	%xmm6,-0xa8(%r9)
	movaps	%xmm7,-0x98(%r9)
	movaps	%xmm8,-0x88(%r9)
	movaps	%xmm9,-0x78(%r9)
	movaps	%xmm10,-0x68(%r9)
	movaps	%xmm11,-0x58(%r9)
	movaps	%xmm12,-0x48(%r9)
	movaps	%xmm13,-0x38(%r9)
	movaps	%xmm14,-0x28(%r9)
	movaps	%xmm15,-0x18(%r9)
___
$code.=".Lavx512_body:\n";
$code.=<<___;
	vbroadcasti32x4	.Lsigma(%rip),$a
	vbroadcasti32x4	($key),$b
	vbroadcasti32x4	16($key),$c
	vbroadcasti32x4	($counter),$d

	vmovdqa32	$a,$a_
	vmovdqa32	$b,$b_
	vmovdqa32	$c,$c_
	vpaddd		.Lzeroz(%rip),$d,$d
	vmovdqa32	.Lfourz(%rip),$fourz
	mov		\$10,$counter	# reuse $counter
	vmovdqa32	$d,$d_
	jmp		.Loop_avx512

.align	16
.Loop_outer_avx512:
	vmovdqa32	$a_,$a
	vmovdqa32	$b_,$b
	vmovdqa32	$c_,$c
	vpaddd		$fourz,$d_,$d
	mov		\$10,$counter
	vmovdqa32	$d,$d_
	jmp		.Loop_avx512

.align	32
.Loop_avx512:
___
	&AVX512ROUND();
	&vpshufd	($c,$c,0b01001110);
	&vpshufd	($b,$b,0b00111001);
	&vpshufd	($d,$d,0b10010011);

	&AVX512ROUND();
	&vpshufd	($c,$c,0b01001110);
	&vpshufd	($b,$b,0b10010011);
	&vpshufd	($d,$d,0b00111001);

	&dec		($counter);
	&jnz		(".Loop_avx512");

$code.=<<___;
	vpaddd		$a_,$a,$a
	vpaddd		$b_,$b,$b
	vpaddd		$c_,$c,$c
	vpaddd		$d_,$d,$d

	sub		\$64,$len
	jb		.Ltail64_avx512

	vpxor		0x00($inp),%x#$a,$t0	# xor with input
	vpxor		0x10($inp),%x#$b,$t1
	vpxor		0x20($inp),%x#$c,$t2
	vpxor		0x30($inp),%x#$d,$t3
	lea		0x40($inp),$inp		# inp+=64

	vmovdqu		$t0,0x00($out)		# write output
	vmovdqu		$t1,0x10($out)
	vmovdqu		$t2,0x20($out)
	vmovdqu		$t3,0x30($out)
	lea		0x40($out),$out		# out+=64

	jz		.Ldone_avx512

	vextracti32x4	\$1,$a,$t0
	vextracti32x4	\$1,$b,$t1
	vextracti32x4	\$1,$c,$t2
	vextracti32x4	\$1,$d,$t3

	sub		\$64,$len
	jb		.Ltail_avx512

	vpxor		0x00($inp),$t0,$t0	# xor with input
	vpxor		0x10($inp),$t1,$t1
	vpxor		0x20($inp),$t2,$t2
	vpxor		0x30($inp),$t3,$t3
	lea		0x40($inp),$inp		# inp+=64

	vmovdqu		$t0,0x00($out)		# write output
	vmovdqu		$t1,0x10($out)
	vmovdqu		$t2,0x20($out)
	vmovdqu		$t3,0x30($out)
	lea		0x40($out),$out		# out+=64

	jz		.Ldone_avx512

	vextracti32x4	\$2,$a,$t0
	vextracti32x4	\$2,$b,$t1
	vextracti32x4	\$2,$c,$t2
	vextracti32x4	\$2,$d,$t3

	sub		\$64,$len
	jb		.Ltail_avx512

	vpxor		0x00($inp),$t0,$t0	# xor with input
	vpxor		0x10($inp),$t1,$t1
	vpxor		0x20($inp),$t2,$t2
	vpxor		0x30($inp),$t3,$t3
	lea		0x40($inp),$inp		# inp+=64

	vmovdqu		$t0,0x00($out)		# write output
	vmovdqu		$t1,0x10($out)
	vmovdqu		$t2,0x20($out)
	vmovdqu		$t3,0x30($out)
	lea		0x40($out),$out		# out+=64

	jz		.Ldone_avx512

	vextracti32x4	\$3,$a,$t0
	vextracti32x4	\$3,$b,$t1
	vextracti32x4	\$3,$c,$t2
	vextracti32x4	\$3,$d,$t3

	sub		\$64,$len
	jb		.Ltail_avx512

	vpxor		0x00($inp),$t0,$t0	# xor with input
	vpxor		0x10($inp),$t1,$t1
	vpxor		0x20($inp),$t2,$t2
	vpxor		0x30($inp),$t3,$t3
	lea		0x40($inp),$inp		# inp+=64

	vmovdqu		$t0,0x00($out)		# write output
	vmovdqu		$t1,0x10($out)
	vmovdqu		$t2,0x20($out)
	vmovdqu		$t3,0x30($out)
	lea		0x40($out),$out		# out+=64

	jnz		.Loop_outer_avx512

	jmp		.Ldone_avx512

.align	16
.Ltail64_avx512:
	vmovdqa		%x#$a,0x00(%rsp)
	vmovdqa		%x#$b,0x10(%rsp)
	vmovdqa		%x#$c,0x20(%rsp)
	vmovdqa		%x#$d,0x30(%rsp)
	add		\$64,$len
	jmp		.Loop_tail_avx512

.align	16
.Ltail_avx512:
	vmovdqa		$t0,0x00(%rsp)
	vmovdqa		$t1,0x10(%rsp)
	vmovdqa		$t2,0x20(%rsp)
	vmovdqa		$t3,0x30(%rsp)
	add		\$64,$len

.Loop_tail_avx512:
	movzb		($inp,$counter),%eax
	movzb		(%rsp,$counter),%ecx
	lea		1($counter),$counter
	xor		%ecx,%eax
	mov		%al,-1($out,$counter)
	dec		$len
	jnz		.Loop_tail_avx512

	vmovdqu32	$a_,0x00(%rsp)

.Ldone_avx512:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps	-0xa8(%r9),%xmm6
	movaps	-0x98(%r9),%xmm7
	movaps	-0x88(%r9),%xmm8
	movaps	-0x78(%r9),%xmm9
	movaps	-0x68(%r9),%xmm10
	movaps	-0x58(%r9),%xmm11
	movaps	-0x48(%r9),%xmm12
	movaps	-0x38(%r9),%xmm13
	movaps	-0x28(%r9),%xmm14
	movaps	-0x18(%r9),%xmm15
___
$code.=<<___;
	lea	(%r9),%rsp
.cfi_def_cfa_register	%rsp
.Lavx512_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_avx512,.-ChaCha20_avx512
.size	ChaCha20_4xvl,.-ChaCha20_4xvl
___

map(s/%z/%y/, $a,$b,$c,$d, $a_,$b_,$c_,$d_,$fourz);

$code.=<<___;
.globl	ChaCha20_2xvl
.type	ChaCha20_2xvl,\@function,5
.type	ChaCha20_avx512vl,\@function,5
.align	32
ChaCha20_2xvl:
ChaCha20_avx512vl:
.cfi_startproc
.LChaCha20_avx512vl:
	mov	%rsp,%r9		# frame pointer
.cfi_def_cfa_register	%r9
	cmp	\$128,$len
	ja	.LChaCha20_8xvl

	sub	\$64+$xframe,%rsp
___
$code.=<<___	if ($win64);
	movaps	%xmm6,-0xa8(%r9)
	movaps	%xmm7,-0x98(%r9)
	movaps	%xmm8,-0x88(%r9)
	movaps	%xmm9,-0x78(%r9)
	movaps	%xmm10,-0x68(%r9)
	movaps	%xmm11,-0x58(%r9)
	movaps	%xmm12,-0x48(%r9)
	movaps	%xmm13,-0x38(%r9)
	movaps	%xmm14,-0x28(%r9)
	movaps	%xmm15,-0x18(%r9)
___
$code.=".Lavx512vl_body:\n";
$code.=<<___;
	vbroadcasti128	.Lsigma(%rip),$a
	vbroadcasti128	($key),$b
	vbroadcasti128	16($key),$c
	vbroadcasti128	($counter),$d

	vmovdqa32	$a,$a_
	vmovdqa32	$b,$b_
	vmovdqa32	$c,$c_
	vpaddd		.Lzeroz(%rip),$d,$d
	vmovdqa32	.Ltwoy(%rip),$fourz
	mov		\$10,$counter	# reuse $counter
	vmovdqa32	$d,$d_
	jmp		.Loop_avx512vl

.align	16
.Loop_outer_avx512vl:
	vmovdqa32	$c_,$c
	vpaddd		$fourz,$d_,$d
	mov		\$10,$counter
	vmovdqa32	$d,$d_
	jmp		.Loop_avx512vl

.align	32
.Loop_avx512vl:
___
	&AVX512ROUND();
	&vpshufd	($c,$c,0b01001110);
	&vpshufd	($b,$b,0b00111001);
	&vpshufd	($d,$d,0b10010011);

	&AVX512ROUND();
	&vpshufd	($c,$c,0b01001110);
	&vpshufd	($b,$b,0b10010011);
	&vpshufd	($d,$d,0b00111001);

	&dec		($counter);
	&jnz		(".Loop_avx512vl");

$code.=<<___;
	vpaddd		$a_,$a,$a
	vpaddd		$b_,$b,$b
	vpaddd		$c_,$c,$c
	vpaddd		$d_,$d,$d

	sub		\$64,$len
	jb		.Ltail64_avx512vl

	vpxor		0x00($inp),%x#$a,$t0	# xor with input
	vpxor		0x10($inp),%x#$b,$t1
	vpxor		0x20($inp),%x#$c,$t2
	vpxor		0x30($inp),%x#$d,$t3
	lea		0x40($inp),$inp		# inp+=64

	vmovdqu		$t0,0x00($out)		# write output
	vmovdqu		$t1,0x10($out)
	vmovdqu		$t2,0x20($out)
	vmovdqu		$t3,0x30($out)
	lea		0x40($out),$out		# out+=64

	jz		.Ldone_avx512vl

	vextracti128	\$1,$a,$t0
	vextracti128	\$1,$b,$t1
	vextracti128	\$1,$c,$t2
	vextracti128	\$1,$d,$t3

	sub		\$64,$len
	jb		.Ltail_avx512vl

	vpxor		0x00($inp),$t0,$t0	# xor with input
	vpxor		0x10($inp),$t1,$t1
	vpxor		0x20($inp),$t2,$t2
	vpxor		0x30($inp),$t3,$t3
	lea		0x40($inp),$inp		# inp+=64

	vmovdqu		$t0,0x00($out)		# write output
	vmovdqu		$t1,0x10($out)
	vmovdqu		$t2,0x20($out)
	vmovdqu		$t3,0x30($out)
	lea		0x40($out),$out		# out+=64

	vmovdqa32	$a_,$a
	vmovdqa32	$b_,$b
	jnz		.Loop_outer_avx512vl

	jmp		.Ldone_avx512vl

.align	16
.Ltail64_avx512vl:
	vmovdqa		%x#$a,0x00(%rsp)
	vmovdqa		%x#$b,0x10(%rsp)
	vmovdqa		%x#$c,0x20(%rsp)
	vmovdqa		%x#$d,0x30(%rsp)
	add		\$64,$len
	jmp		.Loop_tail_avx512vl

.align	16
.Ltail_avx512vl:
	vmovdqa		$t0,0x00(%rsp)
	vmovdqa		$t1,0x10(%rsp)
	vmovdqa		$t2,0x20(%rsp)
	vmovdqa		$t3,0x30(%rsp)
	add		\$64,$len

.Loop_tail_avx512vl:
	movzb		($inp,$counter),%eax
	movzb		(%rsp,$counter),%ecx
	lea		1($counter),$counter
	xor		%ecx,%eax
	mov		%al,-1($out,$counter)
	dec		$len
	jnz		.Loop_tail_avx512vl

	vmovdqu32	$a_,0x00(%rsp)
	vmovdqu32	$a_,0x20(%rsp)

.Ldone_avx512vl:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps	-0xa8(%r9),%xmm6
	movaps	-0x98(%r9),%xmm7
	movaps	-0x88(%r9),%xmm8
	movaps	-0x78(%r9),%xmm9
	movaps	-0x68(%r9),%xmm10
	movaps	-0x58(%r9),%xmm11
	movaps	-0x48(%r9),%xmm12
	movaps	-0x38(%r9),%xmm13
	movaps	-0x28(%r9),%xmm14
	movaps	-0x18(%r9),%xmm15
___
$code.=<<___;
	lea	(%r9),%rsp
.cfi_def_cfa_register	%rsp
.Lavx512vl_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_avx512vl,.-ChaCha20_avx512vl
.size	ChaCha20_2xvl,.-ChaCha20_2xvl
___
}
if ($avx>2) {
# This one handles longer inputs...

my ($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
    $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3)=map("%zmm$_",(0..15));
my  @xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	 $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3);
my @key=map("%zmm$_",(16..31));
my ($xt0,$xt1,$xt2,$xt3)=@key[0..3];

sub AVX512_lane_ROUND {
my ($a0,$b0,$c0,$d0)=@_;
my ($a1,$b1,$c1,$d1)=map(($_&~3)+(($_+1)&3),($a0,$b0,$c0,$d0));
my ($a2,$b2,$c2,$d2)=map(($_&~3)+(($_+1)&3),($a1,$b1,$c1,$d1));
my ($a3,$b3,$c3,$d3)=map(($_&~3)+(($_+1)&3),($a2,$b2,$c2,$d2));
my @x=map("\"$_\"",@xx);

	my @round = (
	"&vpaddd	(@x[$a0],@x[$a0],@x[$b0])",	# Q1
	 "&vpaddd	(@x[$a1],@x[$a1],@x[$b1])",	# Q2
	  "&vpaddd	(@x[$a2],@x[$a2],@x[$b2])",	# Q3
	   "&vpaddd	(@x[$a3],@x[$a3],@x[$b3])",	# Q4
	"&vpxord	(@x[$d0],@x[$d0],@x[$a0])",
	 "&vpxord	(@x[$d1],@x[$d1],@x[$a1])",
	  "&vpxord	(@x[$d2],@x[$d2],@x[$a2])",
	   "&vpxord	(@x[$d3],@x[$d3],@x[$a3])",
	"&vprold	(@x[$d0],@x[$d0],16)",
	 "&vprold	(@x[$d1],@x[$d1],16)",
	  "&vprold	(@x[$d2],@x[$d2],16)",
	   "&vprold	(@x[$d3],@x[$d3],16)",

	"&vpaddd	(@x[$c0],@x[$c0],@x[$d0])",
	 "&vpaddd	(@x[$c1],@x[$c1],@x[$d1])",
	  "&vpaddd	(@x[$c2],@x[$c2],@x[$d2])",
	   "&vpaddd	(@x[$c3],@x[$c3],@x[$d3])",
	"&vpxord	(@x[$b0],@x[$b0],@x[$c0])",
	 "&vpxord	(@x[$b1],@x[$b1],@x[$c1])",
	  "&vpxord	(@x[$b2],@x[$b2],@x[$c2])",
	   "&vpxord	(@x[$b3],@x[$b3],@x[$c3])",
	"&vprold	(@x[$b0],@x[$b0],12)",
	 "&vprold	(@x[$b1],@x[$b1],12)",
	  "&vprold	(@x[$b2],@x[$b2],12)",
	   "&vprold	(@x[$b3],@x[$b3],12)",

	"&vpaddd	(@x[$a0],@x[$a0],@x[$b0])",
	 "&vpaddd	(@x[$a1],@x[$a1],@x[$b1])",
	  "&vpaddd	(@x[$a2],@x[$a2],@x[$b2])",
	   "&vpaddd	(@x[$a3],@x[$a3],@x[$b3])",
	"&vpxord	(@x[$d0],@x[$d0],@x[$a0])",
	 "&vpxord	(@x[$d1],@x[$d1],@x[$a1])",
	  "&vpxord	(@x[$d2],@x[$d2],@x[$a2])",
	   "&vpxord	(@x[$d3],@x[$d3],@x[$a3])",
	"&vprold	(@x[$d0],@x[$d0],8)",
	 "&vprold	(@x[$d1],@x[$d1],8)",
	  "&vprold	(@x[$d2],@x[$d2],8)",
	   "&vprold	(@x[$d3],@x[$d3],8)",

	"&vpaddd	(@x[$c0],@x[$c0],@x[$d0])",
	 "&vpaddd	(@x[$c1],@x[$c1],@x[$d1])",
	  "&vpaddd	(@x[$c2],@x[$c2],@x[$d2])",
	   "&vpaddd	(@x[$c3],@x[$c3],@x[$d3])",
	"&vpxord	(@x[$b0],@x[$b0],@x[$c0])",
	 "&vpxord	(@x[$b1],@x[$b1],@x[$c1])",
	  "&vpxord	(@x[$b2],@x[$b2],@x[$c2])",
	   "&vpxord	(@x[$b3],@x[$b3],@x[$c3])",
	"&vprold	(@x[$b0],@x[$b0],7)",
	 "&vprold	(@x[$b1],@x[$b1],7)",
	  "&vprold	(@x[$b2],@x[$b2],7)",
	   "&vprold	(@x[$b3],@x[$b3],7)"
	);

	# Start the fourth independent lane's dependency chain before issuing the
	# matching operations for lanes 1--3. The instruction multiset is unchanged.
	my @staggered;
	for my $half (0, 1) {
		my @h = @round[$half*24 .. $half*24+23];
		push @staggered, @h[3, 7, 11, 15, 19, 23];
		for my $group (0..5) {
			push @staggered, @h[$group*4 .. $group*4+2];
		}
	}
	return @staggered;
}

my $xframe = $win64 ? 0xa8 : 8;

$code.=<<___;
.globl	ChaCha20_16x
.type	ChaCha20_16x,\@function,5
.align	32
ChaCha20_16x:
.cfi_startproc
.LChaCha20_16x:
	xor		%r11d,%r11d
	jmp		.LChaCha20_16x_common

.globl	ChaCha20_16x_tiered
.type	ChaCha20_16x_tiered,\@function,5
.align	16
ChaCha20_16x_tiered:
	mov		\$-1,%r11
.LChaCha20_16x_common:
	mov		%rsp,%r9		# frame register
.cfi_def_cfa_register	%r9
	sub		\$64+$xframe,%rsp
	and		\$-64,%rsp
	mov		%r11,64(%rsp)
___
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
.L16x_body:
___
$code.=<<___;
	vzeroupper

	lea		.Lsigma(%rip),%r10
	vbroadcasti32x4	(%r10),$xa3		# key[0]
	vbroadcasti32x4	($key),$xb3		# key[1]
	vbroadcasti32x4	16($key),$xc3		# key[2]
	vbroadcasti32x4	($counter),$xd3		# key[3]

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vpshufd		\$0xaa,$xa3,$xa2
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa64	$xa0,@key[0]
	vmovdqa64	$xa1,@key[1]
	vmovdqa64	$xa2,@key[2]
	vmovdqa64	$xa3,@key[3]

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vpshufd		\$0xaa,$xb3,$xb2
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa64	$xb0,@key[4]
	vmovdqa64	$xb1,@key[5]
	vmovdqa64	$xb2,@key[6]
	vmovdqa64	$xb3,@key[7]

	vpshufd		\$0x00,$xc3,$xc0
	vpshufd		\$0x55,$xc3,$xc1
	vpshufd		\$0xaa,$xc3,$xc2
	vpshufd		\$0xff,$xc3,$xc3
	vmovdqa64	$xc0,@key[8]
	vmovdqa64	$xc1,@key[9]
	vmovdqa64	$xc2,@key[10]
	vmovdqa64	$xc3,@key[11]

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpshufd		\$0xaa,$xd3,$xd2
	vpshufd		\$0xff,$xd3,$xd3
	vpaddd		.Lincz(%rip),$xd0,$xd0	# don't save counters yet
	vmovdqa64	$xd0,@key[12]
	vmovdqa64	$xd1,@key[13]
	vmovdqa64	$xd2,@key[14]
	vmovdqa64	$xd3,@key[15]

	mov		\$10,%eax
	jmp		.Loop16x

.align	32
.Loop_outer16x:
	vpbroadcastd	0(%r10),$xa0		# reload key
	vpbroadcastd	4(%r10),$xa1
	vpbroadcastd	8(%r10),$xa2
	vpbroadcastd	12(%r10),$xa3
	vpaddd		.Lsixteen(%rip),@key[12],@key[12]	# next SIMD counters
	vmovdqa64	@key[4],$xb0
	vmovdqa64	@key[5],$xb1
	vmovdqa64	@key[6],$xb2
	vmovdqa64	@key[7],$xb3
	vmovdqa64	@key[8],$xc0
	vmovdqa64	@key[9],$xc1
	vmovdqa64	@key[10],$xc2
	vmovdqa64	@key[11],$xc3
	vmovdqa64	@key[12],$xd0
	vmovdqa64	@key[13],$xd1
	vmovdqa64	@key[14],$xd2
	vmovdqa64	@key[15],$xd3

	vmovdqa64	$xa0,@key[0]
	vmovdqa64	$xa1,@key[1]
	vmovdqa64	$xa2,@key[2]
	vmovdqa64	$xa3,@key[3]

	mov		\$10,%eax
	jmp		.Loop16x

.align	32
.Loop16x:
___
	foreach (&AVX512_lane_ROUND(0, 4, 8,12)) { eval; }
	foreach (&AVX512_lane_ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	dec		%eax
	jnz		.Loop16x

	vpaddd		@key[0],$xa0,$xa0	# accumulate key
	vpaddd		@key[1],$xa1,$xa1
	vpaddd		@key[2],$xa2,$xa2
	vpaddd		@key[3],$xa3,$xa3

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
	($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		@key[4],$xb0,$xb0
	vpaddd		@key[5],$xb1,$xb1
	vpaddd		@key[6],$xb2,$xb2
	vpaddd		@key[7],$xb3,$xb3

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
$code.=<<___;
	vshufi32x4	\$0x44,$xb0,$xa0,$xt3	# "de-interlace" further
	vshufi32x4	\$0xee,$xb0,$xa0,$xb0
	vshufi32x4	\$0x44,$xb1,$xa1,$xa0
	vshufi32x4	\$0xee,$xb1,$xa1,$xb1
	vshufi32x4	\$0x44,$xb2,$xa2,$xa1
	vshufi32x4	\$0xee,$xb2,$xa2,$xb2
	vshufi32x4	\$0x44,$xb3,$xa3,$xa2
	vshufi32x4	\$0xee,$xb3,$xa3,$xb3
___
	($xa0,$xa1,$xa2,$xa3,$xt3)=($xt3,$xa0,$xa1,$xa2,$xa3);
$code.=<<___;
	vpaddd		@key[8],$xc0,$xc0
	vpaddd		@key[9],$xc1,$xc1
	vpaddd		@key[10],$xc2,$xc2
	vpaddd		@key[11],$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		@key[12],$xd0,$xd0
	vpaddd		@key[13],$xd1,$xd1
	vpaddd		@key[14],$xd2,$xd2
	vpaddd		@key[15],$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
$code.=<<___;
	vshufi32x4	\$0x44,$xd0,$xc0,$xt3	# "de-interlace" further
	vshufi32x4	\$0xee,$xd0,$xc0,$xd0
	vshufi32x4	\$0x44,$xd1,$xc1,$xc0
	vshufi32x4	\$0xee,$xd1,$xc1,$xd1
	vshufi32x4	\$0x44,$xd2,$xc2,$xc1
	vshufi32x4	\$0xee,$xd2,$xc2,$xd2
	vshufi32x4	\$0x44,$xd3,$xc3,$xc2
	vshufi32x4	\$0xee,$xd3,$xc3,$xd3
___
	($xc0,$xc1,$xc2,$xc3,$xt3)=($xt3,$xc0,$xc1,$xc2,$xc3);
$code.=<<___;
	vshufi32x4	\$0x88,$xc0,$xa0,$xt0	# "de-interlace" further
	vshufi32x4	\$0xdd,$xc0,$xa0,$xa0
	 vshufi32x4	\$0x88,$xd0,$xb0,$xc0
	 vshufi32x4	\$0xdd,$xd0,$xb0,$xd0
	vshufi32x4	\$0x88,$xc1,$xa1,$xt1
	vshufi32x4	\$0xdd,$xc1,$xa1,$xa1
	 vshufi32x4	\$0x88,$xd1,$xb1,$xc1
	 vshufi32x4	\$0xdd,$xd1,$xb1,$xd1
	vshufi32x4	\$0x88,$xc2,$xa2,$xt2
	vshufi32x4	\$0xdd,$xc2,$xa2,$xa2
	 vshufi32x4	\$0x88,$xd2,$xb2,$xc2
	 vshufi32x4	\$0xdd,$xd2,$xb2,$xd2
	vshufi32x4	\$0x88,$xc3,$xa3,$xt3
	vshufi32x4	\$0xdd,$xc3,$xa3,$xa3
	 vshufi32x4	\$0x88,$xd3,$xb3,$xc3
	 vshufi32x4	\$0xdd,$xd3,$xb3,$xd3
___
	($xa0,$xa1,$xa2,$xa3,$xb0,$xb1,$xb2,$xb3)=
	($xt0,$xt1,$xt2,$xt3,$xa0,$xa1,$xa2,$xa3);

	($xa0,$xb0,$xc0,$xd0, $xa1,$xb1,$xc1,$xd1,
	 $xa2,$xb2,$xc2,$xd2, $xa3,$xb3,$xc3,$xd3) =
	($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	 $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3);
$code.=<<___;
	cmpq		\$-1,64(%rsp)
	je		.Ldata_tail16x
	cmpq		\$0,64(%rsp)
	jne		.Lkey_tail16x
.Ldata_tail16x:
	cmp		\$64*16,$len
	jb		.Ltail16x

	vpxord		0x00($inp),$xa0,$xa0	# xor with input
	vpxord		0x40($inp),$xb0,$xb0
	vpxord		0x80($inp),$xc0,$xc0
	vpxord		0xc0($inp),$xd0,$xd0
	vmovdqu32	$xa0,0x00($out)
	vmovdqu32	$xb0,0x40($out)
	vmovdqu32	$xc0,0x80($out)
	vmovdqu32	$xd0,0xc0($out)

	vpxord		0x100($inp),$xa1,$xa1
	vpxord		0x140($inp),$xb1,$xb1
	vpxord		0x180($inp),$xc1,$xc1
	vpxord		0x1c0($inp),$xd1,$xd1
	vmovdqu32	$xa1,0x100($out)
	vmovdqu32	$xb1,0x140($out)
	vmovdqu32	$xc1,0x180($out)
	vmovdqu32	$xd1,0x1c0($out)

	vpxord		0x200($inp),$xa2,$xa2
	vpxord		0x240($inp),$xb2,$xb2
	vpxord		0x280($inp),$xc2,$xc2
	vpxord		0x2c0($inp),$xd2,$xd2
	vmovdqu32	$xa2,0x200($out)
	vmovdqu32	$xb2,0x240($out)
	vmovdqu32	$xc2,0x280($out)
	vmovdqu32	$xd2,0x2c0($out)

	vpxord		0x300($inp),$xa3,$xa3
	vpxord		0x340($inp),$xb3,$xb3
	vpxord		0x380($inp),$xc3,$xc3
	vpxord		0x3c0($inp),$xd3,$xd3
	lea		0x400($inp),$inp
	vmovdqu32	$xa3,0x300($out)
	vmovdqu32	$xb3,0x340($out)
	vmovdqu32	$xc3,0x380($out)
	vmovdqu32	$xd3,0x3c0($out)
	lea		0x400($out),$out

	sub		\$64*16,$len
	jz		.Ldone16x

	# The terminal seal entry consumes one complete 16-state range. A residue
	# of at most four blocks changes representation in-frame; larger residues
	# retain the four-chain 16-state schedule.
	cmpq		\$-1,64(%rsp)
	jne		.Loop_outer16x
	addl		\$16,0($counter)
	cmp		\$256,$len
	jbe		.Lavx512_body
	jmp		.Loop_outer16x


.align	32
.Lkey_tail16x:
	mov		64(%rsp),%r11
___
	(my $ya0=$xa0)=~s/zmm/ymm/;
$code.=<<___;
	vmovdqu32	$ya0,(%r11)		# r || s from counter zero
	sub		\$64,$len
	test		$len,$len
	jz		.Ldone16x
	xor		%r10,%r10
	sub		$inp,$out
___
	my @key_data_blocks=($xb0,$xc0,$xd0,
	                     $xa1,$xb1,$xc1,$xd1,
	                     $xa2,$xb2,$xc2,$xd2,
	                     $xa3,$xb3,$xc3,$xd3);
	for my $i (0..$#key_data_blocks) {
		my $v=$key_data_blocks[$i];
		$code.=sprintf("\tcmp\t\t\$64*%d,$len\n",$i+1);
		$code.="\tjb\t\t.Lkey_less64_16x_$i\n";
		$code.="\tvpxord\t\t($inp),$v,$v\n";
		$code.="\tvmovdqu32\t$v,($out,$inp)\n";
		$code.="\tje\t\t.Ldone16x\n";
		$code.="\tlea\t\t64($inp),$inp\n";
	}
	for my $i (0..$#key_data_blocks) {
		my $v=$key_data_blocks[$i];
		$code.=".Lkey_less64_16x_$i:\n";
		$code.="\tvmovdqa32\t$v,0(%rsp)\n";
		$code.="\tjmp\t\t.Lkey_less64_16x\n";
	}
$code.=<<___;
.Lkey_less64_16x:
	lea		($out,$inp),$out
	and		\$63,$len
.Lkey_byte_loop16x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Lkey_byte_loop16x
	jmp		.Ldone16x

.align	32
.Ltail16x:
	xor		%r10,%r10
	sub		$inp,$out
	cmp		\$64*1,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xa0,$xa0	# xor with input
	vmovdqu32	$xa0,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xb0,$xa0
	lea		64($inp),$inp

	cmp		\$64*2,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xb0,$xb0
	vmovdqu32	$xb0,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xc0,$xa0
	lea		64($inp),$inp

	cmp		\$64*3,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xc0,$xc0
	vmovdqu32	$xc0,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xd0,$xa0
	lea		64($inp),$inp

	cmp		\$64*4,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xd0,$xd0
	vmovdqu32	$xd0,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xa1,$xa0
	lea		64($inp),$inp

	cmp		\$64*5,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xa1,$xa1
	vmovdqu32	$xa1,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xb1,$xa0
	lea		64($inp),$inp

	cmp		\$64*6,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xb1,$xb1
	vmovdqu32	$xb1,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xc1,$xa0
	lea		64($inp),$inp

	cmp		\$64*7,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xc1,$xc1
	vmovdqu32	$xc1,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xd1,$xa0
	lea		64($inp),$inp

	cmp		\$64*8,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xd1,$xd1
	vmovdqu32	$xd1,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xa2,$xa0
	lea		64($inp),$inp

	cmp		\$64*9,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xa2,$xa2
	vmovdqu32	$xa2,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xb2,$xa0
	lea		64($inp),$inp

	cmp		\$64*10,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xb2,$xb2
	vmovdqu32	$xb2,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xc2,$xa0
	lea		64($inp),$inp

	cmp		\$64*11,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xc2,$xc2
	vmovdqu32	$xc2,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xd2,$xa0
	lea		64($inp),$inp

	cmp		\$64*12,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xd2,$xd2
	vmovdqu32	$xd2,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xa3,$xa0
	lea		64($inp),$inp

	cmp		\$64*13,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xa3,$xa3
	vmovdqu32	$xa3,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xb3,$xa0
	lea		64($inp),$inp

	cmp		\$64*14,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xb3,$xb3
	vmovdqu32	$xb3,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xc3,$xa0
	lea		64($inp),$inp

	cmp		\$64*15,$len
	jb		.Less_than_64_16x
	vpxord		($inp),$xc3,$xc3
	vmovdqu32	$xc3,($out,$inp)
	je		.Ldone16x
	vmovdqa32	$xd3,$xa0
	lea		64($inp),$inp

.Less_than_64_16x:
	vmovdqa32	$xa0,0x00(%rsp)
	lea		($out,$inp),$out
	and		\$63,$len

.Loop_tail16x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail16x

	vpxord		$xa0,$xa0,$xa0
	vmovdqa32	$xa0,0(%rsp)

.Ldone16x:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L16x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_16x,.-ChaCha20_16x
.size	ChaCha20_16x_tiered,.-ChaCha20_16x_tiered
___

########################################################################
# ChaCha20_32x -- two interleaved 16-block instances, 2048 bytes a pass.


{
my @sA = map("%zmm$_",(0..15));		# instance A state, by word index
my @sB = map("%zmm$_",(16..31));	# instance B state, by word index

my @COL  = ([0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15]);
my @DIAG = ([0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14]);

# One quarter-round as twelve separate steps, so the caller can interleave
# them with the other seven chains rather than emitting them back to back.
sub QR32 {
my ($x,$q) = @_;
my ($a,$b,$c,$d) = @{$x}[@$q];
	return ["vpaddd\t\t$b,$a,$a", "vpxord\t\t$a,$d,$d", "vprold\t\t\$16,$d,$d",
		"vpaddd\t\t$d,$c,$c", "vpxord\t\t$c,$b,$b", "vprold\t\t\$12,$b,$b",
		"vpaddd\t\t$b,$a,$a", "vpxord\t\t$a,$d,$d", "vprold\t\t\$8,$d,$d",
		"vpaddd\t\t$d,$c,$c", "vpxord\t\t$c,$b,$b", "vprold\t\t\$7,$b,$b"];
}

# A column or diagonal phase of both instances, emitted step-major: all eight
# chains issue step 1, then all eight issue step 2, and so on.  The phase
# boundary is a real barrier -- the diagonal round reads what the column round
# wrote -- so the interleaving has to be inside a phase, not across one.
sub PHASE32 {
my ($xa,$xb,$quads) = @_;
my @ch = ((map { QR32($xa,$_) } @$quads), (map { QR32($xb,$_) } @$quads));
my $c = "";
	for my $s (0..11) { $c .= "\t$_->[$s]\n" foreach (@ch); }
	return $c;
}

# 16x16 dword transpose, three levels, using register renaming so it needs
# exactly two scratch registers instead of the four ChaCha20_16x spends.
# $x is clobbered; returns the sixteen registers in block order.
sub AVX512_TRANSPOSE_16 {
my ($x,$free) = @_;
my $c = "";
	# Level 1: 4x4 dword transpose inside each group of four words.  Consumes
	# both scratch registers and hands two different ones back.
	for my $g (0..3) {
		my ($p,$q,$r,$s) = @{$x}[4*$g..4*$g+3];
		my ($t2,$t3) = @$free;
		$c .= <<___;
	vpunpckldq	$q,$p,$t2
	vpunpckldq	$s,$r,$t3
	vpunpckhdq	$q,$p,$p
	vpunpckhdq	$s,$r,$r
	vpunpcklqdq	$t3,$t2,$q
	vpunpckhqdq	$t3,$t2,$t2
	vpunpcklqdq	$r,$p,$s
	vpunpckhqdq	$r,$p,$p
___
		@{$x}[4*$g..4*$g+3] = ($q,$t2,$s,$p);
		@$free = ($t3,$r);
	}
	# Level 2: 128-bit lanes, group 0 with group 1 and group 2 with group 3.
	# Each pair is two-in two-out, so one scratch register rotates through.
	for my $base (0,8) {
		for my $i (0..3) {
			my ($a,$b) = ($x->[$base+$i], $x->[$base+4+$i]);
			my $t = shift @$free;
			$c .= "\tvshufi32x4\t\$0x44,$b,$a,$t\n";
			$c .= "\tvshufi32x4\t\$0xee,$b,$a,$b\n";
			$x->[$base+$i] = $t;
			push @$free, $a;
		}
	}
	# Level 3: the surviving 128-bit crossing, same rotation.
	my @out;
	for my $i (0..3) {
		foreach my $pair ([0,8],[4,12]) {
			my ($a,$e) = ($x->[$pair->[0]+$i], $x->[$pair->[1]+$i]);
			my $t = shift @$free;
			$c .= "\tvshufi32x4\t\$0x88,$e,$a,$t\n";
			$c .= "\tvshufi32x4\t\$0xdd,$e,$a,$a\n";
			push @out, $t, $a;
			push @$free, $e;
		}
	}
	@$x = @out;
	return $c;
}

# Frame.  $SPILL holds the two words borrowed from instance B; $ST is the
# original state as sixteen dwords, which is what the embedded broadcasts
# read; $CTRA/$CTRB are the two counter vectors, the only lane-varying word;
# $CTRT is a private counter block for the tail call, so the caller's is
# never written.
my ($SPILL,$ST,$CTRA,$CTRB,$CTRT) = (0,128,192,256,320);
my $frame32 = 384;
my $x32frame = $win64 ? 0xa8 : 8;

$code.=<<___;
.globl	ChaCha20_32x
.type	ChaCha20_32x,\@function,5
.align	32
ChaCha20_32x:
.cfi_startproc
	cmp		\$2048,$len
	jb		.LChaCha20_16x
	push		%rbp
.cfi_push	%rbp
	mov		%rsp,%rbp
.cfi_def_cfa_register	%rbp
	sub		\$$frame32+$x32frame,%rsp
	and		\$-64,%rsp
___
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%rbp)
	movaps		%xmm7,-0x98(%rbp)
	movaps		%xmm8,-0x88(%rbp)
	movaps		%xmm9,-0x78(%rbp)
	movaps		%xmm10,-0x68(%rbp)
	movaps		%xmm11,-0x58(%rbp)
	movaps		%xmm12,-0x48(%rbp)
	movaps		%xmm13,-0x38(%rbp)
	movaps		%xmm14,-0x28(%rbp)
	movaps		%xmm15,-0x18(%rbp)
.L32x_body:
___
$code.=<<___;
	vzeroupper

	lea		.Lsigma(%rip),%r10
	vmovdqu		(%r10),%xmm0		# sigma
	vmovdqu		($key),%xmm1		# key low
	vmovdqu		16($key),%xmm2		# key high
	vmovdqu		($counter),%xmm3	# counter || nonce
	vmovdqa		%xmm0,$ST+0(%rsp)
	vmovdqa		%xmm1,$ST+16(%rsp)
	vmovdqa		%xmm2,$ST+32(%rsp)
	vmovdqa		%xmm3,$ST+48(%rsp)
	vmovdqu		%xmm3,$CTRT(%rsp)	# private counter for the tail

	vpbroadcastd	$ST+48(%rsp),%zmm0
	vpaddd		.Lincz(%rip),%zmm0,%zmm0
	vmovdqa64	%zmm0,$CTRA(%rsp)
	vpaddd		.Lsixteen(%rip),%zmm0,%zmm0
	vmovdqa64	%zmm0,$CTRB(%rsp)

.align	32
.Loop_outer32x:
___
	# Re-materialise both states.  Thirty broadcasts and two vector loads
	# per 2048 bytes, against 1920 round instructions.
	for my $w (0..15) {
		next if ($w == 12);
		$code .= "\tvpbroadcastd\t".($ST+4*$w)."(%rsp),$sA[$w]\n";
		$code .= "\tvpbroadcastd\t".($ST+4*$w)."(%rsp),$sB[$w]\n";
	}
$code.=<<___;
	vmovdqa64	$CTRA(%rsp),$sA[12]
	vmovdqa64	$CTRB(%rsp),$sB[12]
	mov		\$10,%eax

.align	32
.Loop32x:
___
	$code .= PHASE32(\@sA,\@sB,\@COL);
	$code .= PHASE32(\@sA,\@sB,\@DIAG);
$code.=<<___;
	dec		%eax
	jnz		.Loop32x

	vmovdqa64	$sB[14],$SPILL+0(%rsp)	# lend instance A its two scratch
	vmovdqa64	$sB[15],$SPILL+64(%rsp)	# registers; A has none of its own
___
	# Instance A: final add from the stack image, transpose, xor, store.
	my @xa = @sA;
	my @fa = ($sB[14],$sB[15]);
	for my $w (0..15) {
		$code .= ($w == 12)
			? "\tvpaddd\t\t$CTRA(%rsp),$xa[$w],$xa[$w]\n"
			: "\tvpaddd\t\t".($ST+4*$w)."(%rsp)\{1to16\},$xa[$w],$xa[$w]\n";
	}
	$code .= AVX512_TRANSPOSE_16(\@xa,\@fa);
	for my $b (0..15) {
		my $r = $xa[4*($b%4) + int($b/4)];
		$code .= "\tvpxord\t\t".(64*$b)."($inp),$r,$r\n";
		$code .= "\tvmovdqu64\t$r,".(64*$b)."($out)\n";
	}
$code.=<<___;
	vmovdqa64	$SPILL+0(%rsp),$sB[14]
	vmovdqa64	$SPILL+64(%rsp),$sB[15]
___
	# Instance B: A's sixteen registers are free now, so no spill is needed.
	my @xb = @sB;
	my @fb = ($sA[0],$sA[1]);
	for my $w (0..15) {
		$code .= ($w == 12)
			? "\tvpaddd\t\t$CTRB(%rsp),$xb[$w],$xb[$w]\n"
			: "\tvpaddd\t\t".($ST+4*$w)."(%rsp)\{1to16\},$xb[$w],$xb[$w]\n";
	}
	$code .= AVX512_TRANSPOSE_16(\@xb,\@fb);
	for my $b (0..15) {
		my $r = $xb[4*($b%4) + int($b/4)];
		$code .= "\tvpxord\t\t".(1024+64*$b)."($inp),$r,$r\n";
		$code .= "\tvmovdqu64\t$r,".(1024+64*$b)."($out)\n";
	}
$code.=<<___;
	lea		2048($inp),$inp
	lea		2048($out),$out
	addl		\$32,$CTRT(%rsp)
	sub		\$2048,$len

	vmovdqa64	$CTRA(%rsp),$sA[1]
	vmovdqa64	$CTRB(%rsp),$sA[2]
	vpaddd		.Lthirtytwo(%rip),$sA[1],$sA[1]
	vpaddd		.Lthirtytwo(%rip),$sA[2],$sA[2]
	vmovdqa64	$sA[1],$CTRA(%rsp)
	vmovdqa64	$sA[2],$CTRB(%rsp)

	cmp		\$2048,$len
	jae		.Loop_outer32x

	test		$len,$len
	jz		.Ldone32x
	lea		$CTRT(%rsp),$counter	# never touch the caller's block
	vzeroupper
	mov		OPENSSL_ia32cap_P+8(%rip),%r10d
	test		\$0x80000000,%r10d	# AVX512VL
	jz		.Ltail32x_wide
	call		ChaCha20_tail_avx512
	jmp		.Ldone32x
.Ltail32x_wide:
	call		ChaCha20_16x
.Ldone32x:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%rbp),%xmm6
	movaps		-0x98(%rbp),%xmm7
	movaps		-0x88(%rbp),%xmm8
	movaps		-0x78(%rbp),%xmm9
	movaps		-0x68(%rbp),%xmm10
	movaps		-0x58(%rbp),%xmm11
	movaps		-0x48(%rbp),%xmm12
	movaps		-0x38(%rbp),%xmm13
	movaps		-0x28(%rbp),%xmm14
	movaps		-0x18(%rbp),%xmm15
___
$code.=<<___;
	mov		%rbp,%rsp
	pop		%rbp
.cfi_def_cfa	%rsp,8
.L32x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_32x,.-ChaCha20_32x
___
}

########################################################################
# ChaCha20_33x_key -- one dispatch for a whole small message.


{
my @vA = map("%zmm$_",(0..15));		# vector instance A, by word index
my @vB = map("%zmm$_",(16..31));	# vector instance B, by word index
my @COL  = ([0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15]);
my @DIAG = ([0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14]);

# Frame.  $ST doubles as the scalar block's initial state: its word 12 is the
# base counter, which is exactly the Poly1305 key block's counter.
# PHASE32 hands back joined text for ChaCha20_32x; the weave needs the
# instructions one at a time so scalar work can be interleaved between them.
sub PHASE32L {
my ($xa,$xb,$quads) = @_;
my @ch = ((map { QR32($xa,$_) } @$quads), (map { QR32($xb,$_) } @$quads));
my @o;
	for my $s (0..11) { push @o, $_->[$s] foreach (@ch); }
	return @o;
}

my ($SPILL,$ST,$CTRA,$CTRB,$SCB,$STAGE) = (0,128,192,256,320,384);
my ($RC,$SAVED,$OUT,$INP,$LEN,$PK,$SCR) = (448,456,464,472,480,488,496);
my $frame33 = 512;
my ($SCB40,$SCB44) = ($SCB+40,$SCB+44);

$code.=<<___;
.globl	ChaCha20_33x_key
.type	ChaCha20_33x_key,\@function,6
.align	32
ChaCha20_33x_key:
.cfi_startproc
	push		%rbx
.cfi_push	%rbx
	push		%rbp
.cfi_push	%rbp
	push		%r12
.cfi_push	%r12
	push		%r13
.cfi_push	%r13
	push		%r14
.cfi_push	%r14
	push		%r15
.cfi_push	%r15
	mov		%rsp,%rax
	sub		\$$frame33,%rsp
	and		\$-64,%rsp
	vzeroupper

	mov		%rax,$SAVED(%rsp)
	mov		$out,$OUT(%rsp)
	mov		$inp,$INP(%rsp)
	mov		$len,$LEN(%rsp)
	mov		%r9,$PK(%rsp)		# Poly1305 key destination

	lea		.Lsigma(%rip),%r10
	vmovdqu		(%r10),%xmm0
	vmovdqu		($key),%xmm1
	vmovdqu		16($key),%xmm2
	vmovdqu		($counter),%xmm3	# counter || nonce, counter = key block
	vmovdqa		%xmm0,$ST+0(%rsp)
	vmovdqa		%xmm1,$ST+16(%rsp)
	vmovdqa		%xmm2,$ST+32(%rsp)
	vmovdqa		%xmm3,$ST+48(%rsp)

	# Payload counters are base+1..base+32; base+0 is the key block and is the
	# scalar block's job.
	mov		$ST+48(%rsp),%eax
	add		\$1,%eax
	mov		%eax,$SCR(%rsp)
	vpbroadcastd	$SCR(%rsp),%zmm0
	vpaddd		.Lincz(%rip),%zmm0,%zmm0
	vmovdqa64	%zmm0,$CTRA(%rsp)
	vpaddd		.Lsixteen(%rip),%zmm0,%zmm0
	vmovdqa64	%zmm0,$CTRB(%rsp)
___
	# Vector state.  Fifteen of the sixteen words are lane-invariant, so they
	# are broadcast back out of the stack image; only the counter is a vector.
	for my $w (0..15) {
		next if ($w == 12);
		$code .= "\tvpbroadcastd\t".($ST+4*$w)."(%rsp),$vA[$w]\n";
		$code .= "\tvpbroadcastd\t".($ST+4*$w)."(%rsp),$vB[$w]\n";
	}
$code.=<<___;
	vmovdqa64	$CTRA(%rsp),$vA[12]
	vmovdqa64	$CTRB(%rsp),$vB[12]

	# Scalar block state, in the register map SCALAR_ROUND expects: words 8..11
	# live in memory at $SCB+32..$SCB+47, with words 8 and 9 also held in the
	# rotating %esi/%edi pair that the round's c-swap cycles through.
	mov		$ST+0(%rsp),%eax
	mov		$ST+4(%rsp),%ebx
	mov		$ST+8(%rsp),%ecx
	mov		$ST+12(%rsp),%edx
	mov		$ST+16(%rsp),%r8d
	mov		$ST+20(%rsp),%r10d
	mov		$ST+24(%rsp),%r11d
	mov		$ST+28(%rsp),%ebp
	mov		$ST+32(%rsp),%esi
	mov		$ST+36(%rsp),%edi
	mov		$ST+40(%rsp),%r12d
	mov		%r12d,$SCB40(%rsp)
	mov		$ST+44(%rsp),%r13d
	mov		%r13d,$SCB44(%rsp)
	mov		$ST+48(%rsp),%r12d
	mov		$ST+52(%rsp),%r13d
	mov		$ST+56(%rsp),%r14d
	mov		$ST+60(%rsp),%r15d
	movl		\$10,$RC(%rsp)

.align	32
.Loop33x:
___
	{
	my @v = (PHASE32L(\@vA,\@vB,\@COL), PHASE32L(\@vA,\@vB,\@DIAG));
	my @s = (&SCALAR_ROUND($SCB, 0, 4, 8,12), &SCALAR_ROUND($SCB, 0, 5,10,15));
	# The vector stream is emitted as text, the scalar stream as perlasm
	# thunks; weave the two and eval only the thunks.
	my @w = &HYBRID_WEAVE(\@v,\@s,$hybchunk);
	foreach (@w) { if (/^&/) { eval; } else { $code .= "\t$_\n"; } }
	}
$code.=<<___;
	subl		\$1,$RC(%rsp)
	jnz		.Loop33x

	# Poly1305 key: only words 0..7 of the scalar block are wanted (r || s),
	# so eight adds against the untouched initial state and eight stores.
	mov		$PK(%rsp),%r9
	add		$ST+0(%rsp),%eax
	add		$ST+4(%rsp),%ebx
	add		$ST+8(%rsp),%ecx
	add		$ST+12(%rsp),%edx
	add		$ST+16(%rsp),%r8d
	add		$ST+20(%rsp),%r10d
	add		$ST+24(%rsp),%r11d
	add		$ST+28(%rsp),%ebp
	mov		%eax,0(%r9)
	mov		%ebx,4(%r9)
	mov		%ecx,8(%r9)
	mov		%edx,12(%r9)
	mov		%r8d,16(%r9)
	mov		%r10d,20(%r9)
	mov		%r11d,24(%r9)
	mov		%ebp,28(%r9)

	vmovdqa64	$vB[14],$SPILL+0(%rsp)	# two scratch registers for A's
	vmovdqa64	$vB[15],$SPILL+64(%rsp)	# transpose, borrowed from B
___
	my @xa = @vA;
	my @fa = ($vB[14],$vB[15]);
	for my $w (0..15) {
		$code .= ($w == 12)
			? "\tvpaddd\t\t$CTRA(%rsp),$xa[$w],$xa[$w]\n"
			: "\tvpaddd\t\t".($ST+4*$w)."(%rsp)\{1to16\},$xa[$w],$xa[$w]\n";
	}
	$code .= AVX512_TRANSPOSE_16(\@xa,\@fa);

	# Block j of an instance lands in slot 4*(j%4)+j/4.  A's blocks must be
	# stored before B's transpose runs, because B's only scratch is A's
	# registers -- same ordering ChaCha20_32x uses, and the reason only one
	# instance ever pays for a spill.
	my @blkA = map { $xa[4*($_%4) + int($_/4)] } (0..15);
$code.=<<___;
	mov		$OUT(%rsp),$out
	mov		$INP(%rsp),$inp
	mov		$LEN(%rsp),$len
___
	for my $j (0..15) {
		$code .= "\tcmp\t\t\$".(64*($j+1)).",$len\n";
		$code .= "\tjb\t\t.Lless64_33x_$j\n";
		$code .= "\tvpxord\t\t".(64*$j)."($inp),$blkA[$j],$blkA[$j]\n";
		$code .= "\tvmovdqu64\t$blkA[$j],".(64*$j)."($out)\n";
		$code .= "\tje\t\t.Ldone33x\n";
	}
$code.=<<___;
	vmovdqa64	$SPILL+0(%rsp),$vB[14]
	vmovdqa64	$SPILL+64(%rsp),$vB[15]
___
	my @xb = @vB;
	my @fb = ($vA[0],$vA[1]);	# free now: A's blocks are in memory
	for my $w (0..15) {
		$code .= ($w == 12)
			? "\tvpaddd\t\t$CTRB(%rsp),$xb[$w],$xb[$w]\n"
			: "\tvpaddd\t\t".($ST+4*$w)."(%rsp)\{1to16\},$xb[$w],$xb[$w]\n";
	}
	$code .= AVX512_TRANSPOSE_16(\@xb,\@fb);
	my @blkB = map { $xb[4*($_%4) + int($_/4)] } (0..15);
	for my $j (16..31) {
		my $v = $blkB[$j-16];
		$code .= "\tcmp\t\t\$".(64*($j+1)).",$len\n";
		$code .= "\tjb\t\t.Lless64_33x_$j\n";
		$code .= "\tvpxord\t\t".(64*$j)."($inp),$v,$v\n";
		$code .= "\tvmovdqu64\t$v,".(64*$j)."($out)\n";
		$code .= "\tje\t\t.Ldone33x\n";
	}
$code.=<<___;
	jmp		.Ldone33x
___
	my @blk = (@blkA, @blkB);
	for my $j (0..31) {
		$code .= ".Lless64_33x_$j:\n";
		$code .= "\tvmovdqa64\t$blk[$j],$STAGE(%rsp)\n";
		$code .= "\tlea\t\t".(64*$j)."($inp),$inp\n";
		$code .= "\tlea\t\t".(64*$j)."($out),$out\n";
		$code .= "\tjmp\t\t.Ltail33x\n";
	}
$code.=<<___;
.Ltail33x:
	and		\$63,$len
	jz		.Ldone33x
	xor		%r10,%r10
.Loop_tail33x:
	movzb		($inp,%r10),%eax
	movzb		$STAGE(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail33x

.Ldone33x:
	vzeroall
	mov		$SAVED(%rsp),%rsp
	pop		%r15
.cfi_pop	%r15
	pop		%r14
.cfi_pop	%r14
	pop		%r13
.cfi_pop	%r13
	pop		%r12
.cfi_pop	%r12
	pop		%rbp
.cfi_pop	%rbp
	pop		%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	ChaCha20_33x_key,.-ChaCha20_33x_key
___
}

########################################################################
# ChaCha20_25x_key -- 16+8 key kernel (1536 bytes)
{
my @vA = map("%zmm$_",(0..15));		# 16-lane instance, blocks 0..15
my @vB = map("%ymm$_",(16..31));	#  8-lane instance, blocks 16..23
my @COL  = ([0,4,8,12],[1,5,9,13],[2,6,10,14],[3,7,11,15]);
my @DIAG = ([0,5,10,15],[1,6,11,12],[2,7,8,13],[3,4,9,14]);

# Same twelve steps as QR32; the width is carried by the register names.
sub QRW {
my ($x,$q) = @_;
my ($a,$b,$c,$d) = @{$x}[@$q];
	return ["vpaddd\t\t$b,$a,$a", "vpxord\t\t$a,$d,$d", "vprold\t\t\$16,$d,$d",
		"vpaddd\t\t$d,$c,$c", "vpxord\t\t$c,$b,$b", "vprold\t\t\$12,$b,$b",
		"vpaddd\t\t$b,$a,$a", "vpxord\t\t$a,$d,$d", "vprold\t\t\$8,$d,$d",
		"vpaddd\t\t$d,$c,$c", "vpxord\t\t$c,$b,$b", "vprold\t\t\$7,$b,$b"];
}
sub PHASE25L {
my ($xa,$xb,$quads) = @_;
my @ch = ((map { QRW($xa,$_) } @$quads), (map { QRW($xb,$_) } @$quads));
my @o;
	for my $s (0..11) { push @o, $_->[$s] foreach (@ch); }
	return @o;
}

# 8-lane transpose.  Two 128-bit lanes rather than four, so it is one level
# shallower than the 16-lane form, and it lands each block as a pair: block b
# is out[b] (low 32 bytes) then out[8+b] (high 32 bytes).  Needs two scratch
# registers, same renaming trick as AVX512_TRANSPOSE_16.
sub AVX512_TRANSPOSE_8 {
my ($x,$free) = @_;
my $c = "";
	for my $g (0..3) {
		my ($p,$q,$r,$s) = @{$x}[4*$g..4*$g+3];
		my ($t2,$t3) = @$free;
		$c .= <<___;
	vpunpckldq	$q,$p,$t2
	vpunpckldq	$s,$r,$t3
	vpunpckhdq	$q,$p,$p
	vpunpckhdq	$s,$r,$r
	vpunpcklqdq	$t3,$t2,$q
	vpunpckhqdq	$t3,$t2,$t2
	vpunpcklqdq	$r,$p,$s
	vpunpckhqdq	$r,$p,$p
___
		@{$x}[4*$g..4*$g+3] = ($q,$t2,$s,$p);
		@$free = ($t3,$r);
	}
	my @out;
	for my $i (0..3) {
		foreach my $pair ([0,4],[8,12]) {
			my ($a,$e) = ($x->[$pair->[0]+$i], $x->[$pair->[1]+$i]);
			my $t = shift @$free;
			$c .= "\tvshufi32x4\t\$0x00,$e,$a,$t\n";
			$c .= "\tvshufi32x4\t\$0x03,$e,$a,$a\n";
			push @out, [$pair->[0] ? 8 : 0, $i, $t, $a];
			push @$free, $e;
		}
	}
	# out entries are (half, i, lo, hi): lo covers blocks i and i+4's half.
	my @o = (undef) x 16;
	foreach my $e (@out) {
		my ($half,$i,$lo,$hi) = @$e;
		$o[$half + $i] = $lo;
		$o[$half + $i + 4] = $hi;
	}
	@$x = @o;
	return $c;
}

my ($SPILL,$ST,$CTRA,$CTRB,$SCB,$STAGE) = (0,128,192,256,320,384);
my ($RC,$SAVED,$OUT,$INP,$LEN,$PK,$SCR) = (448,456,464,472,480,488,496);
my $frame25 = 512;
my ($SCB40,$SCB44) = ($SCB+40,$SCB+44);

$code.=<<___;
.globl	ChaCha20_25x_key
.type	ChaCha20_25x_key,\@function,6
.align	32
ChaCha20_25x_key:
.cfi_startproc
	push		%rbx
.cfi_push	%rbx
	push		%rbp
.cfi_push	%rbp
	push		%r12
.cfi_push	%r12
	push		%r13
.cfi_push	%r13
	push		%r14
.cfi_push	%r14
	push		%r15
.cfi_push	%r15
	mov		%rsp,%rax
	sub		\$$frame25,%rsp
	and		\$-64,%rsp
	vzeroupper

	mov		%rax,$SAVED(%rsp)
	mov		$out,$OUT(%rsp)
	mov		$inp,$INP(%rsp)
	mov		$len,$LEN(%rsp)
	mov		%r9,$PK(%rsp)

	lea		.Lsigma(%rip),%r10
	vmovdqu		(%r10),%xmm0
	vmovdqu		($key),%xmm1
	vmovdqu		16($key),%xmm2
	vmovdqu		($counter),%xmm3
	vmovdqa		%xmm0,$ST+0(%rsp)
	vmovdqa		%xmm1,$ST+16(%rsp)
	vmovdqa		%xmm2,$ST+32(%rsp)
	vmovdqa		%xmm3,$ST+48(%rsp)

	# Blocks 0..15 take counters base+1..base+16, blocks 16..23 take
	# base+17..base+24; base+0 is the key block and is the scalar block's.
	mov		$ST+48(%rsp),%eax
	add		\$1,%eax
	mov		%eax,$SCR(%rsp)
	vpbroadcastd	$SCR(%rsp),%zmm0
	vpaddd		.Lincz(%rip),%zmm0,%zmm0
	vmovdqa64	%zmm0,$CTRA(%rsp)
	vpaddd		.Lsixteen(%rip),%zmm0,%zmm0
	vmovdqa		%ymm0,$CTRB(%rsp)
___
	for my $w (0..15) {
		next if ($w == 12);
		$code .= "\tvpbroadcastd\t".($ST+4*$w)."(%rsp),$vA[$w]\n";
		$code .= "\tvpbroadcastd\t".($ST+4*$w)."(%rsp),$vB[$w]\n";
	}
$code.=<<___;
	vmovdqa64	$CTRA(%rsp),$vA[12]
	vmovdqa64	$CTRB(%rsp),$vB[12]

	mov		$ST+0(%rsp),%eax
	mov		$ST+4(%rsp),%ebx
	mov		$ST+8(%rsp),%ecx
	mov		$ST+12(%rsp),%edx
	mov		$ST+16(%rsp),%r8d
	mov		$ST+20(%rsp),%r10d
	mov		$ST+24(%rsp),%r11d
	mov		$ST+28(%rsp),%ebp
	mov		$ST+32(%rsp),%esi
	mov		$ST+36(%rsp),%edi
	mov		$ST+40(%rsp),%r12d
	mov		%r12d,$SCB40(%rsp)
	mov		$ST+44(%rsp),%r13d
	mov		%r13d,$SCB44(%rsp)
	mov		$ST+48(%rsp),%r12d
	mov		$ST+52(%rsp),%r13d
	mov		$ST+56(%rsp),%r14d
	mov		$ST+60(%rsp),%r15d
	movl		\$10,$RC(%rsp)

.align	32
.Loop25x:
___
	{
	my @v = (PHASE25L(\@vA,\@vB,\@COL), PHASE25L(\@vA,\@vB,\@DIAG));
	my @s = (&SCALAR_ROUND($SCB, 0, 4, 8,12), &SCALAR_ROUND($SCB, 0, 5,10,15));
	my @w = &HYBRID_WEAVE(\@v,\@s,$hybchunk);
	foreach (@w) { if (/^&/) { eval; } else { $code .= "\t$_\n"; } }
	}
$code.=<<___;
	subl		\$1,$RC(%rsp)
	jnz		.Loop25x

	mov		$PK(%rsp),%r9
	add		$ST+0(%rsp),%eax
	add		$ST+4(%rsp),%ebx
	add		$ST+8(%rsp),%ecx
	add		$ST+12(%rsp),%edx
	add		$ST+16(%rsp),%r8d
	add		$ST+20(%rsp),%r10d
	add		$ST+24(%rsp),%r11d
	add		$ST+28(%rsp),%ebp
	mov		%eax,0(%r9)
	mov		%ebx,4(%r9)
	mov		%ecx,8(%r9)
	mov		%edx,12(%r9)
	mov		%r8d,16(%r9)
	mov		%r10d,20(%r9)
	mov		%r11d,24(%r9)
	mov		%ebp,28(%r9)

	# A's transpose needs two full zmm; borrow zmm16/zmm17, whose low halves
	# are B's ymm16/ymm17, and hand them back before B's own output.
	vmovdqa64	$vB[0],$SPILL+0(%rsp)
	vmovdqa64	$vB[1],$SPILL+32(%rsp)
___
	my @xa = @vA;
	my @fa = ("%zmm16","%zmm17");
	for my $w (0..15) {
		$code .= ($w == 12)
			? "\tvpaddd\t\t$CTRA(%rsp),$xa[$w],$xa[$w]\n"
			: "\tvpaddd\t\t".($ST+4*$w)."(%rsp)\{1to16\},$xa[$w],$xa[$w]\n";
	}
	$code .= AVX512_TRANSPOSE_16(\@xa,\@fa);
	my @blkA = map { $xa[4*($_%4) + int($_/4)] } (0..15);
$code.=<<___;
	mov		$OUT(%rsp),$out
	mov		$INP(%rsp),$inp
	mov		$LEN(%rsp),$len
___
	for my $j (0..15) {
		$code .= "\tcmp\t\t\$".(64*($j+1)).",$len\n";
		$code .= "\tjb\t\t.Lless64_25x_$j\n";
		$code .= "\tvpxord\t\t".(64*$j)."($inp),$blkA[$j],$blkA[$j]\n";
		$code .= "\tvmovdqu64\t$blkA[$j],".(64*$j)."($out)\n";
		$code .= "\tje\t\t.Ldone25x\n";
	}
$code.=<<___;
	vmovdqa64	$SPILL+0(%rsp),$vB[0]
	vmovdqa64	$SPILL+32(%rsp),$vB[1]
___
	my @xb = @vB;
	my @fb = ("%ymm0","%ymm1");	# free now: A's blocks are in memory
	for my $w (0..15) {
		$code .= ($w == 12)
			? "\tvpaddd\t\t$CTRB(%rsp),$xb[$w],$xb[$w]\n"
			: "\tvpaddd\t\t".($ST+4*$w)."(%rsp)\{1to8\},$xb[$w],$xb[$w]\n";
	}
	$code .= AVX512_TRANSPOSE_8(\@xb,\@fb);
	# Block 16+b is the pair (low half $xb[$b], high half $xb[8+$b]).
	for my $b (0..7) {
		my $j = 16 + $b;
		my ($lo,$hi) = ($xb[$b], $xb[8+$b]);
		$code .= "\tcmp\t\t\$".(64*($j+1)).",$len\n";
		$code .= "\tjb\t\t.Lless64_25x_$j\n";
		$code .= "\tvpxord\t\t".(64*$j)."($inp),$lo,$lo\n";
		$code .= "\tvpxord\t\t".(64*$j+32)."($inp),$hi,$hi\n";
		$code .= "\tvmovdqu64\t$lo,".(64*$j)."($out)\n";
		$code .= "\tvmovdqu64\t$hi,".(64*$j+32)."($out)\n";
		$code .= "\tje\t\t.Ldone25x\n";
	}
$code.=<<___;
	jmp		.Ldone25x
___
	for my $j (0..15) {
		$code .= ".Lless64_25x_$j:\n";
		$code .= "\tvmovdqa64\t$blkA[$j],$STAGE(%rsp)\n";
		$code .= "\tlea\t\t".(64*$j)."($inp),$inp\n";
		$code .= "\tlea\t\t".(64*$j)."($out),$out\n";
		$code .= "\tjmp\t\t.Ltail25x\n";
	}
	for my $b (0..7) {
		my $j = 16 + $b;
		$code .= ".Lless64_25x_$j:\n";
		$code .= "\tvmovdqa64\t$xb[$b],$STAGE(%rsp)\n";
		$code .= "\tvmovdqa64\t$xb[8+$b],".($STAGE+32)."(%rsp)\n";
		$code .= "\tlea\t\t".(64*$j)."($inp),$inp\n";
		$code .= "\tlea\t\t".(64*$j)."($out),$out\n";
		$code .= "\tjmp\t\t.Ltail25x\n";
	}
$code.=<<___;
.Ltail25x:
	and		\$63,$len
	jz		.Ldone25x
	xor		%r10,%r10
.Loop_tail25x:
	movzb		($inp,%r10),%eax
	movzb		$STAGE(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail25x

.Ldone25x:
	vzeroall
	mov		$SAVED(%rsp),%rsp
	pop		%r15
.cfi_pop	%r15
	pop		%r14
.cfi_pop	%r14
	pop		%r13
.cfi_pop	%r13
	pop		%r12
.cfi_pop	%r12
	pop		%rbp
.cfi_pop	%rbp
	pop		%rbx
.cfi_pop	%rbx
	ret
.cfi_endproc
.size	ChaCha20_25x_key,.-ChaCha20_25x_key
___
}
($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3, $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3)=map("%zmm$_",(0..15));
@xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3, $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3);
@key=map("%zmm$_",(16..31));
($xt0,$xt1,$xt2,$xt3)=@key[0..3];
$code.=<<___;
.globl	ChaCha20_17x_key
.type	ChaCha20_17x_key,\@function,6
.align	32
ChaCha20_17x_key:
	mov		%r9,%rax		# poly-key output / mode marker
	jmp		.LChaCha20_17x_common

.globl	ChaCha20_17x
.type	ChaCha20_17x,\@function,5
.align	32
ChaCha20_17x:
.cfi_startproc
.LChaCha20_17x:
	# A vector pass is saved only where the 1088-byte batches cross fewer
	# 1024-byte boundaries than stock. With q = (len-1)/1024, that fails exactly
	# when len >= 1088*q + 65 -- 15 intervals, none above 15360. The 65 is the
	# in-frame scalar remainder: a single leftover block costs no vector pass.
	lea		-1(%rdx),%rax
	shr		\$10,%rax		# q
	imul		\$1088,%rax,%rax
	add		\$65,%rax
	cmp		%rax,%rdx
	jae		.LChaCha20_16x
	xor		%eax,%eax		# normal data-only entry
.LChaCha20_17x_common:
	push		%rbx
.cfi_push	%rbx
	push		%rbp
.cfi_push	%rbp
	push		%r12
.cfi_push	%r12
	push		%r13
.cfi_push	%r13
	push		%r14
.cfi_push	%r14
	push		%r15
.cfi_push	%r15
	mov		%rsp,%r9		# frame register
.cfi_def_cfa_register	%r9
	sub		\$256+$xframe,%rsp
	and		\$-64,%rsp
	mov		%rax,224(%rsp)
___
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
.L17x_body:
___
$code.=<<___;
	vzeroupper

	vbroadcasti32x4	.Lsigma(%rip),$xa3		# key[0]
	vbroadcasti32x4	($key),$xb3		# key[1]
	vbroadcasti32x4	16($key),$xc3		# key[2]
	vbroadcasti32x4	($counter),$xd3		# key[3]
	# 17th block: build original state (counter starts at +16)
	mov		\$0x61707865,%eax
	mov		%eax,64(%rsp)
	mov		\$0x3320646e,%eax
	mov		%eax,68(%rsp)
	mov		\$0x79622d32,%eax
	mov		%eax,72(%rsp)
	mov		\$0x6b206574,%eax
	mov		%eax,76(%rsp)
	mov		0(%rcx),%eax
	mov		%eax,80(%rsp)
	mov		4(%rcx),%eax
	mov		%eax,84(%rsp)
	mov		8(%rcx),%eax
	mov		%eax,88(%rsp)
	mov		12(%rcx),%eax
	mov		%eax,92(%rsp)
	mov		16(%rcx),%eax
	mov		%eax,96(%rsp)
	mov		20(%rcx),%eax
	mov		%eax,100(%rsp)
	mov		24(%rcx),%eax
	mov		%eax,104(%rsp)
	mov		28(%rcx),%eax
	mov		%eax,108(%rsp)
	mov		0(%r8),%eax
	add		\$16,%eax
	mov		%eax,112(%rsp)
	mov		4(%r8),%eax
	mov		%eax,116(%rsp)
	mov		8(%r8),%eax
	mov		%eax,120(%rsp)
	mov		12(%r8),%eax
	mov		%eax,124(%rsp)

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	# 17th block: spill the pointers the store block needs
	vpshufd		\$0xaa,$xa3,$xa2
	mov		%rdi,200(%rsp)
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa64	$xa0,@key[0]
	mov		%rsi,208(%rsp)
	vmovdqa64	$xa1,@key[1]
	mov		%rdx,216(%rsp)
	vmovdqa64	$xa2,@key[2]
	vmovdqa64	$xa3,@key[3]
	# 17th block: load working state
	vpshufd		\$0x00,$xb3,$xb0
	mov		64(%rsp),%eax
	vpshufd		\$0x55,$xb3,$xb1
	vpshufd		\$0xaa,$xb3,$xb2
	mov		68(%rsp),%ebx
	vpshufd		\$0xff,$xb3,$xb3
	mov		72(%rsp),%ecx
	vmovdqa64	$xb0,@key[4]
	mov		76(%rsp),%edx
	vmovdqa64	$xb1,@key[5]
	vmovdqa64	$xb2,@key[6]
	mov		80(%rsp),%r8d
	vmovdqa64	$xb3,@key[7]
	mov		84(%rsp),%r10d
	vpshufd		\$0x00,$xc3,$xc0
	vpshufd		\$0x55,$xc3,$xc1
	mov		88(%rsp),%r11d
	vpshufd		\$0xaa,$xc3,$xc2
	mov		92(%rsp),%ebp
	vpshufd		\$0xff,$xc3,$xc3
	vmovdqa64	$xc0,@key[8]
	mov		96(%rsp),%esi
	vmovdqa64	$xc1,@key[9]
	mov		100(%rsp),%edi
	vmovdqa64	$xc2,@key[10]
	mov		104(%rsp),%r12d
	vmovdqa64	$xc3,@key[11]
	vpshufd		\$0x00,$xd3,$xd0
	mov		%r12d,168(%rsp)
	vpshufd		\$0x55,$xd3,$xd1
	mov		108(%rsp),%r13d
	vpshufd		\$0xaa,$xd3,$xd2
	vpshufd		\$0xff,$xd3,$xd3
	mov		%r13d,172(%rsp)
	vpaddd		.Lincz(%rip),$xd0,$xd0	# don't save counters yet
	mov		112(%rsp),%r12d
	vmovdqa64	$xd0,@key[12]
	vmovdqa64	$xd1,@key[13]
	mov		116(%rsp),%r13d
	vmovdqa64	$xd2,@key[14]
	mov		120(%rsp),%r14d
	vmovdqa64	$xd3,@key[15]
	mov		124(%rsp),%r15d
	movl		\$10,192(%rsp)
	jmp		.Loop17x

.align	32
.Loop_outer17x:
	cmp		\$64,%rdx
	jbe		.Lscalar_remainder17x
	vpbroadcastd	.Lsigma+0(%rip),$xa0		# reload key
	# 17th block: spill the pointers the store block needs
	vpbroadcastd	.Lsigma+4(%rip),$xa1
	mov		%rdi,200(%rsp)
	vpbroadcastd	.Lsigma+8(%rip),$xa2
	mov		%rsi,208(%rsp)
	vpbroadcastd	.Lsigma+12(%rip),$xa3
	mov		%rdx,216(%rsp)
	vpaddd		.Lseventeen(%rip),@key[12],@key[12]	# next SIMD counters
	# 17th block: load working state
	vmovdqa64	@key[4],$xb0
	mov		64(%rsp),%eax
	vmovdqa64	@key[5],$xb1
	mov		68(%rsp),%ebx
	vmovdqa64	@key[6],$xb2
	mov		72(%rsp),%ecx
	vmovdqa64	@key[7],$xb3
	mov		76(%rsp),%edx
	vmovdqa64	@key[8],$xc0
	mov		80(%rsp),%r8d
	vmovdqa64	@key[9],$xc1
	mov		84(%rsp),%r10d
	mov		88(%rsp),%r11d
	vmovdqa64	@key[10],$xc2
	mov		92(%rsp),%ebp
	vmovdqa64	@key[11],$xc3
	mov		96(%rsp),%esi
	vmovdqa64	@key[12],$xd0
	mov		100(%rsp),%edi
	vmovdqa64	@key[13],$xd1
	mov		104(%rsp),%r12d
	vmovdqa64	@key[14],$xd2
	mov		%r12d,168(%rsp)
	vmovdqa64	@key[15],$xd3
	mov		108(%rsp),%r13d
	vmovdqa64	$xa0,@key[0]
	mov		%r13d,172(%rsp)
	vmovdqa64	$xa1,@key[1]
	mov		112(%rsp),%r12d
	vmovdqa64	$xa2,@key[2]
	mov		116(%rsp),%r13d
	vmovdqa64	$xa3,@key[3]
	mov		120(%rsp),%r14d
	mov		124(%rsp),%r15d
	movl		\$10,192(%rsp)
	jmp		.Loop17x

.align	32
.Loop17x:
___
	{
	my @v = (&AVX512_lane_ROUND(0, 4, 8,12), &AVX512_lane_ROUND(0, 5,10,15));
	my @s = (&SCALAR_ROUND(128, 0, 4, 8,12), &SCALAR_ROUND(128, 0, 5,10,15));
	if ($hybmode eq "seq") {
		foreach (@v) { eval; }
	} else {
		foreach (&HYBRID_WEAVE(\@v,\@s,$hybchunk)) { eval; }
	}
	}
$code.=<<___;
	subl		\$1,192(%rsp)
	jnz		.Loop17x
___
if ($hybmode eq "seq") {
$code.=<<___;
	movl		\$10,196(%rsp)
.Lscalar17x:
___
	foreach (&SCALAR_ROUND(128, 0, 4, 8,12)) { eval; }
	foreach (&SCALAR_ROUND(128, 0, 5,10,15)) { eval; }
$code.=<<___;
	subl		\$1,196(%rsp)
	jnz		.Lscalar17x
___
}
$code.=<<___;

	vpaddd		@key[0],$xa0,$xa0	# accumulate key
	mov		%eax,128(%rsp)
	vpaddd		@key[1],$xa1,$xa1
	mov		%ebx,132(%rsp)
	vpaddd		@key[2],$xa2,$xa2
	mov		%ecx,136(%rsp)
	vpaddd		@key[3],$xa3,$xa3
	mov		%edx,140(%rsp)

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
	($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		@key[4],$xb0,$xb0
	mov		%r8d,144(%rsp)
	vpaddd		@key[5],$xb1,$xb1
	mov		%r10d,148(%rsp)
	vpaddd		@key[6],$xb2,$xb2
	mov		%r11d,152(%rsp)
	vpaddd		@key[7],$xb3,$xb3
	mov		%ebp,156(%rsp)

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
$code.=<<___;
	vshufi32x4	\$0x44,$xb0,$xa0,$xt3	# "de-interlace" further
	vshufi32x4	\$0xee,$xb0,$xa0,$xb0
	vshufi32x4	\$0x44,$xb1,$xa1,$xa0
	vshufi32x4	\$0xee,$xb1,$xa1,$xb1
	vshufi32x4	\$0x44,$xb2,$xa2,$xa1
	vshufi32x4	\$0xee,$xb2,$xa2,$xb2
	vshufi32x4	\$0x44,$xb3,$xa3,$xa2
	vshufi32x4	\$0xee,$xb3,$xa3,$xb3
___
	($xa0,$xa1,$xa2,$xa3,$xt3)=($xt3,$xa0,$xa1,$xa2,$xa3);
$code.=<<___;
	vpaddd		@key[8],$xc0,$xc0
	mov		%r12d,176(%rsp)
	vpaddd		@key[9],$xc1,$xc1
	mov		%r13d,180(%rsp)
	vpaddd		@key[10],$xc2,$xc2
	mov		%r14d,184(%rsp)
	vpaddd		@key[11],$xc3,$xc3
	mov		%r15d,188(%rsp)

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		@key[12],$xd0,$xd0
	mov		%esi,160(%rsp)
	vpaddd		@key[13],$xd1,$xd1
	mov		%edi,164(%rsp)
	vpaddd		@key[14],$xd2,$xd2
	vpaddd		@key[15],$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
$code.=<<___;
	vshufi32x4	\$0x44,$xd0,$xc0,$xt3	# "de-interlace" further
	vshufi32x4	\$0xee,$xd0,$xc0,$xd0
	vshufi32x4	\$0x44,$xd1,$xc1,$xc0
	vshufi32x4	\$0xee,$xd1,$xc1,$xd1
	vshufi32x4	\$0x44,$xd2,$xc2,$xc1
	vshufi32x4	\$0xee,$xd2,$xc2,$xd2
	vshufi32x4	\$0x44,$xd3,$xc3,$xc2
	vshufi32x4	\$0xee,$xd3,$xc3,$xd3
___
	($xc0,$xc1,$xc2,$xc3,$xt3)=($xt3,$xc0,$xc1,$xc2,$xc3);
$code.=<<___;
	vshufi32x4	\$0x88,$xc0,$xa0,$xt0	# "de-interlace" further
	vshufi32x4	\$0xdd,$xc0,$xa0,$xa0
	 vshufi32x4	\$0x88,$xd0,$xb0,$xc0
	 vshufi32x4	\$0xdd,$xd0,$xb0,$xd0
	vshufi32x4	\$0x88,$xc1,$xa1,$xt1
	vshufi32x4	\$0xdd,$xc1,$xa1,$xa1
	 vshufi32x4	\$0x88,$xd1,$xb1,$xc1
	 vshufi32x4	\$0xdd,$xd1,$xb1,$xd1
	vshufi32x4	\$0x88,$xc2,$xa2,$xt2
	vshufi32x4	\$0xdd,$xc2,$xa2,$xa2
	 vshufi32x4	\$0x88,$xd2,$xb2,$xc2
	 vshufi32x4	\$0xdd,$xd2,$xb2,$xd2
	vshufi32x4	\$0x88,$xc3,$xa3,$xt3
	vshufi32x4	\$0xdd,$xc3,$xa3,$xa3
	 vshufi32x4	\$0x88,$xd3,$xb3,$xc3
	 vshufi32x4	\$0xdd,$xd3,$xb3,$xd3
___
	($xa0,$xa1,$xa2,$xa3,$xb0,$xb1,$xb2,$xb3)=
	($xt0,$xt1,$xt2,$xt3,$xa0,$xa1,$xa2,$xa3);

	($xa0,$xb0,$xc0,$xd0, $xa1,$xb1,$xc1,$xd1,
	 $xa2,$xb2,$xc2,$xd2, $xa3,$xb3,$xc3,$xd3) =
	($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
	 $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3);
$code.=<<___;
	mov		200(%rsp),%rdi
	mov		208(%rsp),%rsi
	mov		216(%rsp),%rdx
	cmpq		\$0,224(%rsp)
	jne		.Lkey_tail17x
	cmp		\$64*16,$len
	jb		.Ltail17x

	vpxord		0x00($inp),$xa0,$xa0	# xor with input
	vpxord		0x40($inp),$xb0,$xb0
	vpxord		0x80($inp),$xc0,$xc0
	vpxord		0xc0($inp),$xd0,$xd0
	vmovdqu32	$xa0,0x00($out)
	vmovdqu32	$xb0,0x40($out)
	vmovdqu32	$xc0,0x80($out)
	vmovdqu32	$xd0,0xc0($out)

	vpxord		0x100($inp),$xa1,$xa1
	vpxord		0x140($inp),$xb1,$xb1
	vpxord		0x180($inp),$xc1,$xc1
	vpxord		0x1c0($inp),$xd1,$xd1
	vmovdqu32	$xa1,0x100($out)
	vmovdqu32	$xb1,0x140($out)
	vmovdqu32	$xc1,0x180($out)
	vmovdqu32	$xd1,0x1c0($out)

	vpxord		0x200($inp),$xa2,$xa2
	vpxord		0x240($inp),$xb2,$xb2
	vpxord		0x280($inp),$xc2,$xc2
	vpxord		0x2c0($inp),$xd2,$xd2
	vmovdqu32	$xa2,0x200($out)
	vmovdqu32	$xb2,0x240($out)
	vmovdqu32	$xc2,0x280($out)
	vmovdqu32	$xd2,0x2c0($out)

	vpxord		0x300($inp),$xa3,$xa3
	vpxord		0x340($inp),$xb3,$xb3
	vpxord		0x380($inp),$xc3,$xc3
	vpxord		0x3c0($inp),$xd3,$xd3
	lea		0x400($inp),$inp
	vmovdqu32	$xa3,0x300($out)
	vmovdqu32	$xb3,0x340($out)
	vmovdqu32	$xc3,0x380($out)
	vmovdqu32	$xd3,0x3c0($out)
	lea		0x400($out),$out

	sub		\$64*16,$len
	jz		.Ldone17x
	cmp		\$64,$len
	jb		.Lscalar_tail17x
	# 17th block: add state, xor, store (one zmm)
	vmovdqa64	128(%rsp),%zmm0
	vpaddd		64(%rsp),%zmm0,%zmm0
	vpxord		0x00(%rsi),%zmm0,%zmm0
	vmovdqu32	%zmm0,0x00(%rdi)
	lea		0x40(%rsi),%rsi
	lea		0x40(%rdi),%rdi
	addl		\$17,112(%rsp)		# block 17 counter += 17
	sub		\$64,$len
	jnz		.Loop_outer17x
	jmp		.Ldone17x

.align	32
.Lkey_tail17x:
	mov		224(%rsp),%r11
___
	(my $ykey0=$xa0)=~s/zmm/ymm/;
$code.=<<___;
	vmovdqu32	$ykey0,(%r11)		# r || s from counter zero
	test		$len,$len
	jz		.Ldone17x
	xor		%r10,%r10
	sub		$inp,$out
___
	my @key17_data_blocks=($xb0,$xc0,$xd0,
	                       $xa1,$xb1,$xc1,$xd1,
	                       $xa2,$xb2,$xc2,$xd2,
	                       $xa3,$xb3,$xc3,$xd3);
	for my $i (0..$#key17_data_blocks) {
		my $v=$key17_data_blocks[$i];
		$code.=sprintf("\tcmp\t\t\$64*%d,$len\n",$i+1);
		$code.="\tjb\t\t.Lkey_less64_17x_$i\n";
		$code.="\tvpxord\t\t($inp),$v,$v\n";
		$code.="\tvmovdqu32\t$v,($out,$inp)\n";
		$code.="\tje\t\t.Ldone17x\n";
		$code.="\tlea\t\t64($inp),$inp\n";
	}
$code.=<<___;
	# Scalar counter-16 block is the sixteenth data block.
	vmovdqa64	128(%rsp),%zmm0
	vpaddd		64(%rsp),%zmm0,%zmm0
	cmp		\$1024,$len
	jb		.Lkey_less64_17x_15
	vpxord		($inp),%zmm0,%zmm0
	vmovdqu32	%zmm0,($out,$inp)
	jmp		.Ldone17x
___
	for my $i (0..$#key17_data_blocks) {
		my $v=$key17_data_blocks[$i];
		$code.=".Lkey_less64_17x_$i:\n";
		$code.="\tvmovdqa32\t$v,0(%rsp)\n";
		$code.="\tjmp\t\t.Lkey_less64_17x\n";
	}
$code.=<<___;
.Lkey_less64_17x_15:
	vmovdqa64	%zmm0,0(%rsp)
.Lkey_less64_17x:
	lea		($out,$inp),$out
	and		\$63,$len
.Lkey_byte_loop17x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Lkey_byte_loop17x
	jmp		.Ldone17x

.Lscalar_remainder17x:
	subl		\$16,112(%rsp)
	# 17th block: spill the pointers the store block needs
	mov		%rdi,200(%rsp)
	mov		%rsi,208(%rsp)
	mov		%rdx,216(%rsp)
	# 17th block: load working state
	mov		64(%rsp),%eax
	mov		68(%rsp),%ebx
	mov		72(%rsp),%ecx
	mov		76(%rsp),%edx
	mov		80(%rsp),%r8d
	mov		84(%rsp),%r10d
	mov		88(%rsp),%r11d
	mov		92(%rsp),%ebp
	mov		96(%rsp),%esi
	mov		100(%rsp),%edi
	mov		104(%rsp),%r12d
	mov		%r12d,168(%rsp)
	mov		108(%rsp),%r13d
	mov		%r13d,172(%rsp)
	mov		112(%rsp),%r12d
	mov		116(%rsp),%r13d
	mov		120(%rsp),%r14d
	mov		124(%rsp),%r15d
	movl		\$10,196(%rsp)
.Lscalar_remainder_rounds17x:
___
	foreach (&SCALAR_ROUND(128, 0, 4, 8,12)) { eval; }
	foreach (&SCALAR_ROUND(128, 0, 5,10,15)) { eval; }
$code.=<<___;
	subl		\$1,196(%rsp)
	jnz		.Lscalar_remainder_rounds17x
	# 17th block: park working state, restore vector pointers
	mov		%eax,128(%rsp)
	mov		%ebx,132(%rsp)
	mov		%ecx,136(%rsp)
	mov		%edx,140(%rsp)
	mov		%r8d,144(%rsp)
	mov		%r10d,148(%rsp)
	mov		%r11d,152(%rsp)
	mov		%ebp,156(%rsp)
	mov		%r12d,176(%rsp)
	mov		%r13d,180(%rsp)
	mov		%r14d,184(%rsp)
	mov		%r15d,188(%rsp)
	mov		%esi,160(%rsp)
	mov		%edi,164(%rsp)
	mov		200(%rsp),%rdi
	mov		208(%rsp),%rsi
	mov		216(%rsp),%rdx
	cmp		\$64,%rdx
	jb		.Lscalar_remainder_partial17x
	# 17th block: add state, xor, store (one zmm)
	vmovdqa64	128(%rsp),%zmm0
	vpaddd		64(%rsp),%zmm0,%zmm0
	vpxord		0x00(%rsi),%zmm0,%zmm0
	vmovdqu32	%zmm0,0x00(%rdi)
	lea		0x40(%rsi),%rsi
	lea		0x40(%rdi),%rdi
	addl		\$17,112(%rsp)		# block 17 counter += 17
	jmp		.Ldone17x
.Lscalar_remainder_partial17x:
	# 17th block: spill keystream for a partial tail
	vmovdqa64	128(%rsp),%zmm0
	vpaddd		64(%rsp),%zmm0,%zmm0
	vmovdqa64	%zmm0,0x00(%rsp)
	xor		%r10,%r10
	jmp		.Loop_tail17x

.Lscalar_tail17x:
	# 17th block: spill keystream for a partial tail
	vmovdqa64	128(%rsp),%zmm0
	vpaddd		64(%rsp),%zmm0,%zmm0
	vmovdqa64	%zmm0,0x00(%rsp)
	xor		%r10,%r10
	jmp		.Loop_tail17x

.align	32
.Ltail17x:
	xor		%r10,%r10
	sub		$inp,$out
	cmp		\$64*1,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xa0,$xa0	# xor with input
	vmovdqu32	$xa0,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xb0,$xa0
	lea		64($inp),$inp

	cmp		\$64*2,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xb0,$xb0
	vmovdqu32	$xb0,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xc0,$xa0
	lea		64($inp),$inp

	cmp		\$64*3,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xc0,$xc0
	vmovdqu32	$xc0,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xd0,$xa0
	lea		64($inp),$inp

	cmp		\$64*4,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xd0,$xd0
	vmovdqu32	$xd0,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xa1,$xa0
	lea		64($inp),$inp

	cmp		\$64*5,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xa1,$xa1
	vmovdqu32	$xa1,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xb1,$xa0
	lea		64($inp),$inp

	cmp		\$64*6,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xb1,$xb1
	vmovdqu32	$xb1,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xc1,$xa0
	lea		64($inp),$inp

	cmp		\$64*7,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xc1,$xc1
	vmovdqu32	$xc1,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xd1,$xa0
	lea		64($inp),$inp

	cmp		\$64*8,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xd1,$xd1
	vmovdqu32	$xd1,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xa2,$xa0
	lea		64($inp),$inp

	cmp		\$64*9,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xa2,$xa2
	vmovdqu32	$xa2,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xb2,$xa0
	lea		64($inp),$inp

	cmp		\$64*10,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xb2,$xb2
	vmovdqu32	$xb2,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xc2,$xa0
	lea		64($inp),$inp

	cmp		\$64*11,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xc2,$xc2
	vmovdqu32	$xc2,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xd2,$xa0
	lea		64($inp),$inp

	cmp		\$64*12,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xd2,$xd2
	vmovdqu32	$xd2,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xa3,$xa0
	lea		64($inp),$inp

	cmp		\$64*13,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xa3,$xa3
	vmovdqu32	$xa3,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xb3,$xa0
	lea		64($inp),$inp

	cmp		\$64*14,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xb3,$xb3
	vmovdqu32	$xb3,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xc3,$xa0
	lea		64($inp),$inp

	cmp		\$64*15,$len
	jb		.Less_than_64_17x
	vpxord		($inp),$xc3,$xc3
	vmovdqu32	$xc3,($out,$inp)
	je		.Ldone17x
	vmovdqa32	$xd3,$xa0
	lea		64($inp),$inp

.Less_than_64_17x:
	vmovdqa32	$xa0,0x00(%rsp)
	lea		($out,$inp),$out
	and		\$63,$len

.Loop_tail17x:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail17x

	vpxord		$xa0,$xa0,$xa0
	vmovdqa32	$xa0,0(%rsp)

.Ldone17x:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
	pop		%r15
.cfi_pop	%r15
	pop		%r14
.cfi_pop	%r14
	pop		%r13
.cfi_pop	%r13
	pop		%r12
.cfi_pop	%r12
	pop		%rbp
.cfi_pop	%rbp
	pop		%rbx
.cfi_pop	%rbx
.L17x_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_17x,.-ChaCha20_17x
.size	ChaCha20_17x_key,.-ChaCha20_17x_key
___

# switch to %ymm domain
($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
 $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3)=map("%ymm$_",(0..15));
@xx=($xa0,$xa1,$xa2,$xa3, $xb0,$xb1,$xb2,$xb3,
     $xc0,$xc1,$xc2,$xc3, $xd0,$xd1,$xd2,$xd3);
@key=map("%ymm$_",(16..31));
($xt0,$xt1,$xt2,$xt3)=@key[0..3];

$code.=<<___;
.globl	ChaCha20_8xvl
.type	ChaCha20_8xvl,\@function,5
.align	32
ChaCha20_8xvl:
.cfi_startproc
.LChaCha20_8xvl:
	mov		%rsp,%r9		# frame register
.cfi_def_cfa_register	%r9
	sub		\$64+$xframe,%rsp
	and		\$-64,%rsp
___
$code.=<<___	if ($win64);
	movaps		%xmm6,-0xa8(%r9)
	movaps		%xmm7,-0x98(%r9)
	movaps		%xmm8,-0x88(%r9)
	movaps		%xmm9,-0x78(%r9)
	movaps		%xmm10,-0x68(%r9)
	movaps		%xmm11,-0x58(%r9)
	movaps		%xmm12,-0x48(%r9)
	movaps		%xmm13,-0x38(%r9)
	movaps		%xmm14,-0x28(%r9)
	movaps		%xmm15,-0x18(%r9)
___
$code.=".L8xvl_body:\n";
$code.=<<___;
	vzeroupper

	lea		.Lsigma(%rip),%r10
	vbroadcasti128	(%r10),$xa3		# key[0]
	vbroadcasti128	($key),$xb3		# key[1]
	vbroadcasti128	16($key),$xc3		# key[2]
	vbroadcasti128	($counter),$xd3		# key[3]

	vpshufd		\$0x00,$xa3,$xa0	# smash key by lanes...
	vpshufd		\$0x55,$xa3,$xa1
	vpshufd		\$0xaa,$xa3,$xa2
	vpshufd		\$0xff,$xa3,$xa3
	vmovdqa64	$xa0,@key[0]
	vmovdqa64	$xa1,@key[1]
	vmovdqa64	$xa2,@key[2]
	vmovdqa64	$xa3,@key[3]

	vpshufd		\$0x00,$xb3,$xb0
	vpshufd		\$0x55,$xb3,$xb1
	vpshufd		\$0xaa,$xb3,$xb2
	vpshufd		\$0xff,$xb3,$xb3
	vmovdqa64	$xb0,@key[4]
	vmovdqa64	$xb1,@key[5]
	vmovdqa64	$xb2,@key[6]
	vmovdqa64	$xb3,@key[7]

	vpshufd		\$0x00,$xc3,$xc0
	vpshufd		\$0x55,$xc3,$xc1
	vpshufd		\$0xaa,$xc3,$xc2
	vpshufd		\$0xff,$xc3,$xc3
	vmovdqa64	$xc0,@key[8]
	vmovdqa64	$xc1,@key[9]
	vmovdqa64	$xc2,@key[10]
	vmovdqa64	$xc3,@key[11]

	vpshufd		\$0x00,$xd3,$xd0
	vpshufd		\$0x55,$xd3,$xd1
	vpshufd		\$0xaa,$xd3,$xd2
	vpshufd		\$0xff,$xd3,$xd3
	vpaddd		.Lincy(%rip),$xd0,$xd0	# don't save counters yet
	vmovdqa64	$xd0,@key[12]
	vmovdqa64	$xd1,@key[13]
	vmovdqa64	$xd2,@key[14]
	vmovdqa64	$xd3,@key[15]

	mov		\$10,%eax
	jmp		.Loop8xvl

.align	32
.Loop_outer8xvl:
	#vpbroadcastd	0(%r10),$xa0		# reload key
	#vpbroadcastd	4(%r10),$xa1
	vpbroadcastd	8(%r10),$xa2
	vpbroadcastd	12(%r10),$xa3
	vpaddd		.Leight(%rip),@key[12],@key[12]	# next SIMD counters
	vmovdqa64	@key[4],$xb0
	vmovdqa64	@key[5],$xb1
	vmovdqa64	@key[6],$xb2
	vmovdqa64	@key[7],$xb3
	vmovdqa64	@key[8],$xc0
	vmovdqa64	@key[9],$xc1
	vmovdqa64	@key[10],$xc2
	vmovdqa64	@key[11],$xc3
	vmovdqa64	@key[12],$xd0
	vmovdqa64	@key[13],$xd1
	vmovdqa64	@key[14],$xd2
	vmovdqa64	@key[15],$xd3

	vmovdqa64	$xa0,@key[0]
	vmovdqa64	$xa1,@key[1]
	vmovdqa64	$xa2,@key[2]
	vmovdqa64	$xa3,@key[3]

	mov		\$10,%eax
	jmp		.Loop8xvl

.align	32
.Loop8xvl:
___
	foreach (&AVX512_lane_ROUND(0, 4, 8,12)) { eval; }
	foreach (&AVX512_lane_ROUND(0, 5,10,15)) { eval; }
$code.=<<___;
	dec		%eax
	jnz		.Loop8xvl

	vpaddd		@key[0],$xa0,$xa0	# accumulate key
	vpaddd		@key[1],$xa1,$xa1
	vpaddd		@key[2],$xa2,$xa2
	vpaddd		@key[3],$xa3,$xa3

	vpunpckldq	$xa1,$xa0,$xt2		# "de-interlace" data
	vpunpckldq	$xa3,$xa2,$xt3
	vpunpckhdq	$xa1,$xa0,$xa0
	vpunpckhdq	$xa3,$xa2,$xa2
	vpunpcklqdq	$xt3,$xt2,$xa1		# "a0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "a1"
	vpunpcklqdq	$xa2,$xa0,$xa3		# "a2"
	vpunpckhqdq	$xa2,$xa0,$xa0		# "a3"
___
	($xa0,$xa1,$xa2,$xa3,$xt2)=($xa1,$xt2,$xa3,$xa0,$xa2);
$code.=<<___;
	vpaddd		@key[4],$xb0,$xb0
	vpaddd		@key[5],$xb1,$xb1
	vpaddd		@key[6],$xb2,$xb2
	vpaddd		@key[7],$xb3,$xb3

	vpunpckldq	$xb1,$xb0,$xt2
	vpunpckldq	$xb3,$xb2,$xt3
	vpunpckhdq	$xb1,$xb0,$xb0
	vpunpckhdq	$xb3,$xb2,$xb2
	vpunpcklqdq	$xt3,$xt2,$xb1		# "b0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "b1"
	vpunpcklqdq	$xb2,$xb0,$xb3		# "b2"
	vpunpckhqdq	$xb2,$xb0,$xb0		# "b3"
___
	($xb0,$xb1,$xb2,$xb3,$xt2)=($xb1,$xt2,$xb3,$xb0,$xb2);
$code.=<<___;
	vshufi32x4	\$0,$xb0,$xa0,$xt3	# "de-interlace" further
	vshufi32x4	\$3,$xb0,$xa0,$xb0
	vshufi32x4	\$0,$xb1,$xa1,$xa0
	vshufi32x4	\$3,$xb1,$xa1,$xb1
	vshufi32x4	\$0,$xb2,$xa2,$xa1
	vshufi32x4	\$3,$xb2,$xa2,$xb2
	vshufi32x4	\$0,$xb3,$xa3,$xa2
	vshufi32x4	\$3,$xb3,$xa3,$xb3
___
	($xa0,$xa1,$xa2,$xa3,$xt3)=($xt3,$xa0,$xa1,$xa2,$xa3);
$code.=<<___;
	vpaddd		@key[8],$xc0,$xc0
	vpaddd		@key[9],$xc1,$xc1
	vpaddd		@key[10],$xc2,$xc2
	vpaddd		@key[11],$xc3,$xc3

	vpunpckldq	$xc1,$xc0,$xt2
	vpunpckldq	$xc3,$xc2,$xt3
	vpunpckhdq	$xc1,$xc0,$xc0
	vpunpckhdq	$xc3,$xc2,$xc2
	vpunpcklqdq	$xt3,$xt2,$xc1		# "c0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "c1"
	vpunpcklqdq	$xc2,$xc0,$xc3		# "c2"
	vpunpckhqdq	$xc2,$xc0,$xc0		# "c3"
___
	($xc0,$xc1,$xc2,$xc3,$xt2)=($xc1,$xt2,$xc3,$xc0,$xc2);
$code.=<<___;
	vpaddd		@key[12],$xd0,$xd0
	vpaddd		@key[13],$xd1,$xd1
	vpaddd		@key[14],$xd2,$xd2
	vpaddd		@key[15],$xd3,$xd3

	vpunpckldq	$xd1,$xd0,$xt2
	vpunpckldq	$xd3,$xd2,$xt3
	vpunpckhdq	$xd1,$xd0,$xd0
	vpunpckhdq	$xd3,$xd2,$xd2
	vpunpcklqdq	$xt3,$xt2,$xd1		# "d0"
	vpunpckhqdq	$xt3,$xt2,$xt2		# "d1"
	vpunpcklqdq	$xd2,$xd0,$xd3		# "d2"
	vpunpckhqdq	$xd2,$xd0,$xd0		# "d3"
___
	($xd0,$xd1,$xd2,$xd3,$xt2)=($xd1,$xt2,$xd3,$xd0,$xd2);
$code.=<<___;
	vperm2i128	\$0x20,$xd0,$xc0,$xt3	# "de-interlace" further
	vperm2i128	\$0x31,$xd0,$xc0,$xd0
	vperm2i128	\$0x20,$xd1,$xc1,$xc0
	vperm2i128	\$0x31,$xd1,$xc1,$xd1
	vperm2i128	\$0x20,$xd2,$xc2,$xc1
	vperm2i128	\$0x31,$xd2,$xc2,$xd2
	vperm2i128	\$0x20,$xd3,$xc3,$xc2
	vperm2i128	\$0x31,$xd3,$xc3,$xd3
___
	($xc0,$xc1,$xc2,$xc3,$xt3)=($xt3,$xc0,$xc1,$xc2,$xc3);
	($xb0,$xb1,$xb2,$xb3,$xc0,$xc1,$xc2,$xc3)=
	($xc0,$xc1,$xc2,$xc3,$xb0,$xb1,$xb2,$xb3);
$code.=<<___;
	cmp		\$64*8,$len
	jb		.Ltail8xvl

	mov		\$0x80,%eax		# size optimization
	vpxord		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vpxor		0x40($inp),$xc0,$xc0
	vpxor		0x60($inp),$xd0,$xd0
	lea		($inp,%rax),$inp	# size optimization
	vmovdqu32	$xa0,0x00($out)
	vmovdqu		$xb0,0x20($out)
	vmovdqu		$xc0,0x40($out)
	vmovdqu		$xd0,0x60($out)
	lea		($out,%rax),$out	# size optimization

	vpxor		0x00($inp),$xa1,$xa1
	vpxor		0x20($inp),$xb1,$xb1
	vpxor		0x40($inp),$xc1,$xc1
	vpxor		0x60($inp),$xd1,$xd1
	lea		($inp,%rax),$inp	# size optimization
	vmovdqu		$xa1,0x00($out)
	vmovdqu		$xb1,0x20($out)
	vmovdqu		$xc1,0x40($out)
	vmovdqu		$xd1,0x60($out)
	lea		($out,%rax),$out	# size optimization

	vpxord		0x00($inp),$xa2,$xa2
	vpxor		0x20($inp),$xb2,$xb2
	vpxor		0x40($inp),$xc2,$xc2
	vpxor		0x60($inp),$xd2,$xd2
	lea		($inp,%rax),$inp	# size optimization
	vmovdqu32	$xa2,0x00($out)
	vmovdqu		$xb2,0x20($out)
	vmovdqu		$xc2,0x40($out)
	vmovdqu		$xd2,0x60($out)
	lea		($out,%rax),$out	# size optimization

	vpxor		0x00($inp),$xa3,$xa3
	vpxor		0x20($inp),$xb3,$xb3
	vpxor		0x40($inp),$xc3,$xc3
	vpxor		0x60($inp),$xd3,$xd3
	lea		($inp,%rax),$inp	# size optimization
	vmovdqu		$xa3,0x00($out)
	vmovdqu		$xb3,0x20($out)
	vmovdqu		$xc3,0x40($out)
	vmovdqu		$xd3,0x60($out)
	lea		($out,%rax),$out	# size optimization

	vpbroadcastd	0(%r10),%ymm0		# reload key
	vpbroadcastd	4(%r10),%ymm1

	sub		\$64*8,$len
	jnz		.Loop_outer8xvl

	jmp		.Ldone8xvl

.align	32
.Ltail8xvl:
	vmovdqa64	$xa0,%ymm8		# size optimization
___
$xa0 = "%ymm8";
$code.=<<___;
	xor		%r10,%r10
	sub		$inp,$out
	cmp		\$64*1,$len
	jb		.Less_than_64_8xvl
	vpxor		0x00($inp),$xa0,$xa0	# xor with input
	vpxor		0x20($inp),$xb0,$xb0
	vmovdqu		$xa0,0x00($out,$inp)
	vmovdqu		$xb0,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa		$xc0,$xa0
	vmovdqa		$xd0,$xb0
	lea		64($inp),$inp

	cmp		\$64*2,$len
	jb		.Less_than_64_8xvl
	vpxor		0x00($inp),$xc0,$xc0
	vpxor		0x20($inp),$xd0,$xd0
	vmovdqu		$xc0,0x00($out,$inp)
	vmovdqu		$xd0,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa		$xa1,$xa0
	vmovdqa		$xb1,$xb0
	lea		64($inp),$inp

	cmp		\$64*3,$len
	jb		.Less_than_64_8xvl
	vpxor		0x00($inp),$xa1,$xa1
	vpxor		0x20($inp),$xb1,$xb1
	vmovdqu		$xa1,0x00($out,$inp)
	vmovdqu		$xb1,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa		$xc1,$xa0
	vmovdqa		$xd1,$xb0
	lea		64($inp),$inp

	cmp		\$64*4,$len
	jb		.Less_than_64_8xvl
	vpxor		0x00($inp),$xc1,$xc1
	vpxor		0x20($inp),$xd1,$xd1
	vmovdqu		$xc1,0x00($out,$inp)
	vmovdqu		$xd1,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa32	$xa2,$xa0
	vmovdqa		$xb2,$xb0
	lea		64($inp),$inp

	cmp		\$64*5,$len
	jb		.Less_than_64_8xvl
	vpxord		0x00($inp),$xa2,$xa2
	vpxor		0x20($inp),$xb2,$xb2
	vmovdqu32	$xa2,0x00($out,$inp)
	vmovdqu		$xb2,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa		$xc2,$xa0
	vmovdqa		$xd2,$xb0
	lea		64($inp),$inp

	cmp		\$64*6,$len
	jb		.Less_than_64_8xvl
	vpxor		0x00($inp),$xc2,$xc2
	vpxor		0x20($inp),$xd2,$xd2
	vmovdqu		$xc2,0x00($out,$inp)
	vmovdqu		$xd2,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa		$xa3,$xa0
	vmovdqa		$xb3,$xb0
	lea		64($inp),$inp

	cmp		\$64*7,$len
	jb		.Less_than_64_8xvl
	vpxor		0x00($inp),$xa3,$xa3
	vpxor		0x20($inp),$xb3,$xb3
	vmovdqu		$xa3,0x00($out,$inp)
	vmovdqu		$xb3,0x20($out,$inp)
	je		.Ldone8xvl
	vmovdqa		$xc3,$xa0
	vmovdqa		$xd3,$xb0
	lea		64($inp),$inp

.Less_than_64_8xvl:
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xb0,0x20(%rsp)
	lea		($out,$inp),$out
	and		\$63,$len

.Loop_tail8xvl:
	movzb		($inp,%r10),%eax
	movzb		(%rsp,%r10),%ecx
	lea		1(%r10),%r10
	xor		%ecx,%eax
	mov		%al,-1($out,%r10)
	dec		$len
	jnz		.Loop_tail8xvl

	vpxor		$xa0,$xa0,$xa0
	vmovdqa		$xa0,0x00(%rsp)
	vmovdqa		$xa0,0x20(%rsp)

.Ldone8xvl:
	vzeroall
___
$code.=<<___	if ($win64);
	movaps		-0xa8(%r9),%xmm6
	movaps		-0x98(%r9),%xmm7
	movaps		-0x88(%r9),%xmm8
	movaps		-0x78(%r9),%xmm9
	movaps		-0x68(%r9),%xmm10
	movaps		-0x58(%r9),%xmm11
	movaps		-0x48(%r9),%xmm12
	movaps		-0x38(%r9),%xmm13
	movaps		-0x28(%r9),%xmm14
	movaps		-0x18(%r9),%xmm15
___
$code.=<<___;
	lea		(%r9),%rsp
.cfi_def_cfa_register	%rsp
.L8xvl_epilogue:
	ret
.cfi_endproc
.size	ChaCha20_8xvl,.-ChaCha20_8xvl
___
}

# EXCEPTION_DISPOSITION handler (EXCEPTION_RECORD *rec,ULONG64 frame,
#		CONTEXT *context,DISPATCHER_CONTEXT *disp)
if ($win64) {
$rec="%rcx";
$frame="%rdx";
$context="%r8";
$disp="%r9";

$code.=<<___;
.extern	__imp_RtlVirtualUnwind
.type	se_handler,\@abi-omnipotent
.align	16
se_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	lea	.Lctr32_body(%rip),%r10
	cmp	%r10,%rbx		# context->Rip<.Lprologue
	jb	.Lcommon_seh_tail

	mov	152($context),%rax	# pull context->Rsp

	lea	.Lno_data(%rip),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=.Lepilogue
	jae	.Lcommon_seh_tail

	lea	64+24+48(%rax),%rax

	mov	-8(%rax),%rbx
	mov	-16(%rax),%rbp
	mov	-24(%rax),%r12
	mov	-32(%rax),%r13
	mov	-40(%rax),%r14
	mov	-48(%rax),%r15
	mov	%rbx,144($context)	# restore context->Rbx
	mov	%rbp,160($context)	# restore context->Rbp
	mov	%r12,216($context)	# restore context->R12
	mov	%r13,224($context)	# restore context->R13
	mov	%r14,232($context)	# restore context->R14
	mov	%r15,240($context)	# restore context->R14

.Lcommon_seh_tail:
	mov	8(%rax),%rdi
	mov	16(%rax),%rsi
	mov	%rax,152($context)	# restore context->Rsp
	mov	%rsi,168($context)	# restore context->Rsi
	mov	%rdi,176($context)	# restore context->Rdi

	mov	40($disp),%rdi		# disp->ContextRecord
	mov	$context,%rsi		# context
	mov	\$154,%ecx		# sizeof(CONTEXT)
	.long	0xa548f3fc		# cld; rep movsq

	mov	$disp,%rsi
	xor	%rcx,%rcx		# arg1, UNW_FLAG_NHANDLER
	mov	8(%rsi),%rdx		# arg2, disp->ImageBase
	mov	0(%rsi),%r8		# arg3, disp->ControlPc
	mov	16(%rsi),%r9		# arg4, disp->FunctionEntry
	mov	40(%rsi),%r10		# disp->ContextRecord
	lea	56(%rsi),%r11		# &disp->HandlerData
	lea	24(%rsi),%r12		# &disp->EstablisherFrame
	mov	%r10,32(%rsp)		# arg5
	mov	%r11,40(%rsp)		# arg6
	mov	%r12,48(%rsp)		# arg7
	mov	%rcx,56(%rsp)		# arg8, (NULL)
	call	*__imp_RtlVirtualUnwind(%rip)

	mov	\$1,%eax		# ExceptionContinueSearch
	add	\$64,%rsp
	popfq
	pop	%r15
	pop	%r14
	pop	%r13
	pop	%r12
	pop	%rbp
	pop	%rbx
	pop	%rdi
	pop	%rsi
	ret
.size	se_handler,.-se_handler

.type	simd_handler,\@abi-omnipotent
.align	16
simd_handler:
	push	%rsi
	push	%rdi
	push	%rbx
	push	%rbp
	push	%r12
	push	%r13
	push	%r14
	push	%r15
	pushfq
	sub	\$64,%rsp

	mov	120($context),%rax	# pull context->Rax
	mov	248($context),%rbx	# pull context->Rip

	mov	8($disp),%rsi		# disp->ImageBase
	mov	56($disp),%r11		# disp->HandlerData

	mov	0(%r11),%r10d		# HandlerData[0]
	lea	(%rsi,%r10),%r10	# prologue label
	cmp	%r10,%rbx		# context->Rip<prologue label
	jb	.Lcommon_seh_tail

	mov	192($context),%rax	# pull context->R9

	mov	4(%r11),%r10d		# HandlerData[1]
	mov	8(%r11),%ecx		# HandlerData[2]
	lea	(%rsi,%r10),%r10	# epilogue label
	cmp	%r10,%rbx		# context->Rip>=epilogue label
	jae	.Lcommon_seh_tail

	neg	%rcx
	lea	-8(%rax,%rcx),%rsi
	lea	512($context),%rdi	# &context.Xmm6
	neg	%ecx
	shr	\$3,%ecx
	.long	0xa548f3fc		# cld; rep movsq

	jmp	.Lcommon_seh_tail
.size	simd_handler,.-simd_handler

.section	.pdata
.align	4
	.rva	.LSEH_begin_ChaCha20_ctr32
	.rva	.LSEH_end_ChaCha20_ctr32
	.rva	.LSEH_info_ChaCha20_ctr32

	.rva	.LSEH_begin_ChaCha20_ssse3
	.rva	.LSEH_end_ChaCha20_ssse3
	.rva	.LSEH_info_ChaCha20_ssse3

	.rva	.LSEH_begin_ChaCha20_128
	.rva	.LSEH_end_ChaCha20_128
	.rva	.LSEH_info_ChaCha20_128

	.rva	.LSEH_begin_ChaCha20_4x
	.rva	.LSEH_end_ChaCha20_4x
	.rva	.LSEH_info_ChaCha20_4x
___
$code.=<<___ if ($avx);
	.rva	.LSEH_begin_ChaCha20_4xop
	.rva	.LSEH_end_ChaCha20_4xop
	.rva	.LSEH_info_ChaCha20_4xop
___
$code.=<<___ if ($avx>1);
	.rva	.LSEH_begin_ChaCha20_8x
	.rva	.LSEH_end_ChaCha20_8x
	.rva	.LSEH_info_ChaCha20_8x
___
$code.=<<___ if ($avx>2);
	.rva	.LSEH_begin_ChaCha20_avx512
	.rva	.LSEH_end_ChaCha20_avx512
	.rva	.LSEH_info_ChaCha20_avx512

	.rva	.LSEH_begin_ChaCha20_avx512vl
	.rva	.LSEH_end_ChaCha20_avx512vl
	.rva	.LSEH_info_ChaCha20_avx512vl

	.rva	.LSEH_begin_ChaCha20_16x
	.rva	.LSEH_end_ChaCha20_16x
	.rva	.LSEH_info_ChaCha20_16x

	.rva	.LSEH_begin_ChaCha20_8xvl
	.rva	.LSEH_end_ChaCha20_8xvl
	.rva	.LSEH_info_ChaCha20_8xvl
___
$code.=<<___;
.section	.xdata
.align	8
.LSEH_info_ChaCha20_ctr32:
	.byte	9,0,0,0
	.rva	se_handler

.LSEH_info_ChaCha20_ssse3:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.Lssse3_body,.Lssse3_epilogue
	.long	0x20,0

.LSEH_info_ChaCha20_128:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.L128_body,.L128_epilogue
	.long	0x60,0

.LSEH_info_ChaCha20_4x:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.L4x_body,.L4x_epilogue
	.long	0xa0,0
___
$code.=<<___ if ($avx);
.LSEH_info_ChaCha20_4xop:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.L4xop_body,.L4xop_epilogue		# HandlerData[]
	.long	0xa0,0
___
$code.=<<___ if ($avx>1);
.LSEH_info_ChaCha20_8x:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.L8x_body,.L8x_epilogue			# HandlerData[]
	.long	0xa0,0
___
$code.=<<___ if ($avx>2);
.LSEH_info_ChaCha20_avx512:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.Lavx512_body,.Lavx512_epilogue		# HandlerData[]
	.long	0x20,0

.LSEH_info_ChaCha20_avx512vl:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.Lavx512vl_body,.Lavx512vl_epilogue	# HandlerData[]
	.long	0x20,0

.LSEH_info_ChaCha20_16x:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.L16x_body,.L16x_epilogue		# HandlerData[]
	.long	0xa0,0

.LSEH_info_ChaCha20_8xvl:
	.byte	9,0,0,0
	.rva	simd_handler
	.rva	.L8xvl_body,.L8xvl_epilogue		# HandlerData[]
	.long	0xa0,0
___
}

foreach (split("\n",$code)) {
	s/\`([^\`]*)\`/eval $1/ge;

	s/%x#%[yz]/%x/g;	# "down-shift"

	print $_,"\n";
}

close STDOUT or die "error closing STDOUT: $!";
