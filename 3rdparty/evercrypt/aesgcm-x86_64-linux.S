.text
.global old_aes128_key_expansion
old_aes128_key_expansion:
  movdqu 0(%rdi), %xmm1
  mov %rsi, %rdx
  movdqu %xmm1, 0(%rdx)
  aeskeygenassist $1, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 16(%rdx)
  aeskeygenassist $2, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 32(%rdx)
  aeskeygenassist $4, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 48(%rdx)
  aeskeygenassist $8, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 64(%rdx)
  aeskeygenassist $16, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 80(%rdx)
  aeskeygenassist $32, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 96(%rdx)
  aeskeygenassist $64, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 112(%rdx)
  aeskeygenassist $128, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 128(%rdx)
  aeskeygenassist $27, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 144(%rdx)
  aeskeygenassist $54, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 160(%rdx)
  pxor %xmm1, %xmm1
  pxor %xmm2, %xmm2
  pxor %xmm3, %xmm3
  ret

.global aes128_key_expansion
aes128_key_expansion:
  movdqu 0(%rdi), %xmm1
  mov %rsi, %rdx
  movdqu %xmm1, 0(%rdx)
  aeskeygenassist $1, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 16(%rdx)
  aeskeygenassist $2, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 32(%rdx)
  aeskeygenassist $4, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 48(%rdx)
  aeskeygenassist $8, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 64(%rdx)
  aeskeygenassist $16, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 80(%rdx)
  aeskeygenassist $32, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 96(%rdx)
  aeskeygenassist $64, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 112(%rdx)
  aeskeygenassist $128, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 128(%rdx)
  aeskeygenassist $27, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 144(%rdx)
  aeskeygenassist $54, %xmm1, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  vpslldq $4, %xmm1, %xmm3
  pxor %xmm3, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 160(%rdx)
  pxor %xmm1, %xmm1
  pxor %xmm2, %xmm2
  pxor %xmm3, %xmm3
  ret

.global aes128_keyhash_init
aes128_keyhash_init:
  mov $579005069656919567, %r8
  pinsrq $0, %r8, %xmm4
  mov $283686952306183, %r8
  pinsrq $1, %r8, %xmm4
  pxor %xmm0, %xmm0
  movdqu %xmm0, 80(%rsi)
  mov %rdi, %r8
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm4, %xmm0
  mov %rsi, %rcx
  movdqu %xmm0, 32(%rcx)
  movdqu %xmm6, %xmm0
  mov %r12, %rax
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 0(%rcx)
  movdqu %xmm6, %xmm1
  movdqu %xmm6, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 16(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 48(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 64(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 96(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 112(%rcx)
  movdqu %xmm0, %xmm6
  mov %rax, %r12
  ret

.global old_aes256_key_expansion
old_aes256_key_expansion:
  movdqu 0(%rdi), %xmm1
  movdqu 16(%rdi), %xmm3
  mov %rsi, %rdx
  movdqu %xmm1, 0(%rdx)
  movdqu %xmm3, 16(%rdx)
  aeskeygenassist $1, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 32(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 48(%rdx)
  aeskeygenassist $2, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 64(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 80(%rdx)
  aeskeygenassist $4, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 96(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 112(%rdx)
  aeskeygenassist $8, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 128(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 144(%rdx)
  aeskeygenassist $16, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 160(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 176(%rdx)
  aeskeygenassist $32, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 192(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 208(%rdx)
  aeskeygenassist $64, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 224(%rdx)
  pxor %xmm1, %xmm1
  pxor %xmm2, %xmm2
  pxor %xmm3, %xmm3
  pxor %xmm4, %xmm4
  ret

.global aes256_key_expansion
aes256_key_expansion:
  movdqu 0(%rdi), %xmm1
  movdqu 16(%rdi), %xmm3
  mov %rsi, %rdx
  movdqu %xmm1, 0(%rdx)
  movdqu %xmm3, 16(%rdx)
  aeskeygenassist $1, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 32(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 48(%rdx)
  aeskeygenassist $2, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 64(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 80(%rdx)
  aeskeygenassist $4, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 96(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 112(%rdx)
  aeskeygenassist $8, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 128(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 144(%rdx)
  aeskeygenassist $16, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 160(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 176(%rdx)
  aeskeygenassist $32, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 192(%rdx)
  aeskeygenassist $0, %xmm1, %xmm2
  pshufd $170, %xmm2, %xmm2
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  vpslldq $4, %xmm3, %xmm4
  pxor %xmm4, %xmm3
  pxor %xmm2, %xmm3
  movdqu %xmm3, 208(%rdx)
  aeskeygenassist $64, %xmm3, %xmm2
  pshufd $255, %xmm2, %xmm2
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  vpslldq $4, %xmm1, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm2, %xmm1
  movdqu %xmm1, 224(%rdx)
  pxor %xmm1, %xmm1
  pxor %xmm2, %xmm2
  pxor %xmm3, %xmm3
  pxor %xmm4, %xmm4
  ret

.global aes256_keyhash_init
aes256_keyhash_init:
  mov $579005069656919567, %r8
  pinsrq $0, %r8, %xmm4
  mov $283686952306183, %r8
  pinsrq $1, %r8, %xmm4
  pxor %xmm0, %xmm0
  movdqu %xmm0, 80(%rsi)
  mov %rdi, %r8
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm4, %xmm0
  mov %rsi, %rcx
  movdqu %xmm0, 32(%rcx)
  movdqu %xmm6, %xmm0
  mov %r12, %rax
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 0(%rcx)
  movdqu %xmm6, %xmm1
  movdqu %xmm6, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 16(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 48(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 64(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 96(%rcx)
  movdqu %xmm6, %xmm2
  movdqu 32(%rcx), %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  movdqu %xmm1, %xmm6
  movdqu %xmm1, %xmm3
  pxor %xmm4, %xmm4
  pxor %xmm5, %xmm5
  mov $3254779904, %r12
  pinsrd $3, %r12d, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  mov $2147483648, %r12
  pinsrd $3, %r12d, %xmm5
  movdqu %xmm3, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pand %xmm5, %xmm3
  pcmpeqd %xmm5, %xmm3
  pshufd $255, %xmm3, %xmm3
  pand %xmm4, %xmm3
  vpxor %xmm3, %xmm1, %xmm1
  movdqu %xmm1, 112(%rcx)
  movdqu %xmm0, %xmm6
  mov %rax, %r12
  ret

.global gctr128_bytes
gctr128_bytes:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  movdqu 0(%r9), %xmm7
  mov %rdi, %rax
  mov %rdx, %rbx
  mov %rcx, %r13
  mov 72(%rsp), %rcx
  mov %rcx, %rbp
  imul $16, %rbp
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L0
  mov %rax, %r9
  mov %rbx, %r10
  pshufb %xmm8, %xmm7
  movdqu %xmm7, %xmm9
  mov $579005069656919567, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pshufb %xmm0, %xmm9
  movdqu %xmm9, %xmm10
  pxor %xmm3, %xmm3
  mov $1, %rax
  pinsrd $2, %eax, %xmm3
  paddd %xmm3, %xmm9
  mov $3, %rax
  pinsrd $2, %eax, %xmm3
  mov $2, %rax
  pinsrd $0, %eax, %xmm3
  paddd %xmm3, %xmm10
  pshufb %xmm8, %xmm9
  pshufb %xmm8, %xmm10
  pextrq $0, %xmm7, %rdi
  mov $283686952306183, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pxor %xmm15, %xmm15
  mov $4, %rax
  pinsrd $0, %eax, %xmm15
  mov $4, %rax
  pinsrd $2, %eax, %xmm15
  jmp L3
.balign 16
L2:
  pinsrq $0, %rdi, %xmm2
  pinsrq $0, %rdi, %xmm12
  pinsrq $0, %rdi, %xmm13
  pinsrq $0, %rdi, %xmm14
  shufpd $2, %xmm9, %xmm2
  shufpd $0, %xmm9, %xmm12
  shufpd $2, %xmm10, %xmm13
  shufpd $0, %xmm10, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  movdqu 0(%r8), %xmm3
  movdqu 16(%r8), %xmm4
  movdqu 32(%r8), %xmm5
  movdqu 48(%r8), %xmm6
  paddd %xmm15, %xmm9
  paddd %xmm15, %xmm10
  pxor %xmm3, %xmm2
  pxor %xmm3, %xmm12
  pxor %xmm3, %xmm13
  pxor %xmm3, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 64(%r8), %xmm3
  movdqu 80(%r8), %xmm4
  movdqu 96(%r8), %xmm5
  movdqu 112(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 128(%r8), %xmm3
  movdqu 144(%r8), %xmm4
  movdqu 160(%r8), %xmm5
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenclast %xmm5, %xmm2
  aesenclast %xmm5, %xmm12
  aesenclast %xmm5, %xmm13
  aesenclast %xmm5, %xmm14
  movdqu 0(%r9), %xmm7
  pxor %xmm7, %xmm2
  movdqu 16(%r9), %xmm7
  pxor %xmm7, %xmm12
  movdqu 32(%r9), %xmm7
  pxor %xmm7, %xmm13
  movdqu 48(%r9), %xmm7
  pxor %xmm7, %xmm14
  movdqu %xmm2, 0(%r10)
  movdqu %xmm12, 16(%r10)
  movdqu %xmm13, 32(%r10)
  movdqu %xmm14, 48(%r10)
  sub $1, %rdx
  add $64, %r9
  add $64, %r10
.balign 16
L3:
  cmp $0, %rdx
  ja L2
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L1
L0:
L1:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm4, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  jmp L5
.balign 16
L4:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm4, %xmm7
.balign 16
L5:
  cmp %rcx, %rdx
  jne L4
  cmp %rbp, %rsi
  jbe L6
  movdqu 0(%r13), %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r13)
  jmp L7
L6:
L7:
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global gctr256_bytes
gctr256_bytes:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  movdqu 0(%r9), %xmm7
  mov %rdi, %rax
  mov %rdx, %rbx
  mov %rcx, %r13
  mov 72(%rsp), %rcx
  mov %rcx, %rbp
  imul $16, %rbp
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L8
  mov %rax, %r9
  mov %rbx, %r10
  pshufb %xmm8, %xmm7
  movdqu %xmm7, %xmm9
  mov $579005069656919567, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pshufb %xmm0, %xmm9
  movdqu %xmm9, %xmm10
  pxor %xmm3, %xmm3
  mov $1, %rax
  pinsrd $2, %eax, %xmm3
  paddd %xmm3, %xmm9
  mov $3, %rax
  pinsrd $2, %eax, %xmm3
  mov $2, %rax
  pinsrd $0, %eax, %xmm3
  paddd %xmm3, %xmm10
  pshufb %xmm8, %xmm9
  pshufb %xmm8, %xmm10
  pextrq $0, %xmm7, %rdi
  mov $283686952306183, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pxor %xmm15, %xmm15
  mov $4, %rax
  pinsrd $0, %eax, %xmm15
  mov $4, %rax
  pinsrd $2, %eax, %xmm15
  jmp L11
.balign 16
L10:
  pinsrq $0, %rdi, %xmm2
  pinsrq $0, %rdi, %xmm12
  pinsrq $0, %rdi, %xmm13
  pinsrq $0, %rdi, %xmm14
  shufpd $2, %xmm9, %xmm2
  shufpd $0, %xmm9, %xmm12
  shufpd $2, %xmm10, %xmm13
  shufpd $0, %xmm10, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  movdqu 0(%r8), %xmm3
  movdqu 16(%r8), %xmm4
  movdqu 32(%r8), %xmm5
  movdqu 48(%r8), %xmm6
  paddd %xmm15, %xmm9
  paddd %xmm15, %xmm10
  pxor %xmm3, %xmm2
  pxor %xmm3, %xmm12
  pxor %xmm3, %xmm13
  pxor %xmm3, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 64(%r8), %xmm3
  movdqu 80(%r8), %xmm4
  movdqu 96(%r8), %xmm5
  movdqu 112(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 128(%r8), %xmm3
  movdqu 144(%r8), %xmm4
  movdqu 160(%r8), %xmm5
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  movdqu %xmm5, %xmm3
  movdqu 176(%r8), %xmm4
  movdqu 192(%r8), %xmm5
  movdqu 208(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 224(%r8), %xmm5
  aesenclast %xmm5, %xmm2
  aesenclast %xmm5, %xmm12
  aesenclast %xmm5, %xmm13
  aesenclast %xmm5, %xmm14
  movdqu 0(%r9), %xmm7
  pxor %xmm7, %xmm2
  movdqu 16(%r9), %xmm7
  pxor %xmm7, %xmm12
  movdqu 32(%r9), %xmm7
  pxor %xmm7, %xmm13
  movdqu 48(%r9), %xmm7
  pxor %xmm7, %xmm14
  movdqu %xmm2, 0(%r10)
  movdqu %xmm12, 16(%r10)
  movdqu %xmm13, 32(%r10)
  movdqu %xmm14, 48(%r10)
  sub $1, %rdx
  add $64, %r9
  add $64, %r10
.balign 16
L11:
  cmp $0, %rdx
  ja L10
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L9
L8:
L9:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm4, %xmm4
  mov $1, %r12
  pinsrd $0, %r12d, %xmm4
  jmp L13
.balign 16
L12:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm4, %xmm7
.balign 16
L13:
  cmp %rcx, %rdx
  jne L12
  cmp %rbp, %rsi
  jbe L14
  movdqu 0(%r13), %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r13)
  jmp L15
L14:
L15:
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global old_gcm128_encrypt
old_gcm128_encrypt:
  mov %rdi, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  movq 0(%r9), %r14
  movq 8(%r9), %r13
  movq 16(%r9), %rax
  movq 24(%r9), %r11
  movq 32(%r9), %r10
  movq 40(%r9), %r8
  movq 48(%r9), %rbx
  movq 56(%r9), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L16
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L18
  mov $0, %rdx
  jmp L21
.balign 16
L20:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L21:
  cmp %rcx, %rdx
  jne L20
  jmp L19
L18:
L19:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L22
  jmp L23
L22:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L24
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L25
L24:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L25:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L23:
  jmp L17
L16:
L17:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L26
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L28
  mov %rax, %r9
  mov %rbx, %r10
  pshufb %xmm8, %xmm7
  movdqu %xmm7, %xmm9
  mov $579005069656919567, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pshufb %xmm0, %xmm9
  movdqu %xmm9, %xmm10
  pxor %xmm3, %xmm3
  mov $1, %rax
  pinsrd $2, %eax, %xmm3
  paddd %xmm3, %xmm9
  mov $3, %rax
  pinsrd $2, %eax, %xmm3
  mov $2, %rax
  pinsrd $0, %eax, %xmm3
  paddd %xmm3, %xmm10
  pshufb %xmm8, %xmm9
  pshufb %xmm8, %xmm10
  pextrq $0, %xmm7, %rdi
  mov $283686952306183, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pxor %xmm15, %xmm15
  mov $4, %rax
  pinsrd $0, %eax, %xmm15
  mov $4, %rax
  pinsrd $2, %eax, %xmm15
  jmp L31
.balign 16
L30:
  pinsrq $0, %rdi, %xmm2
  pinsrq $0, %rdi, %xmm12
  pinsrq $0, %rdi, %xmm13
  pinsrq $0, %rdi, %xmm14
  shufpd $2, %xmm9, %xmm2
  shufpd $0, %xmm9, %xmm12
  shufpd $2, %xmm10, %xmm13
  shufpd $0, %xmm10, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  movdqu 0(%r8), %xmm3
  movdqu 16(%r8), %xmm4
  movdqu 32(%r8), %xmm5
  movdqu 48(%r8), %xmm6
  paddd %xmm15, %xmm9
  paddd %xmm15, %xmm10
  pxor %xmm3, %xmm2
  pxor %xmm3, %xmm12
  pxor %xmm3, %xmm13
  pxor %xmm3, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 64(%r8), %xmm3
  movdqu 80(%r8), %xmm4
  movdqu 96(%r8), %xmm5
  movdqu 112(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 128(%r8), %xmm3
  movdqu 144(%r8), %xmm4
  movdqu 160(%r8), %xmm5
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenclast %xmm5, %xmm2
  aesenclast %xmm5, %xmm12
  aesenclast %xmm5, %xmm13
  aesenclast %xmm5, %xmm14
  movdqu 0(%r9), %xmm7
  pxor %xmm7, %xmm2
  movdqu 16(%r9), %xmm7
  pxor %xmm7, %xmm12
  movdqu 32(%r9), %xmm7
  pxor %xmm7, %xmm13
  movdqu 48(%r9), %xmm7
  pxor %xmm7, %xmm14
  movdqu %xmm2, 0(%r10)
  movdqu %xmm12, 16(%r10)
  movdqu %xmm13, 32(%r10)
  movdqu %xmm14, 48(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm12, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm13, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm14, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  sub $1, %rdx
  add $64, %r9
  add $64, %r10
.balign 16
L31:
  cmp $0, %rdx
  ja L30
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L29
L28:
L29:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L33
.balign 16
L32:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L33:
  cmp %rcx, %rdx
  jne L32
  cmp $0, %rsi
  jne L34
  jmp L35
L34:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  mov %r10, %r9
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L36
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L37
L36:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L37:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L35:
  jmp L27
L26:
L27:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r15)
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global gcm128_encrypt
gcm128_encrypt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov %rdi, %r14
  mov %rsi, %r13
  mov %rdx, %rax
  mov %rcx, %r11
  mov %r8, %r10
  mov %r9, %r8
  mov 72(%rsp), %rbx
  mov 80(%rsp), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L38
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L40
  mov $0, %rdx
  jmp L43
.balign 16
L42:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L43:
  cmp %rcx, %rdx
  jne L42
  jmp L41
L40:
L41:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L44
  jmp L45
L44:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L46
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L47
L46:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L47:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L45:
  jmp L39
L38:
L39:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L48
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L50
  mov %rax, %r9
  mov %rbx, %r10
  pshufb %xmm8, %xmm7
  movdqu %xmm7, %xmm9
  mov $579005069656919567, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pshufb %xmm0, %xmm9
  movdqu %xmm9, %xmm10
  pxor %xmm3, %xmm3
  mov $1, %rax
  pinsrd $2, %eax, %xmm3
  paddd %xmm3, %xmm9
  mov $3, %rax
  pinsrd $2, %eax, %xmm3
  mov $2, %rax
  pinsrd $0, %eax, %xmm3
  paddd %xmm3, %xmm10
  pshufb %xmm8, %xmm9
  pshufb %xmm8, %xmm10
  pextrq $0, %xmm7, %rdi
  mov $283686952306183, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pxor %xmm15, %xmm15
  mov $4, %rax
  pinsrd $0, %eax, %xmm15
  mov $4, %rax
  pinsrd $2, %eax, %xmm15
  jmp L53
.balign 16
L52:
  pinsrq $0, %rdi, %xmm2
  pinsrq $0, %rdi, %xmm12
  pinsrq $0, %rdi, %xmm13
  pinsrq $0, %rdi, %xmm14
  shufpd $2, %xmm9, %xmm2
  shufpd $0, %xmm9, %xmm12
  shufpd $2, %xmm10, %xmm13
  shufpd $0, %xmm10, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  movdqu 0(%r8), %xmm3
  movdqu 16(%r8), %xmm4
  movdqu 32(%r8), %xmm5
  movdqu 48(%r8), %xmm6
  paddd %xmm15, %xmm9
  paddd %xmm15, %xmm10
  pxor %xmm3, %xmm2
  pxor %xmm3, %xmm12
  pxor %xmm3, %xmm13
  pxor %xmm3, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 64(%r8), %xmm3
  movdqu 80(%r8), %xmm4
  movdqu 96(%r8), %xmm5
  movdqu 112(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 128(%r8), %xmm3
  movdqu 144(%r8), %xmm4
  movdqu 160(%r8), %xmm5
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenclast %xmm5, %xmm2
  aesenclast %xmm5, %xmm12
  aesenclast %xmm5, %xmm13
  aesenclast %xmm5, %xmm14
  movdqu 0(%r9), %xmm7
  pxor %xmm7, %xmm2
  movdqu 16(%r9), %xmm7
  pxor %xmm7, %xmm12
  movdqu 32(%r9), %xmm7
  pxor %xmm7, %xmm13
  movdqu 48(%r9), %xmm7
  pxor %xmm7, %xmm14
  movdqu %xmm2, 0(%r10)
  movdqu %xmm12, 16(%r10)
  movdqu %xmm13, 32(%r10)
  movdqu %xmm14, 48(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm12, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm13, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm14, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  sub $1, %rdx
  add $64, %r9
  add $64, %r10
.balign 16
L53:
  cmp $0, %rdx
  ja L52
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L51
L50:
L51:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L55
.balign 16
L54:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L55:
  cmp %rcx, %rdx
  jne L54
  cmp $0, %rsi
  jne L56
  jmp L57
L56:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  mov %r10, %r9
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L58
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L59
L58:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L59:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L57:
  jmp L49
L48:
L49:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r15)
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global old_gcm128_decrypt
old_gcm128_decrypt:
  mov %rdi, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  movq 0(%r9), %r14
  movq 8(%r9), %r13
  movq 16(%r9), %rax
  movq 24(%r9), %r11
  movq 32(%r9), %r10
  movq 40(%r9), %r8
  movq 48(%r9), %rbx
  movq 56(%r9), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L60
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L62
  mov $0, %rdx
  jmp L65
.balign 16
L64:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L65:
  cmp %rcx, %rdx
  jne L64
  jmp L63
L62:
L63:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L66
  jmp L67
L66:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L68
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L69
L68:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L69:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L67:
  jmp L61
L60:
L61:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L70
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L73
.balign 16
L72:
  movdqu 0(%r9), %xmm0
  movdqu %xmm0, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm3
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm3
  movdqu %xmm3, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L73:
  cmp %rcx, %rdx
  jne L72
  cmp $0, %rsi
  jne L74
  jmp L75
L74:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L76
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L77
L76:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L77:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L75:
  jmp L71
L70:
L71:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L78
  mov $0, %rax
  jmp L79
L78:
  mov $1, %rax
L79:
  pextrq $1, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L80
  mov $0, %rdx
  jmp L81
L80:
  mov $1, %rdx
L81:
  add %rdx, %rax
  mov %rax, %rdx
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  mov %rdx, %rax
  ret

.global gcm128_decrypt
gcm128_decrypt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov %rdi, %r14
  mov %rsi, %r13
  mov %rdx, %rax
  mov %rcx, %r11
  mov %r8, %r10
  mov %r9, %r8
  mov 72(%rsp), %rbx
  mov 80(%rsp), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L82
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L84
  mov $0, %rdx
  jmp L87
.balign 16
L86:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L87:
  cmp %rcx, %rdx
  jne L86
  jmp L85
L84:
L85:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L88
  jmp L89
L88:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L90
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L91
L90:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L91:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L89:
  jmp L83
L82:
L83:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L92
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L95
.balign 16
L94:
  movdqu 0(%r9), %xmm0
  movdqu %xmm0, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm3
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm3
  movdqu %xmm3, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L95:
  cmp %rcx, %rdx
  jne L94
  cmp $0, %rsi
  jne L96
  jmp L97
L96:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L98
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L99
L98:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L99:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L97:
  jmp L93
L92:
L93:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L100
  mov $0, %rax
  jmp L101
L100:
  mov $1, %rax
L101:
  pextrq $1, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L102
  mov $0, %rdx
  jmp L103
L102:
  mov $1, %rdx
L103:
  add %rdx, %rax
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global old_gcm256_encrypt
old_gcm256_encrypt:
  mov %rdi, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  movq 0(%r9), %r14
  movq 8(%r9), %r13
  movq 16(%r9), %rax
  movq 24(%r9), %r11
  movq 32(%r9), %r10
  movq 40(%r9), %r8
  movq 48(%r9), %rbx
  movq 56(%r9), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L104
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L106
  mov $0, %rdx
  jmp L109
.balign 16
L108:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L109:
  cmp %rcx, %rdx
  jne L108
  jmp L107
L106:
L107:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L110
  jmp L111
L110:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L112
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L113
L112:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L113:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L111:
  jmp L105
L104:
L105:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L114
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L116
  mov %rax, %r9
  mov %rbx, %r10
  pshufb %xmm8, %xmm7
  movdqu %xmm7, %xmm9
  mov $579005069656919567, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pshufb %xmm0, %xmm9
  movdqu %xmm9, %xmm10
  pxor %xmm3, %xmm3
  mov $1, %rax
  pinsrd $2, %eax, %xmm3
  paddd %xmm3, %xmm9
  mov $3, %rax
  pinsrd $2, %eax, %xmm3
  mov $2, %rax
  pinsrd $0, %eax, %xmm3
  paddd %xmm3, %xmm10
  pshufb %xmm8, %xmm9
  pshufb %xmm8, %xmm10
  pextrq $0, %xmm7, %rdi
  mov $283686952306183, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pxor %xmm15, %xmm15
  mov $4, %rax
  pinsrd $0, %eax, %xmm15
  mov $4, %rax
  pinsrd $2, %eax, %xmm15
  jmp L119
.balign 16
L118:
  pinsrq $0, %rdi, %xmm2
  pinsrq $0, %rdi, %xmm12
  pinsrq $0, %rdi, %xmm13
  pinsrq $0, %rdi, %xmm14
  shufpd $2, %xmm9, %xmm2
  shufpd $0, %xmm9, %xmm12
  shufpd $2, %xmm10, %xmm13
  shufpd $0, %xmm10, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  movdqu 0(%r8), %xmm3
  movdqu 16(%r8), %xmm4
  movdqu 32(%r8), %xmm5
  movdqu 48(%r8), %xmm6
  paddd %xmm15, %xmm9
  paddd %xmm15, %xmm10
  pxor %xmm3, %xmm2
  pxor %xmm3, %xmm12
  pxor %xmm3, %xmm13
  pxor %xmm3, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 64(%r8), %xmm3
  movdqu 80(%r8), %xmm4
  movdqu 96(%r8), %xmm5
  movdqu 112(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 128(%r8), %xmm3
  movdqu 144(%r8), %xmm4
  movdqu 160(%r8), %xmm5
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  movdqu %xmm5, %xmm3
  movdqu 176(%r8), %xmm4
  movdqu 192(%r8), %xmm5
  movdqu 208(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 224(%r8), %xmm5
  aesenclast %xmm5, %xmm2
  aesenclast %xmm5, %xmm12
  aesenclast %xmm5, %xmm13
  aesenclast %xmm5, %xmm14
  movdqu 0(%r9), %xmm7
  pxor %xmm7, %xmm2
  movdqu 16(%r9), %xmm7
  pxor %xmm7, %xmm12
  movdqu 32(%r9), %xmm7
  pxor %xmm7, %xmm13
  movdqu 48(%r9), %xmm7
  pxor %xmm7, %xmm14
  movdqu %xmm2, 0(%r10)
  movdqu %xmm12, 16(%r10)
  movdqu %xmm13, 32(%r10)
  movdqu %xmm14, 48(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm12, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm13, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm14, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  sub $1, %rdx
  add $64, %r9
  add $64, %r10
.balign 16
L119:
  cmp $0, %rdx
  ja L118
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L117
L116:
L117:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L121
.balign 16
L120:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L121:
  cmp %rcx, %rdx
  jne L120
  cmp $0, %rsi
  jne L122
  jmp L123
L122:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  mov %r10, %r9
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L124
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L125
L124:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L125:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L123:
  jmp L115
L114:
L115:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r15)
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global gcm256_encrypt
gcm256_encrypt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov %rdi, %r14
  mov %rsi, %r13
  mov %rdx, %rax
  mov %rcx, %r11
  mov %r8, %r10
  mov %r9, %r8
  mov 72(%rsp), %rbx
  mov 80(%rsp), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L126
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L128
  mov $0, %rdx
  jmp L131
.balign 16
L130:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L131:
  cmp %rcx, %rdx
  jne L130
  jmp L129
L128:
L129:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L132
  jmp L133
L132:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L134
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L135
L134:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L135:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L133:
  jmp L127
L126:
L127:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L136
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L138
  mov %rax, %r9
  mov %rbx, %r10
  pshufb %xmm8, %xmm7
  movdqu %xmm7, %xmm9
  mov $579005069656919567, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pshufb %xmm0, %xmm9
  movdqu %xmm9, %xmm10
  pxor %xmm3, %xmm3
  mov $1, %rax
  pinsrd $2, %eax, %xmm3
  paddd %xmm3, %xmm9
  mov $3, %rax
  pinsrd $2, %eax, %xmm3
  mov $2, %rax
  pinsrd $0, %eax, %xmm3
  paddd %xmm3, %xmm10
  pshufb %xmm8, %xmm9
  pshufb %xmm8, %xmm10
  pextrq $0, %xmm7, %rdi
  mov $283686952306183, %rax
  pinsrq $0, %rax, %xmm0
  mov $579005069656919567, %rax
  pinsrq $1, %rax, %xmm0
  pxor %xmm15, %xmm15
  mov $4, %rax
  pinsrd $0, %eax, %xmm15
  mov $4, %rax
  pinsrd $2, %eax, %xmm15
  jmp L141
.balign 16
L140:
  pinsrq $0, %rdi, %xmm2
  pinsrq $0, %rdi, %xmm12
  pinsrq $0, %rdi, %xmm13
  pinsrq $0, %rdi, %xmm14
  shufpd $2, %xmm9, %xmm2
  shufpd $0, %xmm9, %xmm12
  shufpd $2, %xmm10, %xmm13
  shufpd $0, %xmm10, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  movdqu 0(%r8), %xmm3
  movdqu 16(%r8), %xmm4
  movdqu 32(%r8), %xmm5
  movdqu 48(%r8), %xmm6
  paddd %xmm15, %xmm9
  paddd %xmm15, %xmm10
  pxor %xmm3, %xmm2
  pxor %xmm3, %xmm12
  pxor %xmm3, %xmm13
  pxor %xmm3, %xmm14
  pshufb %xmm0, %xmm9
  pshufb %xmm0, %xmm10
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 64(%r8), %xmm3
  movdqu 80(%r8), %xmm4
  movdqu 96(%r8), %xmm5
  movdqu 112(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 128(%r8), %xmm3
  movdqu 144(%r8), %xmm4
  movdqu 160(%r8), %xmm5
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  movdqu %xmm5, %xmm3
  movdqu 176(%r8), %xmm4
  movdqu 192(%r8), %xmm5
  movdqu 208(%r8), %xmm6
  aesenc %xmm3, %xmm2
  aesenc %xmm3, %xmm12
  aesenc %xmm3, %xmm13
  aesenc %xmm3, %xmm14
  aesenc %xmm4, %xmm2
  aesenc %xmm4, %xmm12
  aesenc %xmm4, %xmm13
  aesenc %xmm4, %xmm14
  aesenc %xmm5, %xmm2
  aesenc %xmm5, %xmm12
  aesenc %xmm5, %xmm13
  aesenc %xmm5, %xmm14
  aesenc %xmm6, %xmm2
  aesenc %xmm6, %xmm12
  aesenc %xmm6, %xmm13
  aesenc %xmm6, %xmm14
  movdqu 224(%r8), %xmm5
  aesenclast %xmm5, %xmm2
  aesenclast %xmm5, %xmm12
  aesenclast %xmm5, %xmm13
  aesenclast %xmm5, %xmm14
  movdqu 0(%r9), %xmm7
  pxor %xmm7, %xmm2
  movdqu 16(%r9), %xmm7
  pxor %xmm7, %xmm12
  movdqu 32(%r9), %xmm7
  pxor %xmm7, %xmm13
  movdqu 48(%r9), %xmm7
  pxor %xmm7, %xmm14
  movdqu %xmm2, 0(%r10)
  movdqu %xmm12, 16(%r10)
  movdqu %xmm13, 32(%r10)
  movdqu %xmm14, 48(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm12, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm13, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm14, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  sub $1, %rdx
  add $64, %r9
  add $64, %r10
.balign 16
L141:
  cmp $0, %rdx
  ja L140
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L139
L138:
L139:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L143
.balign 16
L142:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L143:
  cmp %rcx, %rdx
  jne L142
  cmp $0, %rsi
  jne L144
  jmp L145
L144:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  mov %r10, %r9
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L146
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L147
L146:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L147:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L145:
  jmp L137
L136:
L137:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r15)
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global old_gcm256_decrypt
old_gcm256_decrypt:
  mov %rdi, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  movq 0(%r9), %r14
  movq 8(%r9), %r13
  movq 16(%r9), %rax
  movq 24(%r9), %r11
  movq 32(%r9), %r10
  movq 40(%r9), %r8
  movq 48(%r9), %rbx
  movq 56(%r9), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L148
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L150
  mov $0, %rdx
  jmp L153
.balign 16
L152:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L153:
  cmp %rcx, %rdx
  jne L152
  jmp L151
L150:
L151:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L154
  jmp L155
L154:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L156
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L157
L156:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L157:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L155:
  jmp L149
L148:
L149:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L158
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L161
.balign 16
L160:
  movdqu 0(%r9), %xmm0
  movdqu %xmm0, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm3
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm3
  movdqu %xmm3, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L161:
  cmp %rcx, %rdx
  jne L160
  cmp $0, %rsi
  jne L162
  jmp L163
L162:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L164
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L165
L164:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L165:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L163:
  jmp L159
L158:
L159:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L166
  mov $0, %rax
  jmp L167
L166:
  mov $1, %rax
L167:
  pextrq $1, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L168
  mov $0, %rdx
  jmp L169
L168:
  mov $1, %rdx
L169:
  add %rdx, %rax
  mov %rax, %rdx
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  mov %rdx, %rax
  ret

.global gcm256_decrypt
gcm256_decrypt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov %rdi, %r14
  mov %rsi, %r13
  mov %rdx, %rax
  mov %rcx, %r11
  mov %r8, %r10
  mov %r9, %r8
  mov 72(%rsp), %rbx
  mov 80(%rsp), %r15
  movdqu 0(%r10), %xmm7
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pxor %xmm0, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pshufb %xmm8, %xmm0
  movdqu %xmm0, %xmm11
  pshufb %xmm8, %xmm7
  mov $2, %r12
  pinsrd $0, %r12d, %xmm7
  pxor %xmm1, %xmm1
  cmp $0, %r11
  jbe L170
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L172
  mov $0, %rdx
  jmp L175
.balign 16
L174:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L175:
  cmp %rcx, %rdx
  jne L174
  jmp L173
L172:
L173:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L176
  jmp L177
L176:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L178
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L179
L178:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L179:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L177:
  jmp L171
L170:
L171:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L180
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L183
.balign 16
L182:
  movdqu 0(%r9), %xmm0
  movdqu %xmm0, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm3
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm3
  movdqu %xmm3, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L183:
  cmp %rcx, %rdx
  jne L182
  cmp $0, %rsi
  jne L184
  jmp L185
L184:
  movdqu %xmm1, %xmm3
  movdqu 0(%r9), %xmm2
  movdqu %xmm2, %xmm1
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu %xmm1, 0(%r10)
  mov %rsi, %rax
  movdqu %xmm3, %xmm1
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L186
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L187
L186:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L187:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
L185:
  jmp L181
L180:
L181:
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L188
  mov $0, %rax
  jmp L189
L188:
  mov $1, %rax
L189:
  pextrq $1, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L190
  mov $0, %rdx
  jmp L191
L190:
  mov $1, %rdx
L191:
  add %rdx, %rax
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global gcm128_encrypt_opt
gcm128_encrypt_opt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov 144(%rsp), %rbp
  mov %r8, %r13
  mov %r9, %r14
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  mov %rdi, %rax
  mov %rcx, %r8
  mov %rdx, %r11
  movdqu 32(%r9), %xmm11
  pxor %xmm1, %xmm1
  mov %r11, %rcx
  cmp $0, %rcx
  je L192
  mov $0, %rdx
  mov %rax, %r9
  jmp L195
.balign 16
L194:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L195:
  cmp %rcx, %rdx
  jne L194
  jmp L193
L192:
L193:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L196
  mov 72(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L198
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L199
L198:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L199:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  jmp L197
L196:
L197:
  mov %rsi, %r15
  mov 80(%rsp), %rdi
  mov 88(%rsp), %rsi
  mov 96(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L200
  lea 32(%r9), %r9
  movdqu 0(%r8), %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  movdqu %xmm1, 0(%r8)
  jmp L201
L200:
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  movdqu 0(%r8), %xmm1
  vpshufb %xmm0, %xmm8, %xmm8
  movdqu %xmm8, 0(%r8)
  add $128, %rcx
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  lea 96(%rsi), %r14
  movdqu -128(%rcx), %xmm4
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  movdqu -112(%rcx), %xmm15
  mov %rcx, %r12
  sub $96, %r12
  vpxor %xmm4, %xmm1, %xmm9
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpxor %xmm4, %xmm10, %xmm10
  vpaddd %xmm2, %xmm11, %xmm12
  vpxor %xmm4, %xmm11, %xmm11
  vpaddd %xmm2, %xmm12, %xmm13
  vpxor %xmm4, %xmm12, %xmm12
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm4, %xmm13, %xmm13
  vpaddd %xmm2, %xmm14, %xmm1
  vpxor %xmm4, %xmm14, %xmm14
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -16(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 16(%rcx), %xmm15
  movdqu 32(%rcx), %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 0(%rdi), %xmm3, %xmm4
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor 16(%rdi), %xmm3, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 32(%rdi), %xmm3, %xmm6
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 48(%rdi), %xmm3, %xmm8
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 64(%rdi), %xmm3, %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 80(%rdi), %xmm3, %xmm3
  lea 96(%rdi), %rdi
  vaesenclast %xmm4, %xmm9, %xmm9
  vaesenclast %xmm5, %xmm10, %xmm10
  vaesenclast %xmm6, %xmm11, %xmm11
  vaesenclast %xmm8, %xmm12, %xmm12
  vaesenclast %xmm2, %xmm13, %xmm13
  vaesenclast %xmm3, %xmm14, %xmm14
  movdqu %xmm9, 0(%rsi)
  movdqu %xmm10, 16(%rsi)
  movdqu %xmm11, 32(%rsi)
  movdqu %xmm12, 48(%rsi)
  movdqu %xmm13, 64(%rsi)
  movdqu %xmm14, 80(%rsi)
  lea 96(%rsi), %rsi
  vpshufb %xmm0, %xmm9, %xmm8
  vpshufb %xmm0, %xmm10, %xmm2
  movdqu %xmm8, 112(%rbp)
  vpshufb %xmm0, %xmm11, %xmm4
  movdqu %xmm2, 96(%rbp)
  vpshufb %xmm0, %xmm12, %xmm5
  movdqu %xmm4, 80(%rbp)
  vpshufb %xmm0, %xmm13, %xmm6
  movdqu %xmm5, 64(%rbp)
  vpshufb %xmm0, %xmm14, %xmm7
  movdqu %xmm6, 48(%rbp)
  movdqu -128(%rcx), %xmm4
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  movdqu -112(%rcx), %xmm15
  mov %rcx, %r12
  sub $96, %r12
  vpxor %xmm4, %xmm1, %xmm9
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpxor %xmm4, %xmm10, %xmm10
  vpaddd %xmm2, %xmm11, %xmm12
  vpxor %xmm4, %xmm11, %xmm11
  vpaddd %xmm2, %xmm12, %xmm13
  vpxor %xmm4, %xmm12, %xmm12
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm4, %xmm13, %xmm13
  vpaddd %xmm2, %xmm14, %xmm1
  vpxor %xmm4, %xmm14, %xmm14
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -16(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 16(%rcx), %xmm15
  movdqu 32(%rcx), %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 0(%rdi), %xmm3, %xmm4
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor 16(%rdi), %xmm3, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 32(%rdi), %xmm3, %xmm6
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 48(%rdi), %xmm3, %xmm8
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 64(%rdi), %xmm3, %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 80(%rdi), %xmm3, %xmm3
  lea 96(%rdi), %rdi
  vaesenclast %xmm4, %xmm9, %xmm9
  vaesenclast %xmm5, %xmm10, %xmm10
  vaesenclast %xmm6, %xmm11, %xmm11
  vaesenclast %xmm8, %xmm12, %xmm12
  vaesenclast %xmm2, %xmm13, %xmm13
  vaesenclast %xmm3, %xmm14, %xmm14
  movdqu %xmm9, 0(%rsi)
  movdqu %xmm10, 16(%rsi)
  movdqu %xmm11, 32(%rsi)
  movdqu %xmm12, 48(%rsi)
  movdqu %xmm13, 64(%rsi)
  movdqu %xmm14, 80(%rsi)
  lea 96(%rsi), %rsi
  sub $12, %rdx
  movdqu 0(%r8), %xmm8
  lea 32(%r9), %r9
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vpxor %xmm4, %xmm4, %xmm4
  movdqu -128(%rcx), %xmm15
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpaddd %xmm2, %xmm11, %xmm12
  vpaddd %xmm2, %xmm12, %xmm13
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm4, 16(%rbp)
  mov $14, %rbx
  jmp L203
.balign 16
L202:
  add $6, %rbx
  cmp $256, %rbx
  jb L204
  mov $579005069656919567, %r11
  pinsrq $0, %r11, %xmm0
  mov $283686952306183, %r11
  pinsrq $1, %r11, %xmm0
  vpshufb %xmm0, %xmm1, %xmm6
  pxor %xmm5, %xmm5
  mov $1, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm10
  pxor %xmm5, %xmm5
  mov $2, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm11
  movdqu -32(%r9), %xmm3
  vpaddd %xmm5, %xmm10, %xmm12
  vpshufb %xmm0, %xmm10, %xmm10
  vpaddd %xmm5, %xmm11, %xmm13
  vpshufb %xmm0, %xmm11, %xmm11
  vpxor %xmm15, %xmm10, %xmm10
  vpaddd %xmm5, %xmm12, %xmm14
  vpshufb %xmm0, %xmm12, %xmm12
  vpxor %xmm15, %xmm11, %xmm11
  vpaddd %xmm5, %xmm13, %xmm1
  vpshufb %xmm0, %xmm13, %xmm13
  vpshufb %xmm0, %xmm14, %xmm14
  vpshufb %xmm0, %xmm1, %xmm1
  sub $256, %rbx
  jmp L205
L204:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L205:
  movdqu %xmm1, 0(%r8)
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  vpxor %xmm15, %xmm12, %xmm12
  movdqu -112(%rcx), %xmm2
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vaesenc %xmm2, %xmm9, %xmm9
  movdqu 48(%rbp), %xmm0
  vpxor %xmm15, %xmm13, %xmm13
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vaesenc %xmm2, %xmm10, %xmm10
  vpxor %xmm15, %xmm14, %xmm14
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  vaesenc %xmm2, %xmm11, %xmm11
  movdqu -16(%r9), %xmm3
  vaesenc %xmm2, %xmm12, %xmm12
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vaesenc %xmm2, %xmm13, %xmm13
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vaesenc %xmm2, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 16(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 88(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 80(%r14), %r12
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 32(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 40(%rbp)
  movdqu 16(%r9), %xmm5
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vaesenc %xmm15, %xmm11, %xmm11
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 72(%r14), %r13
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 64(%r14), %r12
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 48(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 56(%rbp)
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 56(%r14), %r13
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 48(%r14), %r12
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 64(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 72(%rbp)
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 40(%r14), %r13
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 32(%r14), %r12
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 80(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 88(%rbp)
  vpxor %xmm5, %xmm6, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor %xmm1, %xmm6, %xmm6
  movdqu -16(%rcx), %xmm15
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $13979173243358019584, %r11
  pinsrq $1, %r11, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm8, %xmm7, %xmm7
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm5, %xmm4, %xmm4
  movbeq 24(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 16(%r14), %r12
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  movq %r13, 96(%rbp)
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r12, 104(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm1
  vaesenc %xmm1, %xmm9, %xmm9
  movdqu 16(%rcx), %xmm15
  vaesenc %xmm1, %xmm10, %xmm10
  vpsrldq $8, %xmm6, %xmm6
  vaesenc %xmm1, %xmm11, %xmm11
  vpxor %xmm6, %xmm7, %xmm7
  vaesenc %xmm1, %xmm12, %xmm12
  vpxor %xmm0, %xmm4, %xmm4
  movbeq 8(%r14), %r13
  vaesenc %xmm1, %xmm13, %xmm13
  movbeq 0(%r14), %r12
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 32(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  movdqu %xmm7, 16(%rbp)
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vaesenc %xmm15, %xmm10, %xmm10
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor 0(%rdi), %xmm1, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 16(%rdi), %xmm1, %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 32(%rdi), %xmm1, %xmm5
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 48(%rdi), %xmm1, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 64(%rdi), %xmm1, %xmm7
  vpxor 80(%rdi), %xmm1, %xmm3
  movdqu 0(%r8), %xmm1
  vaesenclast %xmm2, %xmm9, %xmm9
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vaesenclast %xmm0, %xmm10, %xmm10
  vpaddd %xmm2, %xmm1, %xmm0
  movq %r13, 112(%rbp)
  lea 96(%rdi), %rdi
  vaesenclast %xmm5, %xmm11, %xmm11
  vpaddd %xmm2, %xmm0, %xmm5
  movq %r12, 120(%rbp)
  lea 96(%rsi), %rsi
  movdqu -128(%rcx), %xmm15
  vaesenclast %xmm6, %xmm12, %xmm12
  vpaddd %xmm2, %xmm5, %xmm6
  vaesenclast %xmm7, %xmm13, %xmm13
  vpaddd %xmm2, %xmm6, %xmm7
  vaesenclast %xmm3, %xmm14, %xmm14
  vpaddd %xmm2, %xmm7, %xmm3
  sub $6, %rdx
  add $96, %r14
  cmp $0, %rdx
  jbe L206
  movdqu %xmm9, -96(%rsi)
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm10, -80(%rsi)
  movdqu %xmm0, %xmm10
  movdqu %xmm11, -64(%rsi)
  movdqu %xmm5, %xmm11
  movdqu %xmm12, -48(%rsi)
  movdqu %xmm6, %xmm12
  movdqu %xmm13, -32(%rsi)
  movdqu %xmm7, %xmm13
  movdqu %xmm14, -16(%rsi)
  movdqu %xmm3, %xmm14
  movdqu 32(%rbp), %xmm7
  jmp L207
L206:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L207:
.balign 16
L203:
  cmp $0, %rdx
  ja L202
  movdqu %xmm1, 0(%r8)
  movdqu 32(%rbp), %xmm7
  pxor %xmm4, %xmm4
  movdqu %xmm4, 0(%rbp)
  movdqu -32(%r9), %xmm3
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  movdqu 48(%rbp), %xmm0
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  movdqu -16(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vpxor 0(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  movdqu 16(%r9), %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vpxor %xmm5, %xmm6, %xmm6
  vpxor %xmm1, %xmm6, %xmm6
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $3254779904, %rax
  pinsrd $3, %eax, %xmm3
  vpxor %xmm8, %xmm7, %xmm7
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm5, %xmm4, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpsrldq $8, %xmm6, %xmm6
  vpxor %xmm6, %xmm7, %xmm7
  vpxor %xmm4, %xmm0, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor %xmm7, %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  movdqu %xmm9, -96(%rsi)
  vpshufb %xmm0, %xmm9, %xmm9
  vpxor %xmm7, %xmm1, %xmm1
  movdqu %xmm10, -80(%rsi)
  vpshufb %xmm0, %xmm10, %xmm10
  movdqu %xmm11, -64(%rsi)
  vpshufb %xmm0, %xmm11, %xmm11
  movdqu %xmm12, -48(%rsi)
  vpshufb %xmm0, %xmm12, %xmm12
  movdqu %xmm13, -32(%rsi)
  vpshufb %xmm0, %xmm13, %xmm13
  movdqu %xmm14, -16(%rsi)
  vpshufb %xmm0, %xmm14, %xmm14
  pxor %xmm4, %xmm4
  movdqu %xmm14, %xmm7
  movdqu %xmm4, 0(%rbp)
  movdqu %xmm13, 48(%rbp)
  movdqu %xmm12, 64(%rbp)
  movdqu %xmm11, 80(%rbp)
  movdqu %xmm10, 96(%rbp)
  movdqu %xmm9, 112(%rbp)
  movdqu -32(%r9), %xmm3
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  movdqu 48(%rbp), %xmm0
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  movdqu -16(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vpxor 0(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  movdqu 16(%r9), %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vpxor %xmm5, %xmm6, %xmm6
  vpxor %xmm1, %xmm6, %xmm6
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $3254779904, %rax
  pinsrd $3, %eax, %xmm3
  vpxor %xmm8, %xmm7, %xmm7
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm5, %xmm4, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpsrldq $8, %xmm6, %xmm6
  vpxor %xmm6, %xmm7, %xmm7
  vpxor %xmm4, %xmm0, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor %xmm7, %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm8, %xmm8
  sub $128, %rcx
L201:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 104(%rsp), %rax
  mov 112(%rsp), %rbx
  mov 120(%rsp), %rcx
  movdqu %xmm8, %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pshufb %xmm8, %xmm7
  movdqu 0(%r9), %xmm11
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L209
.balign 16
L208:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L209:
  cmp %rcx, %rdx
  jne L208
  add 96(%rsp), %rcx
  imul $16, %rcx
  mov 136(%rsp), %r13
  cmp %rcx, %r13
  jbe L210
  mov 128(%rsp), %rax
  mov %rax, %rbx
  mov %r13, %rcx
  and $15, %rcx
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%rax), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%rbx)
  mov %rcx, %rax
  cmp $8, %rax
  jae L212
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L213
L212:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L213:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  jmp L211
L210:
L211:
  mov %r15, %r11
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  mov 152(%rsp), %r15
  movdqu %xmm1, 0(%r15)
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global gcm256_encrypt_opt
gcm256_encrypt_opt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov 144(%rsp), %rbp
  mov %r8, %r13
  mov %r9, %r14
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  mov %rdi, %rax
  mov %rcx, %r8
  mov %rdx, %r11
  movdqu 32(%r9), %xmm11
  pxor %xmm1, %xmm1
  mov %r11, %rcx
  cmp $0, %rcx
  je L214
  mov $0, %rdx
  mov %rax, %r9
  jmp L217
.balign 16
L216:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L217:
  cmp %rcx, %rdx
  jne L216
  jmp L215
L214:
L215:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L218
  mov 72(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L220
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L221
L220:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L221:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  jmp L219
L218:
L219:
  mov %rsi, %r15
  mov 80(%rsp), %rdi
  mov 88(%rsp), %rsi
  mov 96(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L222
  lea 32(%r9), %r9
  movdqu 0(%r8), %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  movdqu %xmm1, 0(%r8)
  jmp L223
L222:
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  movdqu 0(%r8), %xmm1
  vpshufb %xmm0, %xmm8, %xmm8
  movdqu %xmm8, 0(%r8)
  add $128, %rcx
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  lea 96(%rsi), %r14
  movdqu -128(%rcx), %xmm4
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  movdqu -112(%rcx), %xmm15
  mov %rcx, %r12
  sub $96, %r12
  vpxor %xmm4, %xmm1, %xmm9
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpxor %xmm4, %xmm10, %xmm10
  vpaddd %xmm2, %xmm11, %xmm12
  vpxor %xmm4, %xmm11, %xmm11
  vpaddd %xmm2, %xmm12, %xmm13
  vpxor %xmm4, %xmm12, %xmm12
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm4, %xmm13, %xmm13
  vpaddd %xmm2, %xmm14, %xmm1
  vpxor %xmm4, %xmm14, %xmm14
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -16(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 16(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 32(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 48(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 64(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 80(%rcx), %xmm15
  movdqu 96(%rcx), %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 0(%rdi), %xmm3, %xmm4
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor 16(%rdi), %xmm3, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 32(%rdi), %xmm3, %xmm6
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 48(%rdi), %xmm3, %xmm8
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 64(%rdi), %xmm3, %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 80(%rdi), %xmm3, %xmm3
  lea 96(%rdi), %rdi
  vaesenclast %xmm4, %xmm9, %xmm9
  vaesenclast %xmm5, %xmm10, %xmm10
  vaesenclast %xmm6, %xmm11, %xmm11
  vaesenclast %xmm8, %xmm12, %xmm12
  vaesenclast %xmm2, %xmm13, %xmm13
  vaesenclast %xmm3, %xmm14, %xmm14
  movdqu %xmm9, 0(%rsi)
  movdqu %xmm10, 16(%rsi)
  movdqu %xmm11, 32(%rsi)
  movdqu %xmm12, 48(%rsi)
  movdqu %xmm13, 64(%rsi)
  movdqu %xmm14, 80(%rsi)
  lea 96(%rsi), %rsi
  vpshufb %xmm0, %xmm9, %xmm8
  vpshufb %xmm0, %xmm10, %xmm2
  movdqu %xmm8, 112(%rbp)
  vpshufb %xmm0, %xmm11, %xmm4
  movdqu %xmm2, 96(%rbp)
  vpshufb %xmm0, %xmm12, %xmm5
  movdqu %xmm4, 80(%rbp)
  vpshufb %xmm0, %xmm13, %xmm6
  movdqu %xmm5, 64(%rbp)
  vpshufb %xmm0, %xmm14, %xmm7
  movdqu %xmm6, 48(%rbp)
  movdqu -128(%rcx), %xmm4
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  movdqu -112(%rcx), %xmm15
  mov %rcx, %r12
  sub $96, %r12
  vpxor %xmm4, %xmm1, %xmm9
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpxor %xmm4, %xmm10, %xmm10
  vpaddd %xmm2, %xmm11, %xmm12
  vpxor %xmm4, %xmm11, %xmm11
  vpaddd %xmm2, %xmm12, %xmm13
  vpxor %xmm4, %xmm12, %xmm12
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm4, %xmm13, %xmm13
  vpaddd %xmm2, %xmm14, %xmm1
  vpxor %xmm4, %xmm14, %xmm14
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -16(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 16(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 32(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 48(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 64(%rcx), %xmm15
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 80(%rcx), %xmm15
  movdqu 96(%rcx), %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 0(%rdi), %xmm3, %xmm4
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor 16(%rdi), %xmm3, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 32(%rdi), %xmm3, %xmm6
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 48(%rdi), %xmm3, %xmm8
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 64(%rdi), %xmm3, %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 80(%rdi), %xmm3, %xmm3
  lea 96(%rdi), %rdi
  vaesenclast %xmm4, %xmm9, %xmm9
  vaesenclast %xmm5, %xmm10, %xmm10
  vaesenclast %xmm6, %xmm11, %xmm11
  vaesenclast %xmm8, %xmm12, %xmm12
  vaesenclast %xmm2, %xmm13, %xmm13
  vaesenclast %xmm3, %xmm14, %xmm14
  movdqu %xmm9, 0(%rsi)
  movdqu %xmm10, 16(%rsi)
  movdqu %xmm11, 32(%rsi)
  movdqu %xmm12, 48(%rsi)
  movdqu %xmm13, 64(%rsi)
  movdqu %xmm14, 80(%rsi)
  lea 96(%rsi), %rsi
  sub $12, %rdx
  movdqu 0(%r8), %xmm8
  lea 32(%r9), %r9
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vpxor %xmm4, %xmm4, %xmm4
  movdqu -128(%rcx), %xmm15
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpaddd %xmm2, %xmm11, %xmm12
  vpaddd %xmm2, %xmm12, %xmm13
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm4, 16(%rbp)
  mov $14, %rbx
  jmp L225
.balign 16
L224:
  add $6, %rbx
  cmp $256, %rbx
  jb L226
  mov $579005069656919567, %r11
  pinsrq $0, %r11, %xmm0
  mov $283686952306183, %r11
  pinsrq $1, %r11, %xmm0
  vpshufb %xmm0, %xmm1, %xmm6
  pxor %xmm5, %xmm5
  mov $1, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm10
  pxor %xmm5, %xmm5
  mov $2, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm11
  movdqu -32(%r9), %xmm3
  vpaddd %xmm5, %xmm10, %xmm12
  vpshufb %xmm0, %xmm10, %xmm10
  vpaddd %xmm5, %xmm11, %xmm13
  vpshufb %xmm0, %xmm11, %xmm11
  vpxor %xmm15, %xmm10, %xmm10
  vpaddd %xmm5, %xmm12, %xmm14
  vpshufb %xmm0, %xmm12, %xmm12
  vpxor %xmm15, %xmm11, %xmm11
  vpaddd %xmm5, %xmm13, %xmm1
  vpshufb %xmm0, %xmm13, %xmm13
  vpshufb %xmm0, %xmm14, %xmm14
  vpshufb %xmm0, %xmm1, %xmm1
  sub $256, %rbx
  jmp L227
L226:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L227:
  movdqu %xmm1, 0(%r8)
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  vpxor %xmm15, %xmm12, %xmm12
  movdqu -112(%rcx), %xmm2
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vaesenc %xmm2, %xmm9, %xmm9
  movdqu 48(%rbp), %xmm0
  vpxor %xmm15, %xmm13, %xmm13
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vaesenc %xmm2, %xmm10, %xmm10
  vpxor %xmm15, %xmm14, %xmm14
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  vaesenc %xmm2, %xmm11, %xmm11
  movdqu -16(%r9), %xmm3
  vaesenc %xmm2, %xmm12, %xmm12
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vaesenc %xmm2, %xmm13, %xmm13
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vaesenc %xmm2, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 16(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 88(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 80(%r14), %r12
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 32(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 40(%rbp)
  movdqu 16(%r9), %xmm5
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vaesenc %xmm15, %xmm11, %xmm11
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 72(%r14), %r13
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 64(%r14), %r12
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 48(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 56(%rbp)
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 56(%r14), %r13
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 48(%r14), %r12
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 64(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 72(%rbp)
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 40(%r14), %r13
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 32(%r14), %r12
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 80(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 88(%rbp)
  vpxor %xmm5, %xmm6, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor %xmm1, %xmm6, %xmm6
  movdqu -16(%rcx), %xmm15
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $13979173243358019584, %r11
  pinsrq $1, %r11, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm8, %xmm7, %xmm7
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm5, %xmm4, %xmm4
  movbeq 24(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 16(%r14), %r12
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  movq %r13, 96(%rbp)
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r12, 104(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm1
  vaesenc %xmm1, %xmm9, %xmm9
  movdqu 16(%rcx), %xmm15
  vaesenc %xmm1, %xmm10, %xmm10
  vpsrldq $8, %xmm6, %xmm6
  vaesenc %xmm1, %xmm11, %xmm11
  vpxor %xmm6, %xmm7, %xmm7
  vaesenc %xmm1, %xmm12, %xmm12
  vpxor %xmm0, %xmm4, %xmm4
  movbeq 8(%r14), %r13
  vaesenc %xmm1, %xmm13, %xmm13
  movbeq 0(%r14), %r12
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 32(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  vaesenc %xmm1, %xmm9, %xmm9
  vaesenc %xmm1, %xmm10, %xmm10
  vaesenc %xmm1, %xmm11, %xmm11
  vaesenc %xmm1, %xmm12, %xmm12
  vaesenc %xmm1, %xmm13, %xmm13
  movdqu 48(%rcx), %xmm15
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 64(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  vaesenc %xmm1, %xmm9, %xmm9
  vaesenc %xmm1, %xmm10, %xmm10
  vaesenc %xmm1, %xmm11, %xmm11
  vaesenc %xmm1, %xmm12, %xmm12
  vaesenc %xmm1, %xmm13, %xmm13
  movdqu 80(%rcx), %xmm15
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 96(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  movdqu %xmm7, 16(%rbp)
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vaesenc %xmm15, %xmm10, %xmm10
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor 0(%rdi), %xmm1, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 16(%rdi), %xmm1, %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 32(%rdi), %xmm1, %xmm5
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 48(%rdi), %xmm1, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 64(%rdi), %xmm1, %xmm7
  vpxor 80(%rdi), %xmm1, %xmm3
  movdqu 0(%r8), %xmm1
  vaesenclast %xmm2, %xmm9, %xmm9
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vaesenclast %xmm0, %xmm10, %xmm10
  vpaddd %xmm2, %xmm1, %xmm0
  movq %r13, 112(%rbp)
  lea 96(%rdi), %rdi
  vaesenclast %xmm5, %xmm11, %xmm11
  vpaddd %xmm2, %xmm0, %xmm5
  movq %r12, 120(%rbp)
  lea 96(%rsi), %rsi
  movdqu -128(%rcx), %xmm15
  vaesenclast %xmm6, %xmm12, %xmm12
  vpaddd %xmm2, %xmm5, %xmm6
  vaesenclast %xmm7, %xmm13, %xmm13
  vpaddd %xmm2, %xmm6, %xmm7
  vaesenclast %xmm3, %xmm14, %xmm14
  vpaddd %xmm2, %xmm7, %xmm3
  sub $6, %rdx
  add $96, %r14
  cmp $0, %rdx
  jbe L228
  movdqu %xmm9, -96(%rsi)
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm10, -80(%rsi)
  movdqu %xmm0, %xmm10
  movdqu %xmm11, -64(%rsi)
  movdqu %xmm5, %xmm11
  movdqu %xmm12, -48(%rsi)
  movdqu %xmm6, %xmm12
  movdqu %xmm13, -32(%rsi)
  movdqu %xmm7, %xmm13
  movdqu %xmm14, -16(%rsi)
  movdqu %xmm3, %xmm14
  movdqu 32(%rbp), %xmm7
  jmp L229
L228:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L229:
.balign 16
L225:
  cmp $0, %rdx
  ja L224
  movdqu %xmm1, 0(%r8)
  movdqu 32(%rbp), %xmm7
  pxor %xmm4, %xmm4
  movdqu %xmm4, 0(%rbp)
  movdqu -32(%r9), %xmm3
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  movdqu 48(%rbp), %xmm0
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  movdqu -16(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vpxor 0(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  movdqu 16(%r9), %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vpxor %xmm5, %xmm6, %xmm6
  vpxor %xmm1, %xmm6, %xmm6
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $3254779904, %rax
  pinsrd $3, %eax, %xmm3
  vpxor %xmm8, %xmm7, %xmm7
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm5, %xmm4, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpsrldq $8, %xmm6, %xmm6
  vpxor %xmm6, %xmm7, %xmm7
  vpxor %xmm4, %xmm0, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor %xmm7, %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  movdqu %xmm9, -96(%rsi)
  vpshufb %xmm0, %xmm9, %xmm9
  vpxor %xmm7, %xmm1, %xmm1
  movdqu %xmm10, -80(%rsi)
  vpshufb %xmm0, %xmm10, %xmm10
  movdqu %xmm11, -64(%rsi)
  vpshufb %xmm0, %xmm11, %xmm11
  movdqu %xmm12, -48(%rsi)
  vpshufb %xmm0, %xmm12, %xmm12
  movdqu %xmm13, -32(%rsi)
  vpshufb %xmm0, %xmm13, %xmm13
  movdqu %xmm14, -16(%rsi)
  vpshufb %xmm0, %xmm14, %xmm14
  pxor %xmm4, %xmm4
  movdqu %xmm14, %xmm7
  movdqu %xmm4, 0(%rbp)
  movdqu %xmm13, 48(%rbp)
  movdqu %xmm12, 64(%rbp)
  movdqu %xmm11, 80(%rbp)
  movdqu %xmm10, 96(%rbp)
  movdqu %xmm9, 112(%rbp)
  movdqu -32(%r9), %xmm3
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  movdqu 48(%rbp), %xmm0
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  movdqu -16(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vpxor 0(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  movdqu 16(%r9), %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vpxor %xmm5, %xmm6, %xmm6
  vpxor %xmm1, %xmm6, %xmm6
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $3254779904, %rax
  pinsrd $3, %eax, %xmm3
  vpxor %xmm8, %xmm7, %xmm7
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm5, %xmm4, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpsrldq $8, %xmm6, %xmm6
  vpxor %xmm6, %xmm7, %xmm7
  vpxor %xmm4, %xmm0, %xmm4
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor %xmm7, %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm8, %xmm8
  sub $128, %rcx
L223:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 104(%rsp), %rax
  mov 112(%rsp), %rbx
  mov 120(%rsp), %rcx
  movdqu %xmm8, %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pshufb %xmm8, %xmm7
  movdqu 0(%r9), %xmm11
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L231
.balign 16
L230:
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%r9), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%r10)
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L231:
  cmp %rcx, %rdx
  jne L230
  add 96(%rsp), %rcx
  imul $16, %rcx
  mov 136(%rsp), %r13
  cmp %rcx, %r13
  jbe L232
  mov 128(%rsp), %rax
  mov %rax, %rbx
  mov %r13, %rcx
  and $15, %rcx
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  movdqu 0(%rax), %xmm2
  pxor %xmm0, %xmm2
  movdqu %xmm2, 0(%rbx)
  mov %rcx, %rax
  cmp $8, %rax
  jae L234
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L235
L234:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L235:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  jmp L233
L232:
L233:
  mov %r15, %r11
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  mov 152(%rsp), %r15
  movdqu %xmm1, 0(%r15)
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  ret

.global gcm128_decrypt_opt
gcm128_decrypt_opt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov 144(%rsp), %rbp
  mov %r8, %r13
  mov %r9, %r14
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  mov %rdi, %rax
  mov %rcx, %r8
  mov %rdx, %r11
  movdqu 32(%r9), %xmm11
  pxor %xmm1, %xmm1
  mov %r11, %rcx
  cmp $0, %rcx
  je L236
  mov $0, %rdx
  mov %rax, %r9
  jmp L239
.balign 16
L238:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L239:
  cmp %rcx, %rdx
  jne L238
  jmp L237
L236:
L237:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L240
  mov 72(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L242
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L243
L242:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L243:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  jmp L241
L240:
L241:
  mov %rsi, %r15
  mov 80(%rsp), %rdi
  mov 88(%rsp), %rsi
  mov 96(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L244
  lea 32(%r9), %r9
  movdqu 0(%r8), %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  movdqu %xmm1, 0(%r8)
  jmp L245
L244:
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  movdqu 0(%r8), %xmm1
  vpshufb %xmm0, %xmm8, %xmm8
  movdqu %xmm8, 0(%r8)
  add $128, %rcx
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  lea 96(%rdi), %r14
  movdqu 0(%r8), %xmm8
  lea 32(%r9), %r9
  movdqu 80(%rdi), %xmm7
  movdqu 64(%rdi), %xmm4
  movdqu 48(%rdi), %xmm5
  movdqu 32(%rdi), %xmm6
  vpshufb %xmm0, %xmm7, %xmm7
  movdqu 16(%rdi), %xmm2
  vpshufb %xmm0, %xmm4, %xmm4
  movdqu 0(%rdi), %xmm3
  vpshufb %xmm0, %xmm5, %xmm5
  movdqu %xmm4, 48(%rbp)
  vpshufb %xmm0, %xmm6, %xmm6
  movdqu %xmm5, 64(%rbp)
  vpshufb %xmm0, %xmm2, %xmm2
  movdqu %xmm6, 80(%rbp)
  vpshufb %xmm0, %xmm3, %xmm3
  movdqu %xmm2, 96(%rbp)
  movdqu %xmm3, 112(%rbp)
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vpxor %xmm4, %xmm4, %xmm4
  movdqu -128(%rcx), %xmm15
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpaddd %xmm2, %xmm11, %xmm12
  vpaddd %xmm2, %xmm12, %xmm13
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm4, 16(%rbp)
  mov $2, %rbx
  jmp L247
.balign 16
L246:
  add $6, %rbx
  cmp $256, %rbx
  jb L248
  mov $579005069656919567, %r11
  pinsrq $0, %r11, %xmm0
  mov $283686952306183, %r11
  pinsrq $1, %r11, %xmm0
  vpshufb %xmm0, %xmm1, %xmm6
  pxor %xmm5, %xmm5
  mov $1, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm10
  pxor %xmm5, %xmm5
  mov $2, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm11
  movdqu -32(%r9), %xmm3
  vpaddd %xmm5, %xmm10, %xmm12
  vpshufb %xmm0, %xmm10, %xmm10
  vpaddd %xmm5, %xmm11, %xmm13
  vpshufb %xmm0, %xmm11, %xmm11
  vpxor %xmm15, %xmm10, %xmm10
  vpaddd %xmm5, %xmm12, %xmm14
  vpshufb %xmm0, %xmm12, %xmm12
  vpxor %xmm15, %xmm11, %xmm11
  vpaddd %xmm5, %xmm13, %xmm1
  vpshufb %xmm0, %xmm13, %xmm13
  vpshufb %xmm0, %xmm14, %xmm14
  vpshufb %xmm0, %xmm1, %xmm1
  sub $256, %rbx
  jmp L249
L248:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L249:
  movdqu %xmm1, 0(%r8)
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  vpxor %xmm15, %xmm12, %xmm12
  movdqu -112(%rcx), %xmm2
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vaesenc %xmm2, %xmm9, %xmm9
  movdqu 48(%rbp), %xmm0
  vpxor %xmm15, %xmm13, %xmm13
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vaesenc %xmm2, %xmm10, %xmm10
  vpxor %xmm15, %xmm14, %xmm14
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  vaesenc %xmm2, %xmm11, %xmm11
  movdqu -16(%r9), %xmm3
  vaesenc %xmm2, %xmm12, %xmm12
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vaesenc %xmm2, %xmm13, %xmm13
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vaesenc %xmm2, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 16(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 88(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 80(%r14), %r12
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 32(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 40(%rbp)
  movdqu 16(%r9), %xmm5
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vaesenc %xmm15, %xmm11, %xmm11
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 72(%r14), %r13
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 64(%r14), %r12
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 48(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 56(%rbp)
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 56(%r14), %r13
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 48(%r14), %r12
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 64(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 72(%rbp)
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 40(%r14), %r13
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 32(%r14), %r12
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 80(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 88(%rbp)
  vpxor %xmm5, %xmm6, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor %xmm1, %xmm6, %xmm6
  movdqu -16(%rcx), %xmm15
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $13979173243358019584, %r11
  pinsrq $1, %r11, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm8, %xmm7, %xmm7
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm5, %xmm4, %xmm4
  movbeq 24(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 16(%r14), %r12
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  movq %r13, 96(%rbp)
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r12, 104(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm1
  vaesenc %xmm1, %xmm9, %xmm9
  movdqu 16(%rcx), %xmm15
  vaesenc %xmm1, %xmm10, %xmm10
  vpsrldq $8, %xmm6, %xmm6
  vaesenc %xmm1, %xmm11, %xmm11
  vpxor %xmm6, %xmm7, %xmm7
  vaesenc %xmm1, %xmm12, %xmm12
  vpxor %xmm0, %xmm4, %xmm4
  movbeq 8(%r14), %r13
  vaesenc %xmm1, %xmm13, %xmm13
  movbeq 0(%r14), %r12
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 32(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  movdqu %xmm7, 16(%rbp)
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vaesenc %xmm15, %xmm10, %xmm10
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor 0(%rdi), %xmm1, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 16(%rdi), %xmm1, %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 32(%rdi), %xmm1, %xmm5
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 48(%rdi), %xmm1, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 64(%rdi), %xmm1, %xmm7
  vpxor 80(%rdi), %xmm1, %xmm3
  movdqu 0(%r8), %xmm1
  vaesenclast %xmm2, %xmm9, %xmm9
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vaesenclast %xmm0, %xmm10, %xmm10
  vpaddd %xmm2, %xmm1, %xmm0
  movq %r13, 112(%rbp)
  lea 96(%rdi), %rdi
  vaesenclast %xmm5, %xmm11, %xmm11
  vpaddd %xmm2, %xmm0, %xmm5
  movq %r12, 120(%rbp)
  lea 96(%rsi), %rsi
  movdqu -128(%rcx), %xmm15
  vaesenclast %xmm6, %xmm12, %xmm12
  vpaddd %xmm2, %xmm5, %xmm6
  vaesenclast %xmm7, %xmm13, %xmm13
  vpaddd %xmm2, %xmm6, %xmm7
  vaesenclast %xmm3, %xmm14, %xmm14
  vpaddd %xmm2, %xmm7, %xmm3
  sub $6, %rdx
  cmp $6, %rdx
  jbe L250
  add $96, %r14
  jmp L251
L250:
L251:
  cmp $0, %rdx
  jbe L252
  movdqu %xmm9, -96(%rsi)
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm10, -80(%rsi)
  movdqu %xmm0, %xmm10
  movdqu %xmm11, -64(%rsi)
  movdqu %xmm5, %xmm11
  movdqu %xmm12, -48(%rsi)
  movdqu %xmm6, %xmm12
  movdqu %xmm13, -32(%rsi)
  movdqu %xmm7, %xmm13
  movdqu %xmm14, -16(%rsi)
  movdqu %xmm3, %xmm14
  movdqu 32(%rbp), %xmm7
  jmp L253
L252:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L253:
.balign 16
L247:
  cmp $0, %rdx
  ja L246
  movdqu %xmm1, 0(%r8)
  movdqu %xmm9, -96(%rsi)
  movdqu %xmm10, -80(%rsi)
  movdqu %xmm11, -64(%rsi)
  movdqu %xmm12, -48(%rsi)
  movdqu %xmm13, -32(%rsi)
  movdqu %xmm14, -16(%rsi)
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm8, %xmm8
  sub $128, %rcx
L245:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 104(%rsp), %rax
  mov 112(%rsp), %rbx
  mov 120(%rsp), %rcx
  movdqu %xmm8, %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pshufb %xmm8, %xmm7
  movdqu 0(%r9), %xmm11
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L255
.balign 16
L254:
  movdqu 0(%r9), %xmm0
  movdqu %xmm0, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm3
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm3
  movdqu %xmm3, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L255:
  cmp %rcx, %rdx
  jne L254
  add 96(%rsp), %rcx
  imul $16, %rcx
  mov 136(%rsp), %r13
  cmp %rcx, %r13
  jbe L256
  mov 128(%rsp), %rax
  mov %rax, %rbx
  mov %r13, %rcx
  and $15, %rcx
  movdqu 0(%rax), %xmm2
  movdqu %xmm2, %xmm0
  mov %rcx, %rax
  cmp $8, %rax
  jae L258
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L259
L258:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L259:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm6
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm6
  movdqu %xmm6, 0(%rbx)
  jmp L257
L256:
L257:
  mov %r15, %r11
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  mov 152(%rsp), %r15
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L260
  mov $0, %rax
  jmp L261
L260:
  mov $1, %rax
L261:
  pextrq $1, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L262
  mov $0, %rdx
  jmp L263
L262:
  mov $1, %rdx
L263:
  add %rdx, %rax
  mov %rax, %rcx
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  mov %rcx, %rax
  ret

.global gcm256_decrypt_opt
gcm256_decrypt_opt:
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  mov 144(%rsp), %rbp
  mov %r8, %r13
  mov %r9, %r14
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  mov %rdi, %rax
  mov %rcx, %r8
  mov %rdx, %r11
  movdqu 32(%r9), %xmm11
  pxor %xmm1, %xmm1
  mov %r11, %rcx
  cmp $0, %rcx
  je L264
  mov $0, %rdx
  mov %rax, %r9
  jmp L267
.balign 16
L266:
  movdqu 0(%r9), %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  add $1, %rdx
  add $16, %r9
.balign 16
L267:
  cmp %rcx, %rdx
  jne L266
  jmp L265
L264:
L265:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L268
  mov 72(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L270
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L271
L270:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L271:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  jmp L269
L268:
L269:
  mov %rsi, %r15
  mov 80(%rsp), %rdi
  mov 88(%rsp), %rsi
  mov 96(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L272
  lea 32(%r9), %r9
  movdqu 0(%r8), %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  movdqu %xmm1, 0(%r8)
  jmp L273
L272:
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  movdqu 0(%r8), %xmm1
  vpshufb %xmm0, %xmm8, %xmm8
  movdqu %xmm8, 0(%r8)
  add $128, %rcx
  vpshufb %xmm0, %xmm1, %xmm1
  mov $2, %rbx
  pinsrd $0, %ebx, %xmm1
  vpshufb %xmm0, %xmm1, %xmm1
  lea 96(%rdi), %r14
  movdqu 0(%r8), %xmm8
  lea 32(%r9), %r9
  movdqu 80(%rdi), %xmm7
  movdqu 64(%rdi), %xmm4
  movdqu 48(%rdi), %xmm5
  movdqu 32(%rdi), %xmm6
  vpshufb %xmm0, %xmm7, %xmm7
  movdqu 16(%rdi), %xmm2
  vpshufb %xmm0, %xmm4, %xmm4
  movdqu 0(%rdi), %xmm3
  vpshufb %xmm0, %xmm5, %xmm5
  movdqu %xmm4, 48(%rbp)
  vpshufb %xmm0, %xmm6, %xmm6
  movdqu %xmm5, 64(%rbp)
  vpshufb %xmm0, %xmm2, %xmm2
  movdqu %xmm6, 80(%rbp)
  vpshufb %xmm0, %xmm3, %xmm3
  movdqu %xmm2, 96(%rbp)
  movdqu %xmm3, 112(%rbp)
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vpxor %xmm4, %xmm4, %xmm4
  movdqu -128(%rcx), %xmm15
  vpaddd %xmm2, %xmm1, %xmm10
  vpaddd %xmm2, %xmm10, %xmm11
  vpaddd %xmm2, %xmm11, %xmm12
  vpaddd %xmm2, %xmm12, %xmm13
  vpaddd %xmm2, %xmm13, %xmm14
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm4, 16(%rbp)
  mov $2, %rbx
  jmp L275
.balign 16
L274:
  add $6, %rbx
  cmp $256, %rbx
  jb L276
  mov $579005069656919567, %r11
  pinsrq $0, %r11, %xmm0
  mov $283686952306183, %r11
  pinsrq $1, %r11, %xmm0
  vpshufb %xmm0, %xmm1, %xmm6
  pxor %xmm5, %xmm5
  mov $1, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm10
  pxor %xmm5, %xmm5
  mov $2, %r11
  pinsrq $0, %r11, %xmm5
  vpaddd %xmm5, %xmm6, %xmm11
  movdqu -32(%r9), %xmm3
  vpaddd %xmm5, %xmm10, %xmm12
  vpshufb %xmm0, %xmm10, %xmm10
  vpaddd %xmm5, %xmm11, %xmm13
  vpshufb %xmm0, %xmm11, %xmm11
  vpxor %xmm15, %xmm10, %xmm10
  vpaddd %xmm5, %xmm12, %xmm14
  vpshufb %xmm0, %xmm12, %xmm12
  vpxor %xmm15, %xmm11, %xmm11
  vpaddd %xmm5, %xmm13, %xmm1
  vpshufb %xmm0, %xmm13, %xmm13
  vpshufb %xmm0, %xmm14, %xmm14
  vpshufb %xmm0, %xmm1, %xmm1
  sub $256, %rbx
  jmp L277
L276:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L277:
  movdqu %xmm1, 0(%r8)
  vpclmulqdq $16, %xmm3, %xmm7, %xmm5
  vpxor %xmm15, %xmm12, %xmm12
  movdqu -112(%rcx), %xmm2
  vpclmulqdq $1, %xmm3, %xmm7, %xmm6
  vaesenc %xmm2, %xmm9, %xmm9
  movdqu 48(%rbp), %xmm0
  vpxor %xmm15, %xmm13, %xmm13
  vpclmulqdq $0, %xmm3, %xmm7, %xmm1
  vaesenc %xmm2, %xmm10, %xmm10
  vpxor %xmm15, %xmm14, %xmm14
  vpclmulqdq $17, %xmm3, %xmm7, %xmm7
  vaesenc %xmm2, %xmm11, %xmm11
  movdqu -16(%r9), %xmm3
  vaesenc %xmm2, %xmm12, %xmm12
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $0, %xmm3, %xmm0, %xmm5
  vpxor %xmm4, %xmm8, %xmm8
  vaesenc %xmm2, %xmm13, %xmm13
  vpxor %xmm5, %xmm1, %xmm4
  vpclmulqdq $16, %xmm3, %xmm0, %xmm1
  vaesenc %xmm2, %xmm14, %xmm14
  movdqu -96(%rcx), %xmm15
  vpclmulqdq $1, %xmm3, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor 16(%rbp), %xmm8, %xmm8
  vpclmulqdq $17, %xmm3, %xmm0, %xmm3
  movdqu 64(%rbp), %xmm0
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 88(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 80(%r14), %r12
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 32(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 40(%rbp)
  movdqu 16(%r9), %xmm5
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -80(%rcx), %xmm15
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $0, %xmm5, %xmm0, %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $16, %xmm5, %xmm0, %xmm2
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm3, %xmm7, %xmm7
  vpclmulqdq $1, %xmm5, %xmm0, %xmm3
  vaesenc %xmm15, %xmm11, %xmm11
  vpclmulqdq $17, %xmm5, %xmm0, %xmm5
  movdqu 80(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor %xmm1, %xmm4, %xmm4
  movdqu 32(%r9), %xmm1
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -64(%rcx), %xmm15
  vpxor %xmm2, %xmm6, %xmm6
  vpclmulqdq $0, %xmm1, %xmm0, %xmm2
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $16, %xmm1, %xmm0, %xmm3
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 72(%r14), %r13
  vpxor %xmm5, %xmm7, %xmm7
  vpclmulqdq $1, %xmm1, %xmm0, %xmm5
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 64(%r14), %r12
  vpclmulqdq $17, %xmm1, %xmm0, %xmm1
  movdqu 96(%rbp), %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 48(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 56(%rbp)
  vpxor %xmm2, %xmm4, %xmm4
  movdqu 64(%r9), %xmm2
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -48(%rcx), %xmm15
  vpxor %xmm3, %xmm6, %xmm6
  vpclmulqdq $0, %xmm2, %xmm0, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm2, %xmm0, %xmm5
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 56(%r14), %r13
  vpxor %xmm1, %xmm7, %xmm7
  vpclmulqdq $1, %xmm2, %xmm0, %xmm1
  vpxor 112(%rbp), %xmm8, %xmm8
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 48(%r14), %r12
  vpclmulqdq $17, %xmm2, %xmm0, %xmm2
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 64(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 72(%rbp)
  vpxor %xmm3, %xmm4, %xmm4
  movdqu 80(%r9), %xmm3
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu -32(%rcx), %xmm15
  vpxor %xmm5, %xmm6, %xmm6
  vpclmulqdq $16, %xmm3, %xmm8, %xmm5
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm1, %xmm6, %xmm6
  vpclmulqdq $1, %xmm3, %xmm8, %xmm1
  vaesenc %xmm15, %xmm10, %xmm10
  movbeq 40(%r14), %r13
  vpxor %xmm2, %xmm7, %xmm7
  vpclmulqdq $0, %xmm3, %xmm8, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 32(%r14), %r12
  vpclmulqdq $17, %xmm3, %xmm8, %xmm8
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r13, 80(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  movq %r12, 88(%rbp)
  vpxor %xmm5, %xmm6, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor %xmm1, %xmm6, %xmm6
  movdqu -16(%rcx), %xmm15
  vpslldq $8, %xmm6, %xmm5
  vpxor %xmm2, %xmm4, %xmm4
  pxor %xmm3, %xmm3
  mov $13979173243358019584, %r11
  pinsrq $1, %r11, %xmm3
  vaesenc %xmm15, %xmm9, %xmm9
  vpxor %xmm8, %xmm7, %xmm7
  vaesenc %xmm15, %xmm10, %xmm10
  vpxor %xmm5, %xmm4, %xmm4
  movbeq 24(%r14), %r13
  vaesenc %xmm15, %xmm11, %xmm11
  movbeq 16(%r14), %r12
  vpalignr $8, %xmm4, %xmm4, %xmm0
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  movq %r13, 96(%rbp)
  vaesenc %xmm15, %xmm12, %xmm12
  movq %r12, 104(%rbp)
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  movdqu 0(%rcx), %xmm1
  vaesenc %xmm1, %xmm9, %xmm9
  movdqu 16(%rcx), %xmm15
  vaesenc %xmm1, %xmm10, %xmm10
  vpsrldq $8, %xmm6, %xmm6
  vaesenc %xmm1, %xmm11, %xmm11
  vpxor %xmm6, %xmm7, %xmm7
  vaesenc %xmm1, %xmm12, %xmm12
  vpxor %xmm0, %xmm4, %xmm4
  movbeq 8(%r14), %r13
  vaesenc %xmm1, %xmm13, %xmm13
  movbeq 0(%r14), %r12
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 32(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  vaesenc %xmm1, %xmm9, %xmm9
  vaesenc %xmm1, %xmm10, %xmm10
  vaesenc %xmm1, %xmm11, %xmm11
  vaesenc %xmm1, %xmm12, %xmm12
  vaesenc %xmm1, %xmm13, %xmm13
  movdqu 48(%rcx), %xmm15
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 64(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  vaesenc %xmm15, %xmm10, %xmm10
  vaesenc %xmm15, %xmm11, %xmm11
  vaesenc %xmm15, %xmm12, %xmm12
  vaesenc %xmm15, %xmm13, %xmm13
  vaesenc %xmm15, %xmm14, %xmm14
  vaesenc %xmm1, %xmm9, %xmm9
  vaesenc %xmm1, %xmm10, %xmm10
  vaesenc %xmm1, %xmm11, %xmm11
  vaesenc %xmm1, %xmm12, %xmm12
  vaesenc %xmm1, %xmm13, %xmm13
  movdqu 80(%rcx), %xmm15
  vaesenc %xmm1, %xmm14, %xmm14
  movdqu 96(%rcx), %xmm1
  vaesenc %xmm15, %xmm9, %xmm9
  movdqu %xmm7, 16(%rbp)
  vpalignr $8, %xmm4, %xmm4, %xmm8
  vaesenc %xmm15, %xmm10, %xmm10
  vpclmulqdq $16, %xmm3, %xmm4, %xmm4
  vpxor 0(%rdi), %xmm1, %xmm2
  vaesenc %xmm15, %xmm11, %xmm11
  vpxor 16(%rdi), %xmm1, %xmm0
  vaesenc %xmm15, %xmm12, %xmm12
  vpxor 32(%rdi), %xmm1, %xmm5
  vaesenc %xmm15, %xmm13, %xmm13
  vpxor 48(%rdi), %xmm1, %xmm6
  vaesenc %xmm15, %xmm14, %xmm14
  vpxor 64(%rdi), %xmm1, %xmm7
  vpxor 80(%rdi), %xmm1, %xmm3
  movdqu 0(%r8), %xmm1
  vaesenclast %xmm2, %xmm9, %xmm9
  pxor %xmm2, %xmm2
  mov $72057594037927936, %r11
  pinsrq $1, %r11, %xmm2
  vaesenclast %xmm0, %xmm10, %xmm10
  vpaddd %xmm2, %xmm1, %xmm0
  movq %r13, 112(%rbp)
  lea 96(%rdi), %rdi
  vaesenclast %xmm5, %xmm11, %xmm11
  vpaddd %xmm2, %xmm0, %xmm5
  movq %r12, 120(%rbp)
  lea 96(%rsi), %rsi
  movdqu -128(%rcx), %xmm15
  vaesenclast %xmm6, %xmm12, %xmm12
  vpaddd %xmm2, %xmm5, %xmm6
  vaesenclast %xmm7, %xmm13, %xmm13
  vpaddd %xmm2, %xmm6, %xmm7
  vaesenclast %xmm3, %xmm14, %xmm14
  vpaddd %xmm2, %xmm7, %xmm3
  sub $6, %rdx
  cmp $6, %rdx
  jbe L278
  add $96, %r14
  jmp L279
L278:
L279:
  cmp $0, %rdx
  jbe L280
  movdqu %xmm9, -96(%rsi)
  vpxor %xmm15, %xmm1, %xmm9
  movdqu %xmm10, -80(%rsi)
  movdqu %xmm0, %xmm10
  movdqu %xmm11, -64(%rsi)
  movdqu %xmm5, %xmm11
  movdqu %xmm12, -48(%rsi)
  movdqu %xmm6, %xmm12
  movdqu %xmm13, -32(%rsi)
  movdqu %xmm7, %xmm13
  movdqu %xmm14, -16(%rsi)
  movdqu %xmm3, %xmm14
  movdqu 32(%rbp), %xmm7
  jmp L281
L280:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L281:
.balign 16
L275:
  cmp $0, %rdx
  ja L274
  movdqu %xmm1, 0(%r8)
  movdqu %xmm9, -96(%rsi)
  movdqu %xmm10, -80(%rsi)
  movdqu %xmm11, -64(%rsi)
  movdqu %xmm12, -48(%rsi)
  movdqu %xmm13, -32(%rsi)
  movdqu %xmm14, -16(%rsi)
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm0
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm0
  vpshufb %xmm0, %xmm8, %xmm8
  sub $128, %rcx
L273:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 104(%rsp), %rax
  mov 112(%rsp), %rbx
  mov 120(%rsp), %rcx
  movdqu %xmm8, %xmm1
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm8
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm8
  pshufb %xmm8, %xmm7
  movdqu 0(%r9), %xmm11
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L283
.balign 16
L282:
  movdqu 0(%r9), %xmm0
  movdqu %xmm0, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm3
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm3
  movdqu %xmm3, 0(%r10)
  add $1, %rdx
  add $16, %r9
  add $16, %r10
  paddd %xmm10, %xmm7
.balign 16
L283:
  cmp %rcx, %rdx
  jne L282
  add 96(%rsp), %rcx
  imul $16, %rcx
  mov 136(%rsp), %r13
  cmp %rcx, %r13
  jbe L284
  mov 128(%rsp), %rax
  mov %rax, %rbx
  mov %r13, %rcx
  and $15, %rcx
  movdqu 0(%rax), %xmm2
  movdqu %xmm2, %xmm0
  mov %rcx, %rax
  cmp $8, %rax
  jae L286
  mov $0, %rcx
  pinsrq $1, %rcx, %xmm2
  mov %rax, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $0, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $0, %rcx, %xmm2
  jmp L287
L286:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L287:
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  movdqu %xmm0, %xmm6
  movdqu %xmm7, %xmm0
  pshufb %xmm8, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm6
  movdqu %xmm6, 0(%rbx)
  jmp L285
L284:
L285:
  mov %r15, %r11
  pxor %xmm2, %xmm2
  mov %r11, %rax
  imul $8, %rax
  pinsrq $1, %rax, %xmm2
  mov %r13, %rax
  imul $8, %rax
  pinsrq $0, %rax, %xmm2
  pshufb %xmm8, %xmm2
  pxor %xmm2, %xmm1
  movdqu %xmm11, %xmm2
  pshufb %xmm8, %xmm1
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm6
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  movdqu %xmm1, %xmm5
  pclmulqdq $16, %xmm2, %xmm1
  movdqu %xmm1, %xmm3
  movdqu %xmm5, %xmm1
  pclmulqdq $1, %xmm2, %xmm1
  movdqu %xmm1, %xmm4
  movdqu %xmm5, %xmm1
  pclmulqdq $0, %xmm2, %xmm1
  pclmulqdq $17, %xmm2, %xmm5
  movdqu %xmm5, %xmm2
  movdqu %xmm1, %xmm5
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm4, %xmm1
  mov $0, %r12
  pinsrd $0, %r12d, %xmm1
  pshufd $14, %xmm1, %xmm1
  pxor %xmm1, %xmm2
  movdqu %xmm3, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm1
  pshufd $79, %xmm1, %xmm1
  mov $0, %r12
  pinsrd $3, %r12d, %xmm4
  pshufd $79, %xmm4, %xmm4
  pxor %xmm4, %xmm1
  pxor %xmm5, %xmm1
  movdqu %xmm1, %xmm3
  psrld $31, %xmm3
  movdqu %xmm2, %xmm4
  psrld $31, %xmm4
  pslld $1, %xmm1
  pslld $1, %xmm2
  vpslldq $4, %xmm3, %xmm5
  vpslldq $4, %xmm4, %xmm4
  mov $0, %r12
  pinsrd $0, %r12d, %xmm3
  pshufd $3, %xmm3, %xmm3
  pxor %xmm4, %xmm3
  pxor %xmm5, %xmm1
  pxor %xmm3, %xmm2
  movdqu %xmm2, %xmm5
  pxor %xmm2, %xmm2
  mov $3774873600, %r12
  pinsrd $3, %r12d, %xmm2
  pclmulqdq $17, %xmm2, %xmm1
  movdqu %xmm1, %xmm2
  psrld $31, %xmm2
  pslld $1, %xmm1
  vpslldq $4, %xmm2, %xmm2
  pxor %xmm2, %xmm1
  pxor %xmm5, %xmm1
  pxor %xmm6, %xmm1
  pshufb %xmm8, %xmm1
  mov $1, %r12
  pinsrd $0, %r12d, %xmm7
  movdqu %xmm7, %xmm0
  mov $579005069656919567, %r12
  pinsrq $0, %r12, %xmm2
  mov $283686952306183, %r12
  pinsrq $1, %r12, %xmm2
  pshufb %xmm2, %xmm0
  movdqu 0(%r8), %xmm2
  pxor %xmm2, %xmm0
  movdqu 16(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 32(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 48(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 64(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 80(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 96(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 112(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 128(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 144(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 160(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 176(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 192(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 208(%r8), %xmm2
  aesenc %xmm2, %xmm0
  movdqu 224(%r8), %xmm2
  aesenclast %xmm2, %xmm0
  pxor %xmm2, %xmm2
  pxor %xmm0, %xmm1
  mov 152(%rsp), %r15
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L288
  mov $0, %rax
  jmp L289
L288:
  mov $1, %rax
L289:
  pextrq $1, %xmm0, %rdx
  cmp $18446744073709551615, %rdx
  jne L290
  mov $0, %rdx
  jmp L291
L290:
  mov $1, %rdx
L291:
  add %rdx, %rax
  mov %rax, %rcx
  pop %rbx
  pop %rbp
  pop %rdi
  pop %rsi
  pop %r12
  pop %r13
  pop %r14
  pop %r15
  mov %rcx, %rax
  ret


