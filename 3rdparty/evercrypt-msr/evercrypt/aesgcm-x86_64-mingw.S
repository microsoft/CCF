.text
.global old_aes128_key_expansion
old_aes128_key_expansion:
  movdqu 0(%rcx), %xmm1
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
  movdqu 0(%rcx), %xmm1
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
  movdqu %xmm0, 80(%rdx)
  mov %rcx, %r8
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
  mov %rdx, %rcx
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
  movdqu 0(%rcx), %xmm1
  movdqu 16(%rcx), %xmm3
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
  movdqu 0(%rcx), %xmm1
  movdqu 16(%rcx), %xmm3
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
  movdqu %xmm0, 80(%rdx)
  mov %rcx, %r8
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
  mov %rdx, %rcx
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov 272(%rsp), %rax
  movdqu 0(%rax), %xmm7
  mov %rcx, %rax
  mov %r8, %rbx
  mov %rdx, %rsi
  mov %r9, %r13
  mov 264(%rsp), %r8
  mov 280(%rsp), %rcx
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
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov 272(%rsp), %rax
  movdqu 0(%rax), %xmm7
  mov %rcx, %rax
  mov %r8, %rbx
  mov %rdx, %rsi
  mov %r9, %r13
  mov 264(%rsp), %r8
  mov 280(%rsp), %rcx
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
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  mov %rcx, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
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
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %r14
  mov %rdx, %r13
  mov %r8, %rax
  mov %r9, %r11
  mov 264(%rsp), %r10
  mov 272(%rsp), %r8
  mov 280(%rsp), %rbx
  mov 288(%rsp), %r15
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
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  mov %rcx, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
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
  sub $18446744073709551615, %rdx
  mov $0, %rax
  adc $0, %rax
  pextrq $1, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rdx
  adc $0, %rdx
  add %rdx, %rax
  mov %rax, %rdx
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %r14
  mov %rdx, %r13
  mov %r8, %rax
  mov %r9, %r11
  mov 264(%rsp), %r10
  mov 272(%rsp), %r8
  mov 280(%rsp), %rbx
  mov 288(%rsp), %r15
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
  jbe L78
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L80
  mov $0, %rdx
  jmp L83
.balign 16
L82:
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
L83:
  cmp %rcx, %rdx
  jne L82
  jmp L81
L80:
L81:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L84
  jmp L85
L84:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L86
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
  jmp L87
L86:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L87:
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
L85:
  jmp L79
L78:
L79:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L88
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L91
.balign 16
L90:
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
L91:
  cmp %rcx, %rdx
  jne L90
  cmp $0, %rsi
  jne L92
  jmp L93
L92:
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
  jae L94
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
  jmp L95
L94:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L95:
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
L93:
  jmp L89
L88:
L89:
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
  sub $18446744073709551615, %rdx
  mov $0, %rax
  adc $0, %rax
  pextrq $1, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rdx
  adc $0, %rdx
  add %rdx, %rax
  pop %rdx
  pinsrq $1, %rdx, %xmm6
  pop %rdx
  pinsrq $0, %rdx, %xmm6
  pop %rdx
  pinsrq $1, %rdx, %xmm7
  pop %rdx
  pinsrq $0, %rdx, %xmm7
  pop %rdx
  pinsrq $1, %rdx, %xmm8
  pop %rdx
  pinsrq $0, %rdx, %xmm8
  pop %rdx
  pinsrq $1, %rdx, %xmm9
  pop %rdx
  pinsrq $0, %rdx, %xmm9
  pop %rdx
  pinsrq $1, %rdx, %xmm10
  pop %rdx
  pinsrq $0, %rdx, %xmm10
  pop %rdx
  pinsrq $1, %rdx, %xmm11
  pop %rdx
  pinsrq $0, %rdx, %xmm11
  pop %rdx
  pinsrq $1, %rdx, %xmm12
  pop %rdx
  pinsrq $0, %rdx, %xmm12
  pop %rdx
  pinsrq $1, %rdx, %xmm13
  pop %rdx
  pinsrq $0, %rdx, %xmm13
  pop %rdx
  pinsrq $1, %rdx, %xmm14
  pop %rdx
  pinsrq $0, %rdx, %xmm14
  pop %rdx
  pinsrq $1, %rdx, %xmm15
  pop %rdx
  pinsrq $0, %rdx, %xmm15
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
  mov %rcx, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
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
  jbe L96
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L98
  mov $0, %rdx
  jmp L101
.balign 16
L100:
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
L101:
  cmp %rcx, %rdx
  jne L100
  jmp L99
L98:
L99:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L102
  jmp L103
L102:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L104
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
  jmp L105
L104:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L105:
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
L103:
  jmp L97
L96:
L97:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L106
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L108
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
  jmp L111
.balign 16
L110:
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
L111:
  cmp $0, %rdx
  ja L110
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L109
L108:
L109:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L113
.balign 16
L112:
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
L113:
  cmp %rcx, %rdx
  jne L112
  cmp $0, %rsi
  jne L114
  jmp L115
L114:
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
  jae L116
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
  jmp L117
L116:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L117:
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
L115:
  jmp L107
L106:
L107:
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
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %r14
  mov %rdx, %r13
  mov %r8, %rax
  mov %r9, %r11
  mov 264(%rsp), %r10
  mov 272(%rsp), %r8
  mov 280(%rsp), %rbx
  mov 288(%rsp), %r15
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
  jbe L118
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L120
  mov $0, %rdx
  jmp L123
.balign 16
L122:
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
L123:
  cmp %rcx, %rdx
  jne L122
  jmp L121
L120:
L121:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L124
  jmp L125
L124:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L126
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
  jmp L127
L126:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L127:
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
L125:
  jmp L119
L118:
L119:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L128
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov %rcx, %rdx
  shr $2, %rdx
  and $3, %rcx
  cmp $0, %rdx
  jbe L130
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
  jmp L133
.balign 16
L132:
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
L133:
  cmp $0, %rdx
  ja L132
  movdqu %xmm9, %xmm7
  pinsrq $0, %rdi, %xmm7
  pshufb %xmm8, %xmm7
  mov %r9, %rax
  mov %r10, %rbx
  jmp L131
L130:
L131:
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L135
.balign 16
L134:
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
L135:
  cmp %rcx, %rdx
  jne L134
  cmp $0, %rsi
  jne L136
  jmp L137
L136:
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
  jae L138
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
  jmp L139
L138:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L139:
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
L137:
  jmp L129
L128:
L129:
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
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  mov %rcx, %r9
  push %r15
  push %r14
  push %r13
  push %r12
  push %rsi
  push %rdi
  push %rbp
  push %rbx
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
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
  jbe L140
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L142
  mov $0, %rdx
  jmp L145
.balign 16
L144:
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
L145:
  cmp %rcx, %rdx
  jne L144
  jmp L143
L142:
L143:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L146
  jmp L147
L146:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L148
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
  jmp L149
L148:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L149:
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
L147:
  jmp L141
L140:
L141:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L150
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L153
.balign 16
L152:
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
L153:
  cmp %rcx, %rdx
  jne L152
  cmp $0, %rsi
  jne L154
  jmp L155
L154:
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
  jmp L151
L150:
L151:
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
  sub $18446744073709551615, %rdx
  mov $0, %rax
  adc $0, %rax
  pextrq $1, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rdx
  adc $0, %rdx
  add %rdx, %rax
  mov %rax, %rdx
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %r14
  mov %rdx, %r13
  mov %r8, %rax
  mov %r9, %r11
  mov 264(%rsp), %r10
  mov 272(%rsp), %r8
  mov 280(%rsp), %rbx
  mov 288(%rsp), %r15
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
  jbe L158
  mov %r11, %rcx
  shr $4, %rcx
  mov %rax, %r9
  cmp $0, %rcx
  je L160
  mov $0, %rdx
  jmp L163
.balign 16
L162:
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
L163:
  cmp %rcx, %rdx
  jne L162
  jmp L161
L160:
L161:
  mov %r11, %rax
  and $15, %rax
  cmp $0, %rax
  jne L164
  jmp L165
L164:
  movdqu 0(%r9), %xmm2
  cmp $8, %rax
  jae L166
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
  jmp L167
L166:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L167:
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
L165:
  jmp L159
L158:
L159:
  mov %r14, %rax
  mov %r13, %rcx
  cmp $0, %rcx
  jbe L168
  mov %rcx, %rsi
  and $15, %rsi
  shr $4, %rcx
  mov $0, %rdx
  mov %rax, %r9
  mov %rbx, %r10
  pxor %xmm10, %xmm10
  mov $1, %r12
  pinsrd $0, %r12d, %xmm10
  jmp L171
.balign 16
L170:
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
L171:
  cmp %rcx, %rdx
  jne L170
  cmp $0, %rsi
  jne L172
  jmp L173
L172:
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
  jae L174
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
  jmp L175
L174:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L175:
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
L173:
  jmp L169
L168:
L169:
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
  sub $18446744073709551615, %rdx
  mov $0, %rax
  adc $0, %rax
  pextrq $1, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rdx
  adc $0, %rdx
  add %rdx, %rax
  pop %rdx
  pinsrq $1, %rdx, %xmm6
  pop %rdx
  pinsrq $0, %rdx, %xmm6
  pop %rdx
  pinsrq $1, %rdx, %xmm7
  pop %rdx
  pinsrq $0, %rdx, %xmm7
  pop %rdx
  pinsrq $1, %rdx, %xmm8
  pop %rdx
  pinsrq $0, %rdx, %xmm8
  pop %rdx
  pinsrq $1, %rdx, %xmm9
  pop %rdx
  pinsrq $0, %rdx, %xmm9
  pop %rdx
  pinsrq $1, %rdx, %xmm10
  pop %rdx
  pinsrq $0, %rdx, %xmm10
  pop %rdx
  pinsrq $1, %rdx, %xmm11
  pop %rdx
  pinsrq $0, %rdx, %xmm11
  pop %rdx
  pinsrq $1, %rdx, %xmm12
  pop %rdx
  pinsrq $0, %rdx, %xmm12
  pop %rdx
  pinsrq $1, %rdx, %xmm13
  pop %rdx
  pinsrq $0, %rdx, %xmm13
  pop %rdx
  pinsrq $1, %rdx, %xmm14
  pop %rdx
  pinsrq $0, %rdx, %xmm14
  pop %rdx
  pinsrq $1, %rdx, %xmm15
  pop %rdx
  pinsrq $0, %rdx, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %rdi
  mov %rdx, %rsi
  mov %r8, %rdx
  mov %r9, %rcx
  mov 264(%rsp), %r8
  mov 272(%rsp), %r9
  mov 352(%rsp), %rbp
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
  je L176
  mov $0, %rdx
  mov %rax, %r9
  jmp L179
.balign 16
L178:
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
L179:
  cmp %rcx, %rdx
  jne L178
  jmp L177
L176:
L177:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L180
  mov 280(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L182
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
  jmp L183
L182:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L183:
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
  jmp L181
L180:
L181:
  mov %rsi, %r15
  mov 288(%rsp), %rdi
  mov 296(%rsp), %rsi
  mov 304(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L184
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
  jmp L185
L184:
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
  jmp L187
.balign 16
L186:
  add $6, %rbx
  cmp $256, %rbx
  jb L188
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
  jmp L189
L188:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L189:
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
  jbe L190
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
  jmp L191
L190:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L191:
.balign 16
L187:
  cmp $0, %rdx
  ja L186
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
L185:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 312(%rsp), %rax
  mov 320(%rsp), %rbx
  mov 328(%rsp), %rcx
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
  jmp L193
.balign 16
L192:
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
L193:
  cmp %rcx, %rdx
  jne L192
  add 304(%rsp), %rcx
  imul $16, %rcx
  mov 344(%rsp), %r13
  cmp %rcx, %r13
  jbe L194
  mov 336(%rsp), %rax
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
  jae L196
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
  jmp L197
L196:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L197:
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
  jmp L195
L194:
L195:
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
  mov 360(%rsp), %r15
  movdqu %xmm1, 0(%r15)
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %rdi
  mov %rdx, %rsi
  mov %r8, %rdx
  mov %r9, %rcx
  mov 264(%rsp), %r8
  mov 272(%rsp), %r9
  mov 352(%rsp), %rbp
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
  je L198
  mov $0, %rdx
  mov %rax, %r9
  jmp L201
.balign 16
L200:
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
L201:
  cmp %rcx, %rdx
  jne L200
  jmp L199
L198:
L199:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L202
  mov 280(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L204
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
  jmp L205
L204:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L205:
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
  jmp L203
L202:
L203:
  mov %rsi, %r15
  mov 288(%rsp), %rdi
  mov 296(%rsp), %rsi
  mov 304(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L206
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
  jmp L207
L206:
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
  jmp L209
.balign 16
L208:
  add $6, %rbx
  cmp $256, %rbx
  jb L210
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
  jmp L211
L210:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L211:
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
  jbe L212
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
  jmp L213
L212:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L213:
.balign 16
L209:
  cmp $0, %rdx
  ja L208
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
L207:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 312(%rsp), %rax
  mov 320(%rsp), %rbx
  mov 328(%rsp), %rcx
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
  jmp L215
.balign 16
L214:
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
L215:
  cmp %rcx, %rdx
  jne L214
  add 304(%rsp), %rcx
  imul $16, %rcx
  mov 344(%rsp), %r13
  cmp %rcx, %r13
  jbe L216
  mov 336(%rsp), %rax
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
  jae L218
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
  jmp L219
L218:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L219:
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
  jmp L217
L216:
L217:
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
  mov 360(%rsp), %r15
  movdqu %xmm1, 0(%r15)
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %rdi
  mov %rdx, %rsi
  mov %r8, %rdx
  mov %r9, %rcx
  mov 264(%rsp), %r8
  mov 272(%rsp), %r9
  mov 352(%rsp), %rbp
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
  je L220
  mov $0, %rdx
  mov %rax, %r9
  jmp L223
.balign 16
L222:
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
L223:
  cmp %rcx, %rdx
  jne L222
  jmp L221
L220:
L221:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L224
  mov 280(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L226
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
  jmp L227
L226:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L227:
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
  jmp L225
L224:
L225:
  mov %rsi, %r15
  mov 288(%rsp), %rdi
  mov 296(%rsp), %rsi
  mov 304(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L228
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
  jmp L229
L228:
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
  jmp L231
.balign 16
L230:
  add $6, %rbx
  cmp $256, %rbx
  jb L232
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
  jmp L233
L232:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L233:
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
  jbe L234
  add $96, %r14
  jmp L235
L234:
L235:
  cmp $0, %rdx
  jbe L236
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
  jmp L237
L236:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L237:
.balign 16
L231:
  cmp $0, %rdx
  ja L230
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
L229:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 312(%rsp), %rax
  mov 320(%rsp), %rbx
  mov 328(%rsp), %rcx
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
  jmp L239
.balign 16
L238:
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
L239:
  cmp %rcx, %rdx
  jne L238
  add 304(%rsp), %rcx
  imul $16, %rcx
  mov 344(%rsp), %r13
  cmp %rcx, %r13
  jbe L240
  mov 336(%rsp), %rax
  mov %rax, %rbx
  mov %r13, %rcx
  and $15, %rcx
  movdqu 0(%rax), %xmm2
  movdqu %xmm2, %xmm0
  mov %rcx, %rax
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
  jmp L241
L240:
L241:
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
  mov 360(%rsp), %r15
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rax
  adc $0, %rax
  pextrq $1, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rdx
  adc $0, %rdx
  add %rdx, %rax
  mov %rax, %rcx
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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
  pextrq $0, %xmm15, %rax
  push %rax
  pextrq $1, %xmm15, %rax
  push %rax
  pextrq $0, %xmm14, %rax
  push %rax
  pextrq $1, %xmm14, %rax
  push %rax
  pextrq $0, %xmm13, %rax
  push %rax
  pextrq $1, %xmm13, %rax
  push %rax
  pextrq $0, %xmm12, %rax
  push %rax
  pextrq $1, %xmm12, %rax
  push %rax
  pextrq $0, %xmm11, %rax
  push %rax
  pextrq $1, %xmm11, %rax
  push %rax
  pextrq $0, %xmm10, %rax
  push %rax
  pextrq $1, %xmm10, %rax
  push %rax
  pextrq $0, %xmm9, %rax
  push %rax
  pextrq $1, %xmm9, %rax
  push %rax
  pextrq $0, %xmm8, %rax
  push %rax
  pextrq $1, %xmm8, %rax
  push %rax
  pextrq $0, %xmm7, %rax
  push %rax
  pextrq $1, %xmm7, %rax
  push %rax
  pextrq $0, %xmm6, %rax
  push %rax
  pextrq $1, %xmm6, %rax
  push %rax
  mov %rcx, %rdi
  mov %rdx, %rsi
  mov %r8, %rdx
  mov %r9, %rcx
  mov 264(%rsp), %r8
  mov 272(%rsp), %r9
  mov 352(%rsp), %rbp
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
  je L244
  mov $0, %rdx
  mov %rax, %r9
  jmp L247
.balign 16
L246:
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
L247:
  cmp %rcx, %rdx
  jne L246
  jmp L245
L244:
L245:
  imul $16, %r11
  cmp %r11, %rsi
  jbe L248
  mov 280(%rsp), %r11
  movdqu 0(%r11), %xmm2
  mov %rsi, %rax
  and $15, %rax
  cmp $8, %rax
  jae L250
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
  jmp L251
L250:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L251:
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
  jmp L249
L248:
L249:
  mov %rsi, %r15
  mov 288(%rsp), %rdi
  mov 296(%rsp), %rsi
  mov 304(%rsp), %rdx
  mov %r8, %rcx
  mov %r13, %r8
  mov %r14, %r9
  movdqu %xmm1, %xmm8
  cmp $0, %rdx
  jne L252
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
  jmp L253
L252:
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
  jmp L255
.balign 16
L254:
  add $6, %rbx
  cmp $256, %rbx
  jb L256
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
  jmp L257
L256:
  movdqu -32(%r9), %xmm3
  vpaddd %xmm14, %xmm2, %xmm1
  vpxor %xmm15, %xmm10, %xmm10
  vpxor %xmm15, %xmm11, %xmm11
L257:
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
  jbe L258
  add $96, %r14
  jmp L259
L258:
L259:
  cmp $0, %rdx
  jbe L260
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
  jmp L261
L260:
  vpxor 16(%rbp), %xmm8, %xmm8
  vpxor %xmm4, %xmm8, %xmm8
L261:
.balign 16
L255:
  cmp $0, %rdx
  ja L254
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
L253:
  movdqu 0(%r8), %xmm7
  mov %rcx, %r8
  mov 312(%rsp), %rax
  mov 320(%rsp), %rbx
  mov 328(%rsp), %rcx
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
  jmp L263
.balign 16
L262:
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
L263:
  cmp %rcx, %rdx
  jne L262
  add 304(%rsp), %rcx
  imul $16, %rcx
  mov 344(%rsp), %r13
  cmp %rcx, %r13
  jbe L264
  mov 336(%rsp), %rax
  mov %rax, %rbx
  mov %r13, %rcx
  and $15, %rcx
  movdqu 0(%rax), %xmm2
  movdqu %xmm2, %xmm0
  mov %rcx, %rax
  cmp $8, %rax
  jae L266
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
  jmp L267
L266:
  mov %rax, %rcx
  sub $8, %rcx
  shl $3, %rcx
  mov $1, %rdx
  shl %cl, %rdx
  sub $1, %rdx
  pextrq $1, %xmm2, %rcx
  and %rdx, %rcx
  pinsrq $1, %rcx, %xmm2
L267:
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
  jmp L265
L264:
L265:
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
  mov 360(%rsp), %r15
  movdqu 0(%r15), %xmm0
  pcmpeqd %xmm1, %xmm0
  pextrq $0, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rax
  adc $0, %rax
  pextrq $1, %xmm0, %rdx
  sub $18446744073709551615, %rdx
  mov $0, %rdx
  adc $0, %rdx
  add %rdx, %rax
  mov %rax, %rcx
  pop %rax
  pinsrq $1, %rax, %xmm6
  pop %rax
  pinsrq $0, %rax, %xmm6
  pop %rax
  pinsrq $1, %rax, %xmm7
  pop %rax
  pinsrq $0, %rax, %xmm7
  pop %rax
  pinsrq $1, %rax, %xmm8
  pop %rax
  pinsrq $0, %rax, %xmm8
  pop %rax
  pinsrq $1, %rax, %xmm9
  pop %rax
  pinsrq $0, %rax, %xmm9
  pop %rax
  pinsrq $1, %rax, %xmm10
  pop %rax
  pinsrq $0, %rax, %xmm10
  pop %rax
  pinsrq $1, %rax, %xmm11
  pop %rax
  pinsrq $0, %rax, %xmm11
  pop %rax
  pinsrq $1, %rax, %xmm12
  pop %rax
  pinsrq $0, %rax, %xmm12
  pop %rax
  pinsrq $1, %rax, %xmm13
  pop %rax
  pinsrq $0, %rax, %xmm13
  pop %rax
  pinsrq $1, %rax, %xmm14
  pop %rax
  pinsrq $0, %rax, %xmm14
  pop %rax
  pinsrq $1, %rax, %xmm15
  pop %rax
  pinsrq $0, %rax, %xmm15
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


