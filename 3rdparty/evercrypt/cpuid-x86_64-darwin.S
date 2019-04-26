.text
.global _check_aesni_stdcall
_check_aesni_stdcall:
  mov %rbx, %r9
  mov $1, %rax
  cpuid
  mov %rcx, %rax
  and $33554432, %rax
  shr $24, %rax
  and $2, %rcx
  and %rcx, %rax
  mov %r9, %rbx
  ret

.global _check_sha_stdcall
_check_sha_stdcall:
  mov %rbx, %r9
  mov $7, %rax
  mov $0, %rcx
  cpuid
  and $536870912, %rbx
  mov %rbx, %rax
  mov %r9, %rbx
  ret


