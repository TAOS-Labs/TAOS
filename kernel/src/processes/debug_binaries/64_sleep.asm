section .data
  buffer db "Before sleep!", 0

section .text
  global _start

_start:
  mov rax, 3
  mov rdi, buffer
  syscall

  mov rdi, 5000000000
  mov rax, 35
  syscall

  mov rdi, 0
  mov rax, 60
  syscall
