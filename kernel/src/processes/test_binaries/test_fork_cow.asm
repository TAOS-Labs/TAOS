section .data
  buffer db "Hello from custom syscall!", 0

section .text
  global _start

_start:
  mov rax, 0x5
  syscall
  mov r12, rax
  cmp rax, 0x0
  je _child  
  mov byte [buffer], 'X'
  mov rdi, buffer
  mov rax, 0x3
  syscall
  mov rax, 60
  mov rdi, r12
  syscall

_child:
  mov byte [buffer + 1], 'B'
  mov rdi, buffer
  mov rax, 0x3
  syscall
  mov rax, 60
  mov rdi, r12
  syscall
