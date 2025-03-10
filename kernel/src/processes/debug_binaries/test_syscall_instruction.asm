section .data
  buffer db "Hello, syscall print!", 0

section .text
  global _start

_start:
  mov rdi, buffer
  mov rax, 3
  syscall ; print
  cmp rax, 0
  je _finish
  
  mov rdi, -1
  mov rax, 60
  syscall ; exit

_finish: 
  mov rdi, 0
  mov rax, 60
  syscall
