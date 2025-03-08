section .text
  global _start

_start:
  mov rdi, 0x0
  mov rsi, 0x1000
  mov rdx, 0x6
  mov r10, 0x10
  mov r8, -1
  mov r9, 0x0
  mov rax, 0x4
  syscall

  mov byte [rax], 0x42

  mov bl, byte [rax] 
  cmp bl, 0x42
  je _finish

  mov rdi, -1
  mov rax, 60
  syscall

_finish: 
  mov rdi, 0x1
  mov rax, 60
  syscall
