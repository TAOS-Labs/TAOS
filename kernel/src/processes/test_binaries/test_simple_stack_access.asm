section .text
  global _start

_start:
  
  mov rax, 50 ; push something to the stack and see if we page fault
  push rax

  mov rax, 60 ; exit
  syscall
