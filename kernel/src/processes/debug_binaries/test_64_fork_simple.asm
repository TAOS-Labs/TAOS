section .text
  global _start

_start:
  mov rax, 5
  int 0x80; Create a child process
  cmp rax, 0 
  je _child ; if child, jump to child label 

  push rax
  mov rbx, 5000000000
  mov rax, 35
  int 0x80; sleep, give child time to exit

  pop rax
  mov rbx, rax
  mov rax, 60
  int 0x80; exit with child pid

_child:
  mov rbx, rax
  mov rax, 60
  int 0x80; exit with code returned from child
