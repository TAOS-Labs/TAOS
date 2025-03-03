section .text
  global _start

_start:
  mov rax, 5
  int 0x80; Create a child process
  cmp rax, 0 
  je _child ; if child, jump to child label 

  mov rbx, rax
  mov rax, 60
  int 0x80; exit with child pid

_child:
  mov rbx, rax
  mov rax, 60
  int 0x80; exit with code returned from child

