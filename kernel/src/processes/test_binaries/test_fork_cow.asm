; test_fork_cow.asm
; This test forks a process. The child modifies a copy-on-write mapping,
; prints its (unchanged) buffer, and exits.
; The parent waits for the child to complete, then modifies its own copy,
; prints its version of the buffer, and exits.

%define SYS_PRINT  3
%define SYS_FORK   5
%define SYS_WAIT   6
%define SYS_EXIT   60

section .data
    buffer db "Hello from custom syscall!", 0

section .text
  global _start

_start:
  ; Call fork (syscall number 0x5)
  mov rax, SYS_FORK
  syscall
  ; Save fork return value in r12
  mov r12, rax
  cmp rax, 0x0
  je _child

_parent:
  mov byte [buffer], 'X'
  mov rdi, buffer 
  mov rax, SYS_PRINT
  syscall ; print buffer

  ; Wait for child to finish 
  mov rdi, r12
  mov rax, SYS_WAIT
  syscall

  ; Exit parent with child pid
  mov rax, 60
  mov rdi, r12
  syscall

_child:
  mov byte [buffer + 1], 'B'
  mov rdi, buffer
  mov rax, SYS_PRINT
  syscall

  ; Exit child  with 
  mov rax, SYS_EXIT
  mov rdi, 0
  syscall
