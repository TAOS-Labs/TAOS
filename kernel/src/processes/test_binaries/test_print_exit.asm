section .data
  buffer db "Print exit syscall", 0

section .text
  global _start

_start:
  ; Set up registers for the custom syscall
  mov rax, 1003         ; Custom syscall number 1003 (print)
  mov rdi, buffer ; First argument: pointer to our string

  syscall

  mov rbx, 0xFFFFFF

_loop:
    sub rbx, 1
    cmp rbx, 0
    jg _loop

  ; Exit the program using the Linux exit syscall (number 1)
  mov rax, 60         ; syscall: exit
  xor rdi, rdi       ; exit code 0
  syscall
