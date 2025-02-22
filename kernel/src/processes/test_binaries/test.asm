section .text
    global _start

_start:
    mov rax, 1 ; EXIT
    syscall

_loop:
  jmp _loop
