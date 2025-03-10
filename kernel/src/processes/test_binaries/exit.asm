section .text
    global _start

_start:
    mov rax, 60 ; EXIT
    syscall

_loop:
  jmp _loop
