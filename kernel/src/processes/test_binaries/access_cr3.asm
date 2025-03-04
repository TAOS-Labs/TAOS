section .text
    global _start

_start:
    mov rdi, cr3
    mov rax, 60
    syscall
    