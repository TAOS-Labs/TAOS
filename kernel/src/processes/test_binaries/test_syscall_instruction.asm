section .text
    global _start

_start:
    mov rax, 3
    syscall ; print
    mov rdi, 2
    mov rax, 60
    syscall ; exit