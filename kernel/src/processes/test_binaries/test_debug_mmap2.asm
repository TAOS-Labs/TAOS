section .data
    buffer db "Hello from custom syscall!", 0

section .text
global _start

_start:
    mov byte [buffer], 'X'
    mov rdi, buffer
    mov rax, 0x3
    syscall
    mov rax, 60
    mov rdi, r12
    syscall
