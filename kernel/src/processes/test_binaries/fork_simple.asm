section .text
global _start

_start:
    mov rax, 0x5
    syscall
    mov r12, rax
    mov rax, 60
    syscall
