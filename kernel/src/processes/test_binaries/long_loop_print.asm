section .data
    buffer db "Long loop ending with print", 0

section .text
    global _start

_start:
    mov rax, 3
    mov rbx, 0xFFFFFFFF
    mov rdi, buffer

_loop:
    sub rbx, 1
    cmp rbx, 0
    jg _loop

    syscall ; print
    mov rax, 60
    syscall ; exit
