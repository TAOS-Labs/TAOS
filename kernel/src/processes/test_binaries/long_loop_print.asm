section .text
    global _start

_start:
    mov rax, 3
    mov rbx, 0xFFFFFFFF

_loop:
    sub rbx, 1
    cmp rbx, 0
    jg _loop

    int 0x80
    mov rax, 1
    int 0x80