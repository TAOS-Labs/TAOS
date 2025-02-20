section .text
    global _start

_start:
    mov rbx, 0xFFFFFFFF

_loop:
    sub rbx, 1
    cmp rbx, 0
    jg _loop

    mov rax, 1
    int 0x80