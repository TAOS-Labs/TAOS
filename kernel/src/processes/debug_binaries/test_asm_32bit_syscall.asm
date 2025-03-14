section .text
    global _start

_start:
    mov rax, 1
    mov rbx, 0x5
    int 0x80 ; exit