section .text
    global _start

_start:
    mov rbx, 0x0
    mov rcx, 0x1000
    mov rdx, 0x6
    mov rsi, 0x10
    mov rdi, -1
    mov rbp, 0x0
    mov rax, 0x4

    int 0x80

    mov byte [rax], 0x42

    mov bl, byte [rax] 
    cmp bl, 0x42
    je _finish

    mov rbx, -1
    mov rax, 0x1
    int 0x80

_finish: 
    mov rbx, 0x1
    mov rax, 0x1
    int 0x80