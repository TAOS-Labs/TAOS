section .data
    buffer db "Hello from custom syscall!", 0

section .text
global _start

_start:
    mov rax, 0x5
    int 0x80
    mov rcx, rax
    cmp rax, 0x0
    je _child  
    mov byte [buffer], 'X'
    mov rbx, buffer
    mov rax, 0x3
    int 0x80
    mov rax, 60
    mov rbx, rcx
    int 0x80

_child:
    mov byte [buffer], 'B'
    mov rbx, buffer
    mov rax, 0x3
    int 0x80
    mov rax, 60
    mov rbx, rcx
    int 0x80
