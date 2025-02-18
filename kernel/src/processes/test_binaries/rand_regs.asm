section .text
    global _start

_start:
    mov rax, 0x14
    mov rbx, 0x20
    mov rcx, 0x34
    mov rdx, 0x71
    mov rsi, 0x100
    mov rdi, 0x200
    mov r8, 0xbeef
    mov r9, 0x69
    mov r10, 0x420
    mov r11, 0x300
    mov r15, 0xdeadbeef
    jmp _start
