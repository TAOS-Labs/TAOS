section .text
    global _start

_start:
    mov rcx, 0x34
    mov rdx, 0x71
    mov rsi, 0x100
    mov rdi, 0x200
    mov r8, 0xbeef
    mov r9, 0x69
    mov r10, 0x420
    mov r15, 0xdeadbeef
    mov rax, 1 ; EXIT
    int 0x80 ; do syscall
