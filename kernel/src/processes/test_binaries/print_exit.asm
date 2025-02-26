section .data
    buffer db "Hello from custom syscall!", 0

section .text
global _start

_start:
    ; Set up registers for the custom syscall
    mov rax, 3         ; Custom syscall number 3
    mov rbx, buffer ; First argument: pointer to our string

    ; Trigger the syscall using the 32-bit interrupt
    int 0x80

    ; Exit the program using the Linux exit syscall (number 1)
    mov rax, 1         ; syscall: exit
    xor rbx, rbx       ; exit code 0
    int 0x80

