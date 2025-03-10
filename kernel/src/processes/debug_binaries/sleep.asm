section .data
  buffer db "Hello, syscall sleep!", 0

section .text
    global _start

_start:
    mov rdi, buffer
    mov rax, 3
    mov rdx, 35
    mov r8, 60
    syscall ; print

    mov rdi, 5000000000
    mov rax, rdx
    syscall ; nanosleep

    mov rax, r8
    syscall ; exit
