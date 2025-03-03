section .data
    buffer db "Hello, syscall print!", 0

section .text
    global _start

_start:
    ; Set up registers for the print syscall:
    mov rax, 3        ; syscall number for print
    mov rdi, buffer   ; pointer to the message buffer (arg1)
    syscall           ; invoke the syscall

    ; Now exit cleanly:
    mov rax, 1       ; syscall number for exit
    xor rdi, rdi      ; exit code 0
    syscall

