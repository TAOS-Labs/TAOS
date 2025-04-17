; test_wait.asm

%define SYS_FORK   5
%define SYS_WAIT   6
%define SYS_EXIT   60

section .text
global _start

_start:
    mov rax, SYS_FORK    ; syscall number for fork
    syscall
    cmp rax, 0
    je _child     ; if rax == 0, then we're in the child

_parent:
    mov rdi, rax         ; child's PID in rdi (1st arg)
    mov rax, SYS_WAIT    ; syscall number for wait
    syscall              ; block until child terminates
    
    mov rdi, rax
    mov rax, SYS_EXIT
    syscall

_child:
    mov rdi, 500000000
    mov rax, 35
    syscall ; nanosleep

    mov rdi, 5
    mov rax, SYS_EXIT
    syscall

