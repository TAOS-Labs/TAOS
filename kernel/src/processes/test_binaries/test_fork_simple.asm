; test_fork.asm

%define SYS_FORK 5

section .data

section .text
    global _start

_start:
    mov rax, SYS_FORK
    syscall ; Fork
    cmp rax, 0 ; rax = 0 in child, >0 in parent
    je _child

_parent:
    ; Parent: rax is child's PID.
    mov rdi, rax        ; Pass child's PID as first argument.
    mov rax, SYS_WAIT
    syscall             ; wait syscall; assume child's exit status is returned in rax.
    cmp rax, 42         ; Check if child's exit code is 42.
    jne error
    ; Success: exit with 0.
    mov rdi, 0
    mov rax, SYS_EXIT
    syscall

_child:
    ; Child: exit with code 42.
    mov rdi, 42
    mov rax, SYS_EXIT
    syscall

error:
    ; On error, exit with code 1.
    mov rdi, 1
    mov rax, SYS_EXIT
    syscall


