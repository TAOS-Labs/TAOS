; test_wait.asm
; Assemble with: nasm -f elf64 test_wait.asm -o test_wait.o
; Link according to your kernel test environment.

; Using Linux syscall numbers:
%define SYS_FORK   5
%define SYS_WAIT   6
%define SYS_EXIT   60

section .text
global _start

_start:
    ; Call fork()
    mov rax, SYS_FORK    ; syscall number for fork
    syscall
    cmp rax, 0
    je child_process     ; if rax == 0, then we're in the child

parent_process:
    ; In parent: rax holds the child's PID.
    ; Call wait(child_pid)
    mov rdi, rax         ; child's PID in rdi (1st arg)
    mov rax, SYS_WAIT    ; syscall number for wait
    syscall              ; block until child terminates (via your async wait and block_on)
    
    ; Optionally, the return value in rax is the exit code, but we ignore it.
    ; Exit with status 0.
    mov rdi, rax
    mov rax, SYS_EXIT
    syscall

child_process:
    mov rdi, 500000000
    mov rax, 35
    syscall ; nanosleep

    mov rdi, 5
    mov rax, SYS_EXIT
    syscall

