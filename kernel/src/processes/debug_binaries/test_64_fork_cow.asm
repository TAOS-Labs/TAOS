section .data
    ; Initialize the test variable to a known value.
    test_var: dq 0x11111111

section .text
    global _start

_start:
    ; Fork the process
    mov rax, 5       ; syscall number for fork (example)
    int 0x80         ; perform fork
    cmp rax, 0
    je _child ; jump to child

    ; Parent Process
    ; Sleep to allow child to finish
    mov rax, 35          ; syscall number for sleep (example)
    mov rbx, 5000000000  ; sleep duration (in your OS’s time units)
    int 0x80

    ; Check that test_var is still the original value (should be for parent)
    mov rax, [test_var]
    mov rbx, 0x11111111
    cmp rax, rbx
    jne _parent_fail     ; if not equal, something went wrong with COW

    ; Exit parent with success code
    mov rax, 60       ; syscall number for exit
    mov rbx, 0        ; exit code 0 (success)
    int 0x80

_child:
    ; --- Child Process ---
    ; Modify test_var to a different value.
    mov rax, 0x22222222
    mov [test_var], rax

    ; Exit child with success code (0).
    mov rax, 60
    mov rbx, 0
    int 0x80

_parent_fail:
    ; --- Parent Failure Path ---
    ; Exit with a nonzero code to indicate test failure.
    mov rax, 60
    mov rbx, 1
    int 0x80

