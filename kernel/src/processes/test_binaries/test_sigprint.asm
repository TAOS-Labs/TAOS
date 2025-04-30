; test_signal_handler_stack.asm

%define SYS_PRINT     1003
%define SYS_FORK      5
%define SYS_KILL      37
%define SYS_SIGACTION 13
%define SYS_WAIT      6
%define SYS_EXIT      60

section .data
    handler_msg db "SIGNAL HANDLER EXECUTED", 0
    parent_msg db "Parent process waiting", 0
    child_msg db "Child process sending signal", 0

section .text
global _start

; The signal handler function
handler:
    mov rdi, handler_msg
    mov rax, SYS_PRINT
    syscall
    ret

_start:
    ; Allocate space on stack for SigAction struct
    sub rsp, 16                     ; Reserve 16 bytes (sa_handler + sa_flags + sa_mask)

    ; Setup SigAction struct on stack
    lea rax, [rel handler]           ; Address of handler function
    mov [rsp], rax                   ; sa_handler = handler address
    mov dword [rsp + 8], 0            ; sa_flags = 0
    mov dword [rsp + 12], 0           ; sa_mask = 0

    ; Register the signal handler for signal 31
    mov rdi, 31                      ; signum = 31
    mov rsi, rsp                     ; pointer to our SigAction struct on stack
    mov rdx, 0                       ; oldact = NULL
    mov r10, 8                       ; sigset size = 8 bytes
    mov rax, SYS_SIGACTION
    syscall

    ; Free the stack space
    add rsp, 16

    ; Fork
    mov rax, SYS_FORK
    syscall

    ; Save fork return value
    mov r12, rax

    cmp rax, 0
    je _child

_parent:
    ; Print parent message
    mov rdi, parent_msg
    mov rax, SYS_PRINT
    syscall

    ; Wait for child to exit
    mov rdi, r12        ; child's PID
    mov rax, SYS_WAIT
    syscall

    ; After waiting, parent loops 10 times then exits
    mov rbx, 100000000         ; loop counter
_loop_parent:
    dec rbx
    cmp rbx, 0
    jne _loop_parent

    ; Exit parent
    mov rax, SYS_EXIT
    mov rdi, 0
    syscall

_child:
    ; Print child message
    mov rdi, child_msg
    mov rax, SYS_PRINT
    syscall

    ; Send signal 31 to parent
    mov rdi, 1          ; assuming parent PID is 1
    mov rsi, 31
    mov rax, SYS_KILL
    syscall

    ; Child loops 10 times then exits
    mov rbx, 10         ; loop counter
_loop_child:
    dec rbx
    cmp rbx, 0
    jne _loop_child

    ; Exit child
    mov rax, SYS_EXIT
    mov rdi, 0
    syscall
