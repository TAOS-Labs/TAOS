section .text
global _start

_start:
    mov rax, [0x0]    ; try to load from address 0x0 (NULL)
    nop               ; do nothing (if somehow survives)
hang:
    jmp hang          ; infinite loop (in case somehow not killed)
