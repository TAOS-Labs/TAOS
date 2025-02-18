; test.asm
; A minimal 64-bit program that just sets a register and loops forever.

BITS 64
default rel   ; ensure relative addressing

global _start

section .text

_start:
    ; Put a recognizable value in a register
    mov  rax, 0xDEAD_BEEF

    ; Infinite loop
.loop:  
    jmp .loop
