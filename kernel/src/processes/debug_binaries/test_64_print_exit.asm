section .data
  buffer db "Hello from test syscall!", 0

section .text
  global _start

_start:
  ; Set up registers for the custom syscall
  mov rax, 3         ; Custom syscall number 3
  mov rdi, buffer    ; First argument: pointer to our string

  ; Trigger the syscall using the 64-bit interrupt
  syscall

  ; Exit the program using the Linux exit syscall (number 1)
  mov rax, 60        ; syscall: exit
  xor rdi, rdi       ; exit code 0
  syscall
