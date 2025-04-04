%define PROT_READ  0x1
%define PROT_WRITE 0x2
%define MAP_ANON   0x10

section .data
    message db 'hello world!', 0

section .text
    global _start

_start:
    ; mmap syscall
    mov rax, 4             ; Syscall number for mmap (assuming 4)
    mov rdi, 0x1000         ; Address hint (0x1000)
    mov rsi, 0x2000         ; Length of the mapping (8192 bytes)
    mov rdx, PROT_READ
    or rdx, PROT_WRITE
    mov r10, MAP_ANON
    mov r8, -1              ; File descriptor (-1 for anonymous mapping)
    mov r9syscall_handler_64_naked, 0               ; Offset (0)
    syscall

    ; Save the returned address from mmap
    mov rbx, rax            ; Store the returned address from mmap in RBX
    mov r11, rbx            ; Save address for sys_print

    ; Write "hello world!" to the mmap'd memory
    lea rsi, [message]       ; Load the address of the message
    mov rcx, 12              ; Length of the message ("hello world!" is 12 bytes)
.write_loop:
    mov al, byte [rsi]       ; Read a byte from the message
    mov [rbx], al            ; Write the byte to the mmap'd memory
    inc rsi                  ; Move to the next byte in the message
    inc rbx                  ; Move to the next position in the mmap'd memory
    dec rcx                  ; Decrement rcx manually
    jnz .write_loop          ; Jump if rcx is not zero

    ; Call sys_print with the buffer pointer
    mov rax, 3               ; Syscall number for sys_print
    mov rdi, r11             ; Pointer to the start of the written message
    syscall

    ; Exit
    mov rax, 60              ; Syscall number for exit
    xor rdi, rdi             ; Status code 0
    syscall
