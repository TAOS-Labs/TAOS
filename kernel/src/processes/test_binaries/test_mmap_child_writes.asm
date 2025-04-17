; shared_memory_fork.asm
; Program that demonstrates shared memory between parent and child processes
; Parent mmaps a shared, anonymous page, forks a child process
; Child writes to first three bytes and exits
; Parent waits for child, reads those bytes into registers r8, r9, r10, then exits

%define SYS_MMAP   4        ; mmap syscall number (from test case)
%define SYS_FORK   5        ; fork syscall number (from test case)
%define SYS_WAIT   6        ; wait syscall number (from test case)
%define SYS_EXIT   60       ; exit syscall number (from test case)

%define MAP_SHARED     0x01
%define MAP_ANONYMOUS  0x20
%define PROT_READ      0x1
%define PROT_WRITE     0x2

section .text
  global _start

_start:
  ; mmap a shared anonymous page
  ; void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset)
  xor rdi, rdi              ; addr = NULL (let kernel choose address)
  mov rsi, 0x1000           ; length = 4096 (one page)
  mov rdx, PROT_READ | PROT_WRITE ; protection = read | write
  mov r10, MAP_SHARED | MAP_ANONYMOUS ; flags = shared and anonymous
  mov r8, -1                ; fd = -1 (for anonymous mapping)
  xor r9, r9                ; offset = 0
  mov rax, SYS_MMAP
  syscall
  
  ; Save mapped address in r15
  mov r15, rax

  ; Fork a child process
  mov rax, SYS_FORK
  syscall
  
  ; Check if we're parent or child
  cmp rax, 0
  je child_process          ; Jump if fork returned 0 (we're in child)
  
  ; Parent process continues here
  ; Save child PID for wait
  mov r12, rax
  
  ; Wait for child to exit
  mov rdi, r12
  mov rax, SYS_WAIT
  syscall
  
  ; Read values from shared memory into registers
  movzx r8, byte [r15]      ; First byte into r8
  movzx r9, byte [r15 + 1]  ; Second byte into r9
  movzx r10, byte [r15 + 2] ; Third byte into r10
  
  ; Exit parent process
  mov rax, SYS_EXIT
  xor rdi, rdi              ; exit code 0
  syscall

child_process:
  ; Child writes 'X', 'Y', 'Z' to first three bytes
  mov byte [r15], 'X'
  mov byte [r15 + 1], 'Y'
  mov byte [r15 + 2], 'Z'
  
  ; Exit child process
  mov rax, SYS_EXIT
  xor rdi, rdi              ; exit code 0
  syscall