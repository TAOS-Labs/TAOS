; test_fork_cow_mmap.asm
; A process mmaps a shared, anonymous, read-write page.
; Writes 'A' to first byte.
; Forks. Child writes 'B' to second byte, exits.
; Parent waits, writes 'C' to third byte.
; Parent then loads first 3 bytes into r8, r9, r10 and exits.

%define SYS_MMAP   4
%define SYS_PRINT  3
%define SYS_FORK   5
%define SYS_WAIT   6
%define SYS_EXIT   60

%define MAP_SHARED     0x01
%define MAP_ANONYMOUS  0x20
%define PROT_READ      0x1
%define PROT_WRITE     0x2

section .text
  global _start

_start:
  ; mmap: void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
  xor rdi, rdi              ; addr = NULL
  mov rsi, 0x1000           ; length = 4096
  mov rdx, PROT_READ | PROT_WRITE ; prot = read | write
  mov r10, MAP_SHARED | MAP_ANONYMOUS ; flags = shared, anonymous
  mov r8, -1                ; fd = -1
  xor r9, r9                ; offset = 0
  mov rax, SYS_MMAP
  syscall
  mov r15, rax              ; save buffer ptr

  ; Write 'A' to first byte
  mov byte [r15], 'A'

  ; Fork
  mov rax, SYS_FORK
  syscall
  mov r12, rax              ; store fork return value
  cmp rax, 0
  je _child

_parent:
  ; Wait for child
  mov rdi, r12
  mov rax, SYS_WAIT
  syscall

  ; Write 'C' to third byte
  mov byte [r15 + 2], 'C'

  ; Load bytes into r8, r9, r10
  movzx r8, byte [r15]
  movzx r9, byte [r15 + 1]
  movzx r10, byte [r15 + 2]

  ; Exit
  mov rax, SYS_EXIT
  xor rdi, rdi
  syscall

_child:
  ; Write 'B' to second byte
  mov byte [r15 + 1], 'B'

  ; Exit
  mov rax, SYS_EXIT
  xor rdi, rdi
  syscall
