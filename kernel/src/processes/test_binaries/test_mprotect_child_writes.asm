; test_fork_mprotect_shared.asm
; A process mmaps a shared, anonymous, read-only page.
; Forks. The child calls mprotect to change its mapping to read-write,
; writes some bytes, then exits.
; The parent waits for the child and then reads some bytes from the mapping.

%define SYS_MMAP       4
%define SYS_MPROTECT   10
%define SYS_FORK       5
%define SYS_WAIT       6
%define SYS_EXIT       60

%define MAP_SHARED     0x01
%define MAP_ANONYMOUS  0x20
%define PROT_READ      0x1
%define PROT_WRITE     0x2

section .text
  global _start

_start:
  ; mmap: void *mmap(void *addr, size_t length, int prot, int flags, int fd, off_t offset);
  xor rdi, rdi              ; addr = NULL
  mov rsi, 0x1000           ; length = 4096 bytes
  mov rdx, PROT_READ        ; prot = read-only
  mov r10, MAP_SHARED | MAP_ANONYMOUS ; flags = shared, anonymous
  mov r8, -1                ; fd = -1 (not used)
  xor r9, r9                ; offset = 0
  mov rax, SYS_MMAP
  syscall
  mov r15, rax              ; save the mapping address

  ; Fork the process.
  mov rax, SYS_FORK
  syscall
  mov r12, rax              ; store fork return value
  cmp rax, 0
  je _child

_parent:
  ; Parent: wait for the child to complete.
  mov rdi, r12
  mov rax, SYS_WAIT
  syscall

  ; Read the bytes that the child wrote.
  movzx r8, byte [r15]         ; load first byte into r8
  movzx r9, byte [r15 + 1]     ; load second byte into r9
  movzx r10, byte [r15 + 2]    ; load third byte into r10

  ; Exit parent.
  mov rax, SYS_EXIT
  xor rdi, rdi
  syscall

_child:
  ; Child: change memory protection to allow writes.
  mov rdi, r15             ; addr of the mapping
  mov rsi, 0x1000          ; length (4096 bytes)
  mov rdx, PROT_READ | PROT_WRITE ; new protection: read+write
  mov rax, SYS_MPROTECT
  syscall

  ; Write some bytes to the mapping.
  mov byte [r15], 'X'
  mov byte [r15 + 1], 'Y'
  mov byte [r15 + 2], 'Z'

  ; Exit child.
  mov rax, SYS_EXIT
  xor rdi, rdi
  syscall
