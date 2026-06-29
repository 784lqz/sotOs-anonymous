/*
 * sotOs · L10 · PTY test fixture.
 *
 * Tiny x86_64 Linux ELF that exercises the LUCAS PTY VFS backend:
 *   1. open("/dev/ptmx", O_RDWR=2)      → fd_master
 *   2. write(fd_master, "HELLO-PTY\n", 10)
 *   3. open("/dev/pts/0", O_RDWR=2)     → fd_slave
 *   4. read(fd_slave, buf, 16)           → should return 10
 *   5. write(2, buf, n)                  → prints "HELLO-PTY\n" to serial
 *   6. exit_group(0)
 *
 * No libc, no PT_INTERP, no relocations.  Build:
 *   gcc -nostdlib -static -no-pie -Wl,--build-id=none \
 *       -o pty_test.bin pty_test.S && strip pty_test.bin
 *
 * Smoke: operator console must contain:
 *   [pty] ptmx allocated · pair 0
 *   [pty] master write 10 bytes
 *   [pty] slave read 10 bytes
 *   HELLO-PTY
 */

.intel_syntax noprefix

.section .text
.global _start
_start:
    /* open("/dev/ptmx", O_RDWR=2, 0) · sys 2 */
    mov rax, 2
    lea rdi, [rip + path_ptmx]
    mov rsi, 2          /* O_RDWR */
    xor rdx, rdx
    syscall
    /* rax = fd_master (expect >= 3) */
    test rax, rax
    js   .Lfail
    mov r12, rax        /* save fd_master */

    /* write(fd_master, msg, 10) · sys 1 */
    mov rax, 1
    mov rdi, r12
    lea rsi, [rip + msg]
    mov rdx, 10
    syscall
    /* rax = bytes written (expect 10) */

    /* open("/dev/pts/0", O_RDWR=2, 0) · sys 2 */
    mov rax, 2
    lea rdi, [rip + path_pts0]
    mov rsi, 2
    xor rdx, rdx
    syscall
    test rax, rax
    js   .Lfail
    mov r13, rax        /* save fd_slave */

    /* read(fd_slave, buf, 16) · sys 0 */
    mov rax, 0
    mov rdi, r13
    lea rsi, [rip + buf]
    mov rdx, 16
    syscall
    /* rax = bytes read (expect 10) */
    test rax, rax
    jle  .Lfail
    mov r14, rax        /* save bytes read */

    /* write(2, buf, r14) · sys 1 — serial output */
    mov rax, 1
    mov rdi, 2
    lea rsi, [rip + buf]
    mov rdx, r14
    syscall

.Lfail:
    /* exit_group(0) · sys 231 */
    mov rax, 231
    xor rdi, rdi
    syscall
    ud2

.section .rodata
path_ptmx:
    .asciz "/dev/ptmx"

path_pts0:
    .asciz "/dev/pts/0"

msg:
    .ascii "HELLO-PTY\n"

.section .bss
buf:
    .space 16
