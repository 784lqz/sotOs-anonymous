/*
 * sotOs · LUCAS L1 test fixture · static x86_64 Linux ELF.
 *
 * Uses only write(2) and exit_group(2). No libc, no TLS, no brk.
 * Designed to be the smallest possible binary that exercises the
 * happy path of our companion.
 *
 * Build (on a Linux host with binutils):
 *   gcc -nostdlib -static -no-pie -o hello-linux.bin hello.S
 *   strip hello-linux.bin
 *
 * Verify it works on Linux first:
 *   ./hello-linux.bin   # should print "hello world\n" and exit 0
 */

.intel_syntax noprefix

.section .text
.global _start
_start:
    # write(1, msg, 12)
    mov rax, 1            # SYS_write
    mov rdi, 1            # fd = stdout
    lea rsi, [rip + msg]
    mov rdx, 12           # length of "hello world\n"
    syscall

    # exit_group(0)
    mov rax, 231          # SYS_exit_group
    xor rdi, rdi          # code = 0
    syscall

    # not reached
    ud2

.section .rodata
msg:
    .ascii "hello world\n"
