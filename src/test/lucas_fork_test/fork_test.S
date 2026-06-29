/*
 * sotOs · LUCAS L3a · fork test fixture.
 *
 * No libc, no PT_INTERP, no relocations.  Tiny x86_64 binary that
 * calls fork() then wait4() in the parent, exit_group() in both
 * parent and child.  Validates the L3a fork story end-to-end.
 *
 * Build:
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o fork_test.bin fork_test.S
 *   strip fork_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

.section .text
.global _start
_start:
    /* fork() · sys 57 · no args */
    mov $57, %rax
    syscall
    /* rax = child_pid in parent, 0 in child */
    test %rax, %rax
    jz   .Lchild

.Lparent:
    /* Save child_pid in r12 (callee-saved, but no other callees here) */
    mov %rax, %r12

    /* wait4(pid=r12, NULL, 0, NULL) · sys 61 */
    mov $61, %rax
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall
    /* rax now = pid of reaped child (positive on success) */

    /* write(1, parent_msg, parent_msg_len) · sys 1 */
    mov $1, %rax
    mov $1, %rdi
    lea parent_msg(%rip), %rsi
    mov $parent_msg_len, %rdx
    syscall

    /* exit_group(0) · sys 231 */
    mov $231, %rax
    xor %rdi, %rdi
    syscall
    ud2

.Lchild:
    /* write(1, child_msg, child_msg_len) */
    mov $1, %rax
    mov $1, %rdi
    lea child_msg(%rip), %rsi
    mov $child_msg_len, %rdx
    syscall

    /* exit_group(42) */
    mov $231, %rax
    mov $42, %rdi
    syscall
    ud2

.section .rodata
parent_msg:
    .ascii "PARENT here \xc2\xb7 child reaped\n"
parent_msg_len = . - parent_msg

child_msg:
    .ascii "CHILD HERE\n"
child_msg_len = . - child_msg
