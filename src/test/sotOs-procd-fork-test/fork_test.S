/*
 * sotOs · procd PR 6 · fork test fixture (asm).
 *
 * Distinct from src/test/lucas_fork_test/fork_test.S in that it emits
 * "[fork-test] ..." markers so smoke-procd.sh can grep for the procd
 * shadow-announce side effects without false positives from the L3a
 * fork demo.
 *
 * Calls fork() (sys 57), child writes "[fork-test] child alive\n" and
 * exit_group(42); parent wait4(-1, NULL, 0, NULL) (sys 61), then writes
 * "[fork-test] parent reaped\n" and exit_group with WEXITSTATUS bit.
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o procd_fork_test.bin fork_test.S
 *   strip procd_fork_test.bin
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
    /* Save child_pid in r12 (callee-saved, no other callees here) */
    mov %rax, %r12

    /* wait4(-1, NULL, 0, NULL) · sys 61 · wait for any child */
    mov $61, %rax
    mov $-1, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall

    /* write(1, parent_msg, parent_msg_len) · sys 1 */
    mov $1, %rax
    mov $1, %rdi
    lea parent_msg(%rip), %rsi
    mov $parent_msg_len, %rdx
    syscall

    /* exit_group(0) · sys 231 · success
     * Note: fixture always exits parent with 0 · status check is via
     * the [fork-test] parent reaped log line, not the parent's exit
     * code. The child's status (42) is captured in wait4's status arg
     * (passed as NULL above · we don't propagate it to parent rdi). */
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

    /* exit_group(42) · the PR 6 acceptance value */
    mov $231, %rax
    mov $42, %rdi
    syscall
    ud2

.section .rodata
parent_msg:
    .ascii "[fork-test] parent reaped child\n"
parent_msg_len = . - parent_msg

child_msg:
    .ascii "[fork-test] child alive\n"
child_msg_len = . - child_msg
