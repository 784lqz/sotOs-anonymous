/*
 * sotOs · LUCAS · PR 10 · shell-hook test fixture (asm).
 *
 * Exercises the execve argv-rewrite path:
 *   1. parent writes "[shellhook-test] before execve\n"
 *   2. parent fork()s
 *   3. child execve("/bin/sh", {"sh", NULL}, NULL)
 *      -> lucas_shellhook_apply rewrites argv to
 *         {"/bin/sh", "-c", "source /etc/bashrc 2>/dev/null; ...; exec sh", NULL}
 *      -> busybox-static runs the wrapper -> [BASHRC-MARKER] lines on serial
 *   4. parent wait4(child) then exit_group(0)
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none \
 *       -o shellhook_test.bin shellhook_test.S
 *   strip shellhook_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

.section .text
.global _start
_start:
    /* write(1, before_msg, before_msg_len) · sys 1 */
    mov $1, %rax
    mov $1, %rdi
    lea before_msg(%rip), %rsi
    mov $before_msg_len, %rdx
    syscall

    /* fork() · sys 57 · no args */
    mov $57, %rax
    syscall
    test %rax, %rax
    jz   .Lchild

.Lparent:
    /* Save child_pid */
    mov %rax, %r12

    /* wait4(pid=r12, NULL, 0, NULL) · sys 61 */
    mov $61, %rax
    mov %r12, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall

    /* write(1, parent_msg, parent_msg_len) */
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
    /* execve("/bin/sh", argv, NULL) · sys 59
     *   rdi = pathname pointer
     *   rsi = argv pointer (array of char* terminated by NULL)
     *   rdx = envp pointer (NULL · L3b ignores envp)
     */
    mov $59, %rax
    lea sh_path(%rip), %rdi
    lea argv_arr(%rip), %rsi
    xor %rdx, %rdx
    syscall

    /* If execve returned, it failed.  Print diagnostic + exit 1. */
    mov $1, %rax
    mov $2, %rdi
    lea fail_msg(%rip), %rsi
    mov $fail_msg_len, %rdx
    syscall

    mov $231, %rax
    mov $1, %rdi
    syscall
    ud2

.section .rodata
before_msg:
    .ascii "[shellhook-test] before execve\n"
before_msg_len = . - before_msg

parent_msg:
    .ascii "[shellhook-test] parent reaped\n"
parent_msg_len = . - parent_msg

fail_msg:
    .ascii "[shellhook-test] execve returned (FAIL)\n"
fail_msg_len = . - fail_msg

sh_path:
    .ascii "/bin/sh"
    .byte 0

sh_arg0:
    .ascii "sh"
    .byte 0

.section .data
.align 8
argv_arr:
    .quad sh_arg0
    .quad 0
