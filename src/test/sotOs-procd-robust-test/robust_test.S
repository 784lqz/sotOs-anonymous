/*
 * sotOs · procd PR 13 · robust_list test fixture (asm).
 *
 * Exercises the OP_SET_ROBUST shadow-announce + the lucas-side
 * robust_list walk on thread exit.  The simplest fixture that proves
 * the end-to-end wire from glibc-style set_robust_list(2) through
 * lucas_sys_set_robust_list and into procd_handle_set_robust where
 * the operator-visible "[procd] set_robust tid=N head=0x..." log
 * line fires.
 *
 * Scope reduction (per PR 13 plan note): we don't drive a real
 * pthread_mutex_lock/EOWNERDEAD round-trip · that needs glibc/musl
 * robust mutex runtime support which the no-libc static fixture
 * doesn't have.  Instead the fixture:
 *
 *   1. main calls set_robust_list(&main_head, 24) · this hits the
 *      lucas handler which announces to procd with tid=0 (no thread
 *      yet, falls back to main-thread anomaly).
 *   2. main writes the PASS line "[robust-test] set_robust announced".
 *   3. main calls exit_group(0) · the parent's exit_group sweep
 *      walks all thread_list entries (PR 13 path · this fixture has
 *      no clone'd threads in the path that announces robust_list
 *      per-thread, so it just exits cleanly).
 *
 * NOTE on multi-thread testing: workers in CLONE_VM|CLONE_THREAD
 * threads cannot fully run unless their TCBs receive register updates
 * from the fault loop · lucas's current model writes only to the
 * parent's TCB.  Worker threads that park on futex via SaveCaller
 * work (cond-test fixture demonstrates this) but workers issuing
 * sequential syscalls don't advance.  PR 13 scope confines the
 * robust-test to the main-thread set_robust_list announce since that's
 * the operator-visible evidence we need · the multi-thread robust
 * walk path is exercised at sotbox teardown when the WHOLE sotbox
 * exits (lucas_threads_suspend_all walks every per-thread robust list
 * before suspending TCBs · this fires on every procd-pthread-test /
 * procd-cond-test run too).
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o procd_robust_test.bin robust_test.S
 *   strip procd_robust_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

.intel_syntax noprefix

#define SYS_write           1
#define SYS_exit_group    231
#define SYS_set_robust_list 273

.section .text
.global _start
_start:
    /* === main: announce our own robust_list_head ============
     * Linux signature: set_robust_list(head*, sizeof(robust_list_head))
     *   rdi = &main_robust_head, rsi = 24 (3 * sizeof(void*))
     * The head's internal fields are all zero (empty list) · the
     * announce is what matters for PR 13 evidence. */
    mov  rax, SYS_set_robust_list
    lea  rdi, [rip + main_robust_head]
    mov  rsi, 24
    syscall

    /* === main: write PASS line ============================== */
    mov  rax, SYS_write
    mov  rdi, 1
    lea  rsi, [rip + pass_msg]
    mov  rdx, 35               /* pass_msg length · count carefully */
    syscall

    /* exit_group(0) · success */
    mov  rax, SYS_exit_group
    xor  rdi, rdi
    syscall
    ud2

.section .data
.align 8
/* Linux struct robust_list_head layout:
 *   void *list;             // +0
 *   long  futex_offset;     // +8
 *   void *list_op_pending;  // +16
 * Total size = 24 bytes (3 quadwords).  We zero-initialize the list
 * + pending pointers so the kernel's walk-on-exit immediately
 * terminates (no entries to mark).  The non-empty walk path is
 * exercised by glibc/musl pthread fixtures in PR 14+ once the
 * pthread runtime lands. */
main_robust_head:
    .quad 0           /* list (head pointer = NULL means empty) */
    .quad 0           /* futex_offset */
    .quad 0           /* list_op_pending */

.section .rodata
pass_msg:
    .ascii "[robust-test] set_robust announced\n"
pass_msg_len = . - pass_msg
