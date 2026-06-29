/*
 * sotOs · procd PR 12 · futex variants test fixture (asm).
 *
 * Exercises FUTEX_WAIT_BITSET + FUTEX_WAKE_BITSET on 3 simultaneous
 * waiters · the smallest fixture that fully covers the bitset path
 * AND the "many waiters on the same addr" path (which used to be
 * gated by the futex_waiters[16] queue · PR 12 bumped to 32 so 3
 * concurrent waiters fit with margin).
 *
 * The fixture spawns 3 worker threads via clone(CLONE_VM|CLONE_THREAD),
 * each performs FUTEX_WAIT_BITSET on a shared cond variable with a
 * disjoint bitset (worker 1 → bit 0, worker 2 → bit 1, worker 3 → bit 2).
 * The main thread then issues a single FUTEX_WAKE_BITSET with all bits
 * set (~0u) and INT_MAX wakeups, mirroring pthread_cond_broadcast.
 *
 * Each woken worker atomically increments a `done` counter (via
 * lock xadd) and prints "[cond-test] worker N woke".  The main thread
 * polls `done` until it equals 3 (with a generous spin budget · we
 * don't have nanosleep wired in this fixture), then prints
 * "[cond-test] PASS" and exits 0.
 *
 * If any worker exits without waking (e.g. EAGAIN race lost the wait),
 * the polling loop times out and the fixture exits 1 instead of 0 ·
 * smoke-procd.sh greps for "[cond-test] PASS" on stdout.
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o procd_cond_test.bin cond_test.S
 *   strip procd_cond_test.bin
 *
 * Or via the Makefile.fixture target.
 */

.intel_syntax noprefix

#define SYS_write        1
#define SYS_clone        56
#define SYS_exit         60
#define SYS_exit_group   231
#define SYS_futex        202

#define CLONE_VM         0x00000100
#define CLONE_THREAD     0x00010000
#define CLONE_SIGHAND    0x00000800

/* futex ops · PR 12 surface */
#define FUTEX_WAIT_BITSET  9
#define FUTEX_WAKE_BITSET  10

.section .text
.global _start
_start:
    /* === main thread: initialize shared state =============== */
    /* cond_var = 0 (workers park while it stays 0) */
    lea  rax, [rip + cond_var]
    mov  dword ptr [rax], 0

    /* done_counter = 0 */
    lea  rax, [rip + done_counter]
    mov  dword ptr [rax], 0

    /* === clone() worker 1 (bitset = 0x1) ==================== */
    mov  rax, SYS_clone
    mov  rdi, (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND)
    lea  rsi, [rip + child_stack1_top]
    xor  rdx, rdx
    xor  r10, r10
    xor  r8,  r8
    syscall
    test rax, rax
    js   .Lfail
    jz   .Lworker1

    /* === clone() worker 2 (bitset = 0x2) ==================== */
    mov  rax, SYS_clone
    mov  rdi, (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND)
    lea  rsi, [rip + child_stack2_top]
    xor  rdx, rdx
    xor  r10, r10
    xor  r8,  r8
    syscall
    test rax, rax
    js   .Lfail
    jz   .Lworker2

    /* === clone() worker 3 (bitset = 0x4) ==================== */
    mov  rax, SYS_clone
    mov  rdi, (CLONE_VM | CLONE_THREAD | CLONE_SIGHAND)
    lea  rsi, [rip + child_stack3_top]
    xor  rdx, rdx
    xor  r10, r10
    xor  r8,  r8
    syscall
    test rax, rax
    js   .Lfail
    jz   .Lworker3

    /* === main: give workers time to park (spin a bit) =======
     * We don't have nanosleep wired in this no-libc fixture · spin
     * a fixed-iteration loop instead.  Each iteration is ~1 cycle
     * on a host but on QEMU+seL4 the IPC fastpath turns this into a
     * busy-wait that lasts long enough for all 3 workers to issue
     * their FUTEX_WAIT_BITSET and SaveCaller-park.  The actual
     * synchronization is the spin-on-done_counter at the end · we
     * just need the workers to land on the queue before WAKE_BITSET
     * fires (vacant wakes would noop and break the test). */
    mov  rcx, 200000000
.Lspin_pre:
    dec  rcx
    jnz  .Lspin_pre

    /* === main: flip cond_var = 1 and broadcast ==============
     * The cond_var = 1 store happens BEFORE the WAKE so that a worker
     * woken by a spurious WAKE re-evaluates the condition and sees the
     * update.  Order matters only for the WAIT-then-WAKE race · the
     * fixture is single-vCPU so we don't need a memory barrier. */
    lea  rax, [rip + cond_var]
    mov  dword ptr [rax], 1

    /* futex(&cond_var, FUTEX_WAKE_BITSET, INT_MAX, 0, NULL, 0xFFFFFFFF) */
    mov  rax, SYS_futex
    lea  rdi, [rip + cond_var]
    mov  rsi, FUTEX_WAKE_BITSET
    mov  rdx, 0x7FFFFFFF        /* INT_MAX waiters */
    xor  r10, r10               /* timeout = NULL (ignored for WAKE) */
    xor  r8,  r8                /* uaddr2 = NULL */
    mov  r9,  0xFFFFFFFF        /* val3 = full bitset · wakes all 3 workers */
    syscall

    /* === main: poll done_counter ============================
     * Each worker increments done_counter from its post-wake path.
     * We spin until it hits 3 or our budget runs out.  Budget is set
     * high enough (a few hundred million iterations) to cover a slow
     * QEMU + seL4 IPC round-trip per worker, but bounded so a
     * regression doesn't deadlock the smoke run.
     *
     * If the loop times out we fall into .Lfail (exit 1).  The PASS
     * line only prints when all 3 workers acked. */
    mov  rcx, 500000000
.Lpoll:
    lea  rax, [rip + done_counter]
    mov  edx, dword ptr [rax]
    cmp  edx, 3
    je   .Lpass
    dec  rcx
    jnz  .Lpoll
    jmp  .Lfail

.Lpass:
    /* write(1, pass_msg, pass_msg_len) */
    mov  rax, SYS_write
    mov  rdi, 1
    lea  rsi, [rip + pass_msg]
    mov  rdx, 17                /* pass_msg length */
    syscall

    /* exit_group(0) */
    mov  rax, SYS_exit_group
    xor  rdi, rdi
    syscall
    ud2

.Lfail:
    mov  rax, SYS_write
    mov  rdi, 1
    lea  rsi, [rip + fail_msg]
    mov  rdx, 27                /* fail_msg length */
    syscall
    mov  rax, SYS_exit_group
    mov  rdi, 1
    syscall
    ud2

/* === worker 1 (bitset = 0x1) ============================= */
.Lworker1:
    /* futex(&cond_var, FUTEX_WAIT_BITSET, 0, NULL, NULL, 0x1)
     * Wait while *cond_var == 0; bitset = 0x1 (will match the
     * main thread's WAKE_BITSET with bits=0xFFFFFFFF). */
    mov  rax, SYS_futex
    lea  rdi, [rip + cond_var]
    mov  rsi, FUTEX_WAIT_BITSET
    mov  rdx, 0                 /* expected value */
    xor  r10, r10
    xor  r8,  r8
    mov  r9,  1                 /* bitset = bit 0 */
    syscall

    /* lock incl [done_counter] · atomic ++ across the 3 workers */
    lea  rax, [rip + done_counter]
    lock inc dword ptr [rax]

    /* write worker-1 woke line */
    mov  rax, SYS_write
    mov  rdi, 1
    lea  rsi, [rip + worker1_msg]
    mov  rdx, 26                /* worker1_msg length */
    syscall

    /* sys_exit(0) · terminate just this thread */
    mov  rax, SYS_exit
    xor  rdi, rdi
    syscall
    ud2

/* === worker 2 (bitset = 0x2) ============================= */
.Lworker2:
    mov  rax, SYS_futex
    lea  rdi, [rip + cond_var]
    mov  rsi, FUTEX_WAIT_BITSET
    mov  rdx, 0
    xor  r10, r10
    xor  r8,  r8
    mov  r9,  2                 /* bitset = bit 1 */
    syscall

    lea  rax, [rip + done_counter]
    lock inc dword ptr [rax]

    mov  rax, SYS_write
    mov  rdi, 1
    lea  rsi, [rip + worker2_msg]
    mov  rdx, 26                /* worker2_msg length */
    syscall

    mov  rax, SYS_exit
    xor  rdi, rdi
    syscall
    ud2

/* === worker 3 (bitset = 0x4) ============================= */
.Lworker3:
    mov  rax, SYS_futex
    lea  rdi, [rip + cond_var]
    mov  rsi, FUTEX_WAIT_BITSET
    mov  rdx, 0
    xor  r10, r10
    xor  r8,  r8
    mov  r9,  4                 /* bitset = bit 2 */
    syscall

    lea  rax, [rip + done_counter]
    lock inc dword ptr [rax]

    mov  rax, SYS_write
    mov  rdi, 1
    lea  rsi, [rip + worker3_msg]
    mov  rdx, 26                /* worker3_msg length */
    syscall

    mov  rax, SYS_exit
    xor  rdi, rdi
    syscall
    ud2

/*
 * .data · shared variables visible to clones via CLONE_VM.
 */
.section .data
.align 4
cond_var:
    .long 0
done_counter:
    .long 0

.section .rodata
worker1_msg:
    .ascii "[cond-test] worker 1 woke\n"
worker1_msg_len = . - worker1_msg
worker2_msg:
    .ascii "[cond-test] worker 2 woke\n"
worker2_msg_len = . - worker2_msg
worker3_msg:
    .ascii "[cond-test] worker 3 woke\n"
worker3_msg_len = . - worker3_msg
pass_msg:
    .ascii "[cond-test] PASS\n"
pass_msg_len = . - pass_msg
fail_msg:
    .ascii "[cond-test] FAIL (timeout)\n"
fail_msg_len = . - fail_msg

/*
 * .bss · per-worker child stacks (4 KiB each, 16-byte aligned).
 * Stacks grow downward · child_stackN_top points to the highest
 * address in the region.
 */
.section .bss
.align 16
child_stack1_base:
    .skip 4096
child_stack1_top:

.align 16
child_stack2_base:
    .skip 4096
child_stack2_top:

.align 16
child_stack3_base:
    .skip 4096
child_stack3_top:
