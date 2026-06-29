/*
 * sotOs · MS-M2 · pthread (clone+futex) test fixture.
 *
 * Tiny x86_64 Linux ELF that exercises the threading primitives:
 *   - clone(CLONE_VM|CLONE_THREAD|CLONE_SETTLS, child_stack, ...)  ; syscall 56
 *   - futex(addr, FUTEX_WAIT, val, NULL, NULL, 0)                  ; syscall 202
 *   - futex(addr, FUTEX_WAKE, 1, NULL, NULL, 0)                    ; syscall 202
 *   - exit_group(status)                                            ; syscall 231
 *
 * Both parent and child write distinct values to a shared global.
 * Parent waits on the futex, child wakes it after writing 42.
 * Exit code = shared_var observed by parent (expected 42).
 *
 * No libc, no PT_INTERP, no relocations.  Tiny static ELF (~1 KiB
 * stripped) so it fits the orch allocman pool at spawn time.
 *
 * Build:
 *   gcc -nostdlib -static -no-pie -Wl,--build-id=none -o pthread_test.bin pthread_test.S
 *   strip pthread_test.bin
 *
 * Verify on Linux host:
 *   ./pthread_test.bin; echo "exit=$?"
 *   # expect exit=42
 */

.intel_syntax noprefix

#define SYS_clone        56
#define SYS_futex        202
#define SYS_exit_group   231
#define SYS_exit         60

#define CLONE_VM         0x00000100
#define CLONE_THREAD     0x00010000
#define CLONE_SETTLS     0x00080000

/* futex ops */
#define FUTEX_WAIT       0
#define FUTEX_WAKE       1

.section .text
.global _start
_start:
    /* Initialize shared_var = 1 (parent's first write) */
    lea  rax, [rip + shared_var]
    mov  dword ptr [rax], 1

    /*
     * clone(flags=CLONE_VM|CLONE_THREAD|CLONE_SETTLS,
     *       child_stack=stack_top, parent_tid=NULL, child_tid=NULL, tls=0)
     *
     * x86_64 syscall ABI for clone:
     *   rax = 56 (SYS_clone)
     *   rdi = flags
     *   rsi = child_stack
     *   rdx = parent_tid
     *   r10 = child_tid
     *   r8  = tls
     *
     * On return:
     *   rax == 0          → we are the child (running on child_stack)
     *   rax >  0          → we are the parent (rax = child TID)
     *   rax <  0          → error
     */
    mov  rax, SYS_clone
    mov  rdi, (CLONE_VM | CLONE_THREAD | CLONE_SETTLS)
    lea  rsi, [rip + child_stack_top]
    xor  rdx, rdx
    xor  r10, r10
    xor  r8,  r8
    syscall

    test rax, rax
    js   .Lparent_fail     /* negative → clone failed; exit with error */
    jz   .Lchild_entry     /* zero → we are the child */

    /* ---------- parent path ---------- */
    /*
     * futex(&shared_var, FUTEX_WAIT, 1, NULL, NULL, 0)
     * Blocks while *shared_var == 1.  Child writes 42 then FUTEX_WAKE.
     */
.Lparent_wait:
    mov  rax, SYS_futex
    lea  rdi, [rip + shared_var]
    mov  rsi, FUTEX_WAIT
    mov  rdx, 1                 /* expected value */
    xor  r10, r10               /* timeout = NULL */
    xor  r8,  r8                /* uaddr2 = NULL */
    xor  r9,  r9                /* val3 = 0 */
    syscall
    /*
     * FUTEX_WAIT returns:
     *   0       → woken up normally
     *   -EAGAIN → *addr != expected (child already wrote)
     *   -EINTR  → spurious; we should re-check value
     *
     * In all cases we proceed to read shared_var and exit with it.
     * If shared_var == 42, child ran successfully.
     */

    /* Read shared_var and exit with that value */
    lea  rax, [rip + shared_var]
    mov  edi, dword ptr [rax]
    mov  rax, SYS_exit_group
    syscall
    ud2

.Lparent_fail:
    mov  rax, SYS_exit_group
    mov  rdi, 1
    syscall
    ud2

    /* ---------- child path ---------- */
    /*
     * Child runs on child_stack_top (CLONE_VM → shares parent's address
     * space).  Write 42 to shared_var, FUTEX_WAKE one waiter, then exit
     * the thread.
     *
     * We must NOT call exit_group here (that would kill the whole
     * process group, including the parent before it reads shared_var).
     * Use SYS_exit (60) to exit just this thread.
     */
.Lchild_entry:
    lea  rax, [rip + shared_var]
    mov  dword ptr [rax], 42

    /* futex(&shared_var, FUTEX_WAKE, 1, NULL, NULL, 0) */
    mov  rax, SYS_futex
    lea  rdi, [rip + shared_var]
    mov  rsi, FUTEX_WAKE
    mov  rdx, 1                 /* wake up to 1 waiter */
    xor  r10, r10
    xor  r8,  r8
    xor  r9,  r9
    syscall

    /* sys_exit(0) — terminate this thread only */
    mov  rax, SYS_exit
    xor  rdi, rdi
    syscall
    ud2

/*
 * .data — shared_var lives here so CLONE_VM makes it visible to the child.
 * Initialized to 0; parent sets it to 1 before clone, child sets to 42.
 */
.section .data
.align 4
shared_var:
    .long 0

/*
 * .bss-style stack for the child thread.  4 KiB, aligned to 16 bytes
 * as required by x86_64 ABI.  child_stack_top points to the TOP of
 * the region since stacks grow downward.
 */
.section .bss
.align 16
child_stack_base:
    .skip 4096
child_stack_top:
