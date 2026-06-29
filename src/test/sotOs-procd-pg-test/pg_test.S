/*
 * sotOs · procd PR 9 · process-group test fixture (asm).
 *
 * Exercises the OP_SETSID + OP_SETPGID + OP_GETPGID shadow-announce
 * path against procd.  The fixture forks once; the child detaches into
 * a fresh session via setsid() and then reads its pgid back via
 * getpgid(0).  The "ok" flag is 1 when the loop closes cleanly · sid
 * is positive (no EPERM) and getpgid(0) returns the same value.
 *
 * Why fork-first: a freshly procd-spawned slot has pgid == synthetic_pid
 * (its own group leader · inherited from procd_handle_spawn's defaults).
 * Linux setsid() returns EPERM in that state, mirrored 1:1 by
 * procd_handle_setsid.  fork() copies pgid from parent so the child's
 * pgid still equals the *parent's* synthetic_pid (procd_handle_fork inherits
 * parent->pgid), which is distinct from the child's own synthetic_pid · the
 * child is no longer a pgrp leader and setsid succeeds, returning the
 * child's synthetic_pid as the new sid + pgid.
 *
 * Stdout shape (a single line, parsed by smoke-procd.sh):
 *   [pg-test] before_pgrp=<pgid> sid=<sid> pgid=<pgid_after> ok=<0|1>
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o procd_pg_test.bin pg_test.S
 *   strip procd_pg_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

.section .text
.global _start
_start:
    /* fork() · sys 57 · returns child pid in parent, 0 in child. */
    mov $57, %rax
    syscall
    test %rax, %rax
    jz   .Lchild

.Lparent:
    /* wait4(-1, NULL, 0, NULL) · sys 61 · wait for the child to print
     * before the parent exits.  Without the wait, the parent could exit
     * group before procd's setsid log line lands, and the test fixture
     * would race the [procd] markers with [orch] EOF cleanup. */
    mov $61, %rax
    mov $-1, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    xor %r10, %r10
    syscall

    /* exit_group(0) · the parent always exits 0; the child's status
     * (the ok flag) is the load-bearing signal in stdout. */
    mov $231, %rax
    xor %rdi, %rdi
    syscall
    ud2

.Lchild:
    /* === step 1: getpgrp() · sys 111 · save in r12 (before_pgrp) === */
    mov $111, %rax
    syscall
    mov %rax, %r12      /* r12 = before_pgrp */

    /* === step 2: setsid() · sys 112 · save in r13 (sid) === */
    mov $112, %rax
    syscall
    mov %rax, %r13      /* r13 = sid (>0 on success, -EPERM on already-leader) */

    /* === step 2b: setpgid(0, 0) · sys 109 ·
     * "make me the leader of a group named after my own pid".  After
     * setsid above we already are (procd sets pgid=synthetic_pid in
     * setsid), so this is a no-op invariant check · its purpose is to
     * exercise the OP_SETPGID announce path so smoke-procd.sh's
     * "[procd] setpgid slot=" pattern fires.  We don't inspect the
     * return value · setpgid returns 0 on success and the operator
     * visibility lives in the [procd] log line on the procd side. */
    mov $109, %rax
    xor %rdi, %rdi
    xor %rsi, %rsi
    syscall

    /* === step 3: getpgid(0) · sys 121 · save in r14 (pgid) === */
    mov $121, %rax
    xor %rdi, %rdi      /* target_pid = 0 · self */
    syscall
    mov %rax, %r14      /* r14 = pgid */

    /* === step 4: compute ok = (sid > 0 && pgid == sid) === */
    xor %r15, %r15      /* r15 = ok (default 0) */
    test %r13, %r13
    jle  .Lwrite        /* sid <= 0 · ok stays 0 */
    cmp  %r13, %r14
    jne  .Lwrite        /* pgid != sid · ok stays 0 */
    mov $1, %r15        /* both invariants hold · ok = 1 */

.Lwrite:
    /* === step 5: format the result line into a stack buffer ===
     * Buffer layout (max 128 bytes is plenty):
     *   "[pg-test] before_pgrp=<u32> sid=<i32> pgid=<u32> ok=<0|1>\n"
     *
     * We unroll a simple unsigned decimal printer · the values fit in
     * 32 bits (procd assigns synthetic_pid from a monotonic counter <=256).
     * The "sid=" field can be negative when setsid returns -EPERM ·
     * we handle the sign by checking r13's high bit and emitting '-'.
     *
     * Stack layout: 256-byte aligned buffer at rsp-256, written
     * forward as we emit characters.  rbx holds the write cursor. */
    sub $256, %rsp
    mov %rsp, %rbx

    /* Prefix · "[pg-test] before_pgrp=" */
    lea prefix1(%rip), %rsi
    mov $prefix1_len, %rcx
    call .Lcopy

    /* before_pgrp (unsigned) */
    mov %r12, %rax
    call .Lemit_u64

    /* " sid=" */
    lea sep_sid(%rip), %rsi
    mov $sep_sid_len, %rcx
    call .Lcopy

    /* sid (signed) */
    mov %r13, %rax
    call .Lemit_i64

    /* " pgid=" */
    lea sep_pgid(%rip), %rsi
    mov $sep_pgid_len, %rcx
    call .Lcopy

    /* pgid (unsigned · always non-negative when present) */
    mov %r14, %rax
    call .Lemit_u64

    /* " ok=" */
    lea sep_ok(%rip), %rsi
    mov $sep_ok_len, %rcx
    call .Lcopy

    /* ok (0 or 1) */
    add $'0', %r15
    mov %r15b, (%rbx)
    inc %rbx

    /* trailing newline */
    movb $'\n', (%rbx)
    inc %rbx

    /* write(1, buf, len = rbx - rsp) · sys 1 */
    mov %rbx, %rdx
    sub %rsp, %rdx      /* rdx = byte count */
    mov $1, %rax
    mov $1, %rdi
    mov %rsp, %rsi
    syscall

    /* exit_group(ok ? 0 : 1) · sys 231 ·
     * subtract back to recover ok (we already added '0' to it). */
    sub $'0', %r15
    mov $1, %rdi
    test %r15, %r15
    jz   .Lexit_with_rdi
    xor %rdi, %rdi
.Lexit_with_rdi:
    mov $231, %rax
    syscall
    ud2

/* === helpers · all use rbx as the output cursor and clobber rax/rsi/rcx */

/* .Lcopy: copy rcx bytes from rsi into [rbx], advance rbx by rcx. */
.Lcopy:
    test %rcx, %rcx
    jz   .Lcopy_done
.Lcopy_loop:
    mov (%rsi), %al
    mov %al, (%rbx)
    inc %rsi
    inc %rbx
    dec %rcx
    jnz .Lcopy_loop
.Lcopy_done:
    ret

/* .Lemit_u64: write decimal of rax (unsigned) into [rbx], advance rbx. */
.Lemit_u64:
    /* Special-case zero so the loop below doesn't emit an empty digit. */
    test %rax, %rax
    jnz  .Lemit_u64_nonzero
    movb $'0', (%rbx)
    inc %rbx
    ret
.Lemit_u64_nonzero:
    /* Reverse-decimal print · push remainders onto stack, pop into buf. */
    xor %rcx, %rcx
.Lemit_u64_div:
    test %rax, %rax
    jz   .Lemit_u64_pop
    xor %rdx, %rdx
    mov $10, %rsi
    div %rsi            /* rax /= 10, rdx = remainder */
    add $'0', %dl
    push %rdx
    inc %rcx
    jmp .Lemit_u64_div
.Lemit_u64_pop:
    test %rcx, %rcx
    jz   .Lemit_u64_done
    pop %rdx
    mov %dl, (%rbx)
    inc %rbx
    dec %rcx
    jnz .Lemit_u64_pop
.Lemit_u64_done:
    ret

/* .Lemit_i64: write decimal of rax (signed) into [rbx], advance rbx.
 * Handles the negative case (e.g. setsid returning -EPERM = -1). */
.Lemit_i64:
    test %rax, %rax
    jns  .Lemit_i64_pos
    /* negative · emit '-' and negate. */
    movb $'-', (%rbx)
    inc %rbx
    neg %rax
.Lemit_i64_pos:
    jmp .Lemit_u64

.section .rodata
prefix1:
    .ascii "[pg-test] before_pgrp="
prefix1_len = . - prefix1

sep_sid:
    .ascii " sid="
sep_sid_len = . - sep_sid

sep_pgid:
    .ascii " pgid="
sep_pgid_len = . - sep_pgid

sep_ok:
    .ascii " ok="
sep_ok_len = . - sep_ok
