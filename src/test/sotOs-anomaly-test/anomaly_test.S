/* sotOs · ANOMALY · PR 7 · weighted-score test fixture (asm).
 *
 * Deterministic regression proof for the Spec B weighted suspicion
 * scoring engine (anomaly PRs 1-5).  Runs as a sotbox at boot and
 * performs a fixed raw-syscall sequence that drives the monitor's
 * per-pid score across BOTH tier thresholds (T1=20, T2=40):
 *
 *   stage 0 · setup (Tier 0)
 *     create + close six burst scratch files /tmp/st_b0..b5
 *     (O_CREAT|O_WRONLY).  open() of a non-cred /tmp path does not
 *     score; doing these while still Tier 0 keeps them clear of the
 *     Tier-1 open-with-write revoke gate.  Also open /tmp/st_doc.bin
 *     (O_CREAT|O_WRONLY) and KEEP the fd · the five writes below ride
 *     this single fd so the write-open also predates promotion.
 *
 *   stage 1 · cred recon (+15 → score 15 · still under T1=20)
 *     open("/honey-aws-creds", O_RDONLY) then close.  The path is
 *     classifier-flagged (sotos_path_is_cred_sensitive) and the vfs
 *     aliases /canary-* to the canary install, so the open resolves and
 *     forwards EV_CRED_ACCESS (weight 15).
 *
 *   stage 2 · five real-file writes (+1 each → score 20 · crosses T1)
 *     write(doc_fd, "x", 1) x5.  Each fd>=3 write forwards EV_WRITE
 *     (weight 1).  The 5th brings score 15+5=20 → reply-driven Tier 1.
 *     The fd was opened at Tier 0 so it is not write-revoked; once at
 *     Tier 1 further writes would be silenced-silenced, but five is all
 *     we need.
 *
 *   stage 3 · six-unlink burst (escalating → crosses T2)
 *     unlink(/tmp/st_b0..b5) consecutively.  The i-th unlink in a run
 *     adds min(2*i, 12): 2+4+6+8+10+12 = 42.  Cumulative 20+42 = 62 ·
 *     crosses T2=40 at the 4th unlink (20+2+4+6+8=40).  unlink is not
 *     tier-gated, so the burst keeps forwarding EV_UNLINK after the
 *     Tier-1 promotion in stage 2.
 *
 *   stage 4 · verdict
 *     if every step held: write(1, "[anomaly-test] ALL PASS\n").
 *     else:               write(2, "[anomaly-test] FAIL\n").
 *
 * The tier transitions themselves are asserted by the SMOKE GATES
 * against the monitor's serial output (a sotbox can't reliably read
 * its own tier) · this fixture only proves the sequence ran to
 * completion without faulting.  r12 tracks pass/fail (0 = passing).
 *
 * Hand-derived asm · no libc · static ELF · committed binary.
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none \
 *       -o anomaly_test.bin anomaly_test.S
 *   strip anomaly_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

.section .text
.global _start
_start:
    /* r12 = fail flag · starts 0 (passing) */
    xor %r12, %r12

    /* announce alive to stdout · sys 1 (fd 1 · console boundary) */
    mov $1, %rax
    mov $1, %rdi
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    syscall

    /* ============================================================ */
    /* stage 0a · create + close six burst files /tmp/st_b0..b5    */
    /*   while still Tier 0 (open-with-write is gated at Tier 1).   */
    /*   r13 = loop index 0..5 · r14 = path table cursor.          */
    /* ============================================================ */
    xor %r13, %r13                 /* i = 0 */
    lea burst_paths(%rip), %r14    /* &burst_paths[0] */
.Lburst_create:
    cmp $6, %r13
    jge .Ldoc_open
    /* open(burst_paths[i], O_CREAT|O_WRONLY=0x41, 0644) · sys 2 */
    mov $2, %rax
    mov (%r14), %rdi               /* burst_paths[i] */
    mov $0x41, %rsi                /* O_CREAT|O_WRONLY */
    mov $0x1A4, %rdx               /* 0644 */
    syscall
    test %rax, %rax
    js   .Lburst_create_fail
    /* close(fd) · sys 3 */
    mov %rax, %rbx
    mov $3, %rax
    mov %rbx, %rdi
    syscall
    jmp .Lburst_next
.Lburst_create_fail:
    mov $1, %r12
.Lburst_next:
    add $8, %r14                   /* next path pointer */
    inc %r13
    jmp .Lburst_create

    /* ============================================================ */
    /* stage 0b · open /tmp/st_doc.bin (O_CREAT|O_WRONLY|O_TRUNC)   */
    /*   KEEP the fd in r15 · the five writes ride this single fd.  */
    /* ============================================================ */
.Ldoc_open:
    mov $2, %rax
    lea path_doc(%rip), %rdi
    mov $0x241, %rsi               /* O_CREAT|O_WRONLY|O_TRUNC */
    mov $0x1A4, %rdx               /* 0644 */
    syscall
    test %rax, %rax
    js   .Ldoc_open_fail
    mov %rax, %r15                 /* save doc fd */
    jmp .Lcred

.Ldoc_open_fail:
    mov $1, %r12
    mov $-1, %r15                  /* anomaly · skip writes below */

    /* ============================================================ */
    /* stage 1 · cred recon · open("/honey-aws-creds", O_RDONLY)   */
    /*   forwards EV_CRED_ACCESS (+15 → score 15 · still Tier 0).   */
    /* ============================================================ */
.Lcred:
    mov $2, %rax
    lea path_cred(%rip), %rdi
    xor %rsi, %rsi                 /* O_RDONLY */
    xor %rdx, %rdx
    syscall
    test %rax, %rax
    js   .Lcred_fail               /* canary alias should resolve · rc>=0 */
    /* close the cred fd · sys 3 */
    mov %rax, %rbx
    mov $3, %rax
    mov %rbx, %rdi
    syscall
    jmp .Lwrites
.Lcred_fail:
    mov $1, %r12

    /* ============================================================ */
    /* stage 2 · five writes to doc fd · +1 each → score 20 (T1)   */
    /*   r13 = write counter 0..4.                                 */
    /* ============================================================ */
.Lwrites:
    cmp $-1, %r15                  /* doc fd valid? */
    je  .Lunlink_burst            /* no fd · skip writes (fail flagged) */
    xor %r13, %r13                 /* i = 0 */
.Lwrite_loop:
    cmp $5, %r13
    jge .Lunlink_burst
    mov $1, %rax                   /* write · sys 1 */
    mov %r15, %rdi                 /* doc fd */
    lea body_x(%rip), %rsi
    mov $1, %rdx                   /* one byte */
    syscall
    cmp $1, %rax                   /* expect 1 byte written */
    jne .Lwrite_fail
    jmp .Lwrite_next
.Lwrite_fail:
    mov $1, %r12
.Lwrite_next:
    inc %r13
    jmp .Lwrite_loop

    /* close doc fd before the burst (best-effort) · sys 3 */
.Lunlink_burst:
    cmp $-1, %r15
    je  .Lburst_unlink_start
    mov %r15, %rbx
    mov $3, %rax
    mov %rbx, %rdi
    syscall

    /* ============================================================ */
    /* stage 3 · six-unlink burst · /tmp/st_b0..b5 consecutively   */
    /*   escalating 2+4+6+8+10+12 = 42 · score 20+42 = 62 → T2.    */
    /*   r13 = index 0..5 · r14 = path table cursor.               */
    /* ============================================================ */
.Lburst_unlink_start:
    xor %r13, %r13                 /* i = 0 */
    lea burst_paths(%rip), %r14
.Lburst_unlink:
    cmp $6, %r13
    jge .Lverdict
    mov $87, %rax                  /* unlink · sys 87 */
    mov (%r14), %rdi               /* burst_paths[i] */
    syscall
    test %rax, %rax
    jns  .Lburst_unlink_next       /* rc>=0 · unlink ok */
    mov $1, %r12                   /* unlink failed */
.Lburst_unlink_next:
    add $8, %r14
    inc %r13
    jmp .Lburst_unlink

    /* ============================================================ */
    /* stage 4 · verdict · ALL PASS (r12==0) or FAIL              */
    /* ============================================================ */
.Lverdict:
    test %r12, %r12
    jnz  .Lfail
    mov $1, %rax
    mov $1, %rdi
    lea msg_pass(%rip), %rsi
    mov $msg_pass_len, %rdx
    syscall
    jmp .Lexit
.Lfail:
    mov $1, %rax
    mov $2, %rdi
    lea msg_fail(%rip), %rsi
    mov $msg_fail_len, %rdx
    syscall

    /* ============================================================ */
    /* exit_group(0) · sys 231                                    */
    /* ============================================================ */
.Lexit:
    mov $231, %rax
    xor %rdi, %rdi
    syscall
    ud2

.section .rodata
banner:
    .ascii "[anomaly-test] alive\n"
banner_len   = . - banner

body_x:
    .ascii "x"

path_cred:
    .ascii "/honey-aws-creds"
    .byte 0

path_doc:
    .ascii "/tmp/st_doc.bin"
    .byte 0

/* Six burst scratch paths · each NUL-terminated. */
p_b0: .ascii "/tmp/st_b0"
      .byte 0
p_b1: .ascii "/tmp/st_b1"
      .byte 0
p_b2: .ascii "/tmp/st_b2"
      .byte 0
p_b3: .ascii "/tmp/st_b3"
      .byte 0
p_b4: .ascii "/tmp/st_b4"
      .byte 0
p_b5: .ascii "/tmp/st_b5"
      .byte 0

msg_pass:
    .ascii "[anomaly-test] ALL PASS\n"
msg_pass_len = . - msg_pass

msg_fail:
    .ascii "[anomaly-test] FAIL\n"
msg_fail_len = . - msg_fail

.section .data
.align 8
/* Table of pointers to the six burst paths · 8 bytes each (x86_64). */
burst_paths:
    .quad p_b0
    .quad p_b1
    .quad p_b2
    .quad p_b3
    .quad p_b4
    .quad p_b5
