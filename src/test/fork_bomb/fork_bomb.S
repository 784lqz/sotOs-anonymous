/*
 * sotOs · Pillar-2 P2b · fork-bomb gate fixture.
 *
 * No libc, no PT_INTERP, no relocations.  Tiny x86_64 binary that calls
 * fork() in a tight loop FAR past SOTBOX_FORK_QUOTA (16).  The OS is
 * expected to detect the abusive fork rate (per-cell attempt quota),
 * quarantine the cell (Tier-2 + suspend subtree) and terminate it — so the
 * exit_group() below is never actually reached once quarantined.
 *
 * Build (matches fork_test.bin recipe):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none -o fork_bomb.bin fork_bomb.S
 *   strip fork_bomb.bin
 *
 * Or via the included Makefile.fixture target.
 */

.section .text
.global _start
_start:
    /* r12 = iteration count (64 > SOTBOX_FORK_QUOTA=16) */
    mov $64, %r12

.Lloop:
    /* fork() · sys 57 · no args */
    mov $57, %rax
    syscall

    dec %r12
    jnz .Lloop

    /* exit_group(0) · sys 231 · (unreached once quarantined) */
    mov $231, %rax
    xor %rdi, %rdi
    syscall

.Lhang:
    jmp .Lhang
