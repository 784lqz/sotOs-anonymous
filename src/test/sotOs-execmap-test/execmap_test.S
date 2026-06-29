/* sotOs · LUCAS · SP1 PR 4 · writable-executable memory test fixture (asm).
 *
 * GATING PROOF for the whole SP1 arc: a TRUSTED sotbox must be able to
 * execute memory it mapped writable.  The in-OS C compiler (tcc -run,
 * PR 5) generates machine code into a writable buffer and jumps into it;
 * before this can work, LUCAS's mmap handler must grant a page that is
 * BOTH writable (ReadWrite caprights) AND executable (default no-NX
 * VMAttributes).  PR 4 relaxes the OBSD-ε W^X rejection for st->trusted
 * sotboxes; this fixture proves the relaxation actually yields an
 * executable writable page on this build.
 *
 * DESIGN · why the executed stub does NOT issue a syscall itself:
 *   LUCAS has a separate OBSD-ε MSYSCALL gate (src/lucas/fault_loop.c)
 *   that flags any `syscall` whose RIP is outside the ELF .text range —
 *   i.e. a syscall issued FROM a writable/anon page — as exploit-shellcode
 *   behaviour.  That gate is orthogonal to PR 4's W^X relaxation and is
 *   out of this PR's scope.  To prove ONLY the W^X / executable-writable
 *   capability cleanly, the copied stub runs pure computation and RETURNS
 *   to the caller; the caller (running in legitimate .text) verifies the
 *   stub's result and prints the success marker via a normal stdout write.
 *   Control returning with the stub's computed magic in hand is proof the
 *   CPU fetched-and-executed instructions from the writable-mapped page.
 *
 * Sequence (raw x86_64 syscalls · no libc · spawned TRUSTED at boot):
 *   1. write(1, banner)                       · "[execmap-test] alive"
 *   2. mmap(0, 4096, PROT_READ|PROT_WRITE|PROT_EXEC=0x7,
 *           MAP_PRIVATE|MAP_ANONYMOUS=0x22, -1, 0)  · sysno 9
 *      On an untrusted box the W^X rejection returns -EINVAL here; on a
 *      trusted box PR 4 grants the RWX page.  rc<0 -> FAIL (no exec OK).
 *   3. copy the code stub into [page + 0] (the page is the entry point).
 *      The stub is position-independent: it sets %rax to a known magic
 *      (EXECMAP_MAGIC = 0x5EC0DE17) and `ret`s.  Pure compute · no syscall · so
 *      it does not trip the MSYSCALL gate.
 *   4. call into the writable-mapped page.  If the jump faulted (page not
 *      executable) control never returns and the marker never prints.
 *   5. verify %rax == magic on return · if so print "[execmap-test] exec
 *      OK" (from .text), else FAIL.
 *   6. exit_group(0).
 *
 * The operator-visible serial markers are:
 *   [execmap-test] alive                 (fixture started)
 *   [execmap-test] exec OK               (smoke gate EXECMAP·exec-ok ·
 *                                         control RETURNED from code that
 *                                         RAN INSIDE the writable-mapped
 *                                         page, carrying the magic value)
 *   [execmap-test] FAIL                  (mmap rejected, jump faulted, or
 *                                         the magic did not survive)
 *
 * Hand-derived asm · no libc · static ELF · committed binary.
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none \
 *       -o execmap_test.bin execmap_test.S
 *   strip execmap_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

/* Magic the in-page stub computes and the caller verifies on return. */
#define EXECMAP_MAGIC 0x5EC0DE17

.section .text
.global _start
_start:
    /* ============================================================ */
    /* 1. write(1, banner, banner_len) · stdout · sys 1            */
    /* ============================================================ */
    mov $1, %eax
    mov $1, %edi
    lea banner(%rip), %rsi
    mov $banner_len, %edx
    syscall

    /* ============================================================ */
    /* 2. mmap(0, 4096, RWX=0x7, MAP_PRIVATE|ANON=0x22, -1, 0)·sys9 */
    /* ============================================================ */
    mov $9, %rax
    xor %rdi, %rdi              /* addr = 0 (let LUCAS pick) */
    mov $4096, %rsi            /* length = one page */
    mov $0x7, %rdx             /* PROT_READ|PROT_WRITE|PROT_EXEC */
    mov $0x22, %r10            /* MAP_PRIVATE|MAP_ANONYMOUS */
    mov $-1, %r8               /* fd = -1 */
    xor %r9, %r9               /* offset = 0 */
    syscall
    test %rax, %rax
    js   .Lfail                /* rc<0 · mmap RWX rejected · FAIL */
    mov %rax, %r15             /* r15 = page base */

    /* ============================================================ */
    /* 3. copy the code stub into [page + 0]                       */
    /*    rsi=src(stub) rdi=dst(page) rcx=stub_len                 */
    /* ============================================================ */
    lea stub_begin(%rip), %rsi
    mov %r15, %rdi
    mov $stub_len, %rcx
    rep movsb

    /* ============================================================ */
    /* 4. call into the writable-mapped page (stub at page base).  */
    /*    The stub sets %rax = magic and `ret`s · pure compute, no */
    /*    syscall, so the MSYSCALL gate is not involved.  A fault   */
    /*    here (non-executable page) never returns.                 */
    /* ============================================================ */
    mov %r15, %rax
    call *%rax                  /* -> stub · returns with %rax = magic */

    /* ============================================================ */
    /* 5. verify the stub's magic survived the call into the page. */
    /* ============================================================ */
    mov $EXECMAP_MAGIC, %ecx
    cmp %ecx, %eax
    jne .Lfail

    /* exec OK · printed from .text (legitimate syscall site) */
    mov $1, %eax
    mov $1, %edi
    lea ok_msg(%rip), %rsi
    mov $ok_msg_len, %edx
    syscall
    jmp .Lexit

.Lfail:
    mov $1, %eax
    mov $2, %edi               /* stderr */
    lea fail_msg(%rip), %rsi
    mov $fail_msg_len, %edx
    syscall

.Lexit:
    mov $231, %eax             /* exit_group(0) */
    xor %edi, %edi
    syscall
    ud2

/* ================================================================ */
/* Position-independent code stub · copied into the RWX page and    */
/* executed there.  Pure computation: load the magic into %rax and  */
/* return to the caller.  No syscall · uses only immediates · runs   */
/* correctly at any runtime load address.                            */
/* ================================================================ */
.balign 16
stub_begin:
    mov $EXECMAP_MAGIC, %eax    /* return value the caller verifies */
    ret
stub_end:
stub_len = stub_end - stub_begin

.section .rodata
banner:
    .ascii "[execmap-test] alive\n"
banner_len  = . - banner

ok_msg:
    .ascii "[execmap-test] exec OK\n"
ok_msg_len  = . - ok_msg

fail_msg:
    .ascii "[execmap-test] FAIL\n"
fail_msg_len = . - fail_msg
