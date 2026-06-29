/* sotOs · LUCAS · PR 6 · POSIX-surface syscall test fixture (asm).
 *
 * REAL runtime validation of the LUCAS POSIX surface arc (PRs 1-5):
 *   PR 1  unlink(87)              · delete a file, assert it's gone
 *   PR 3  readv(19) / writev(20)  · scatter-gather round-trip
 *   PR 4  safe_noop[] / madvise   · madvise(0,0,0) returns 0 (noop)
 *   PR 5  console/FS boundary     · write(1,...) to stdout (must NOT
 *                                    count as a filesystem mutation /
 *                                    promote the box)
 *
 * Sequence (raw x86_64 syscalls · no libc):
 *   1. write(1, banner)                       · "[syscall-test] alive"
 *   2. open("/tmp/sc.tmp", O_CREAT|O_WRONLY|O_TRUNC=0x241, 0644) -> fd
 *      write(fd, "hello", 5); close(fd)
 *   3. writev/readv round-trip to /tmp/sc.iov  · "[syscall-test] iov OK"
 *   4. unlink("/tmp/sc.tmp")                   · sysno 87
 *   5. open("/tmp/sc.tmp", O_RDONLY=0)         · expect rc < 0 (ENOENT).
 *      If rc >= 0 -> FAIL marker + skip ALL PASS.
 *   6. madvise(0, 0, 0)                        · sysno 28 · expect rc == 0
 *   7. if all good: write(1, "[syscall-test] ALL PASS\n")
 *      else:        write(2, "[syscall-test] FAIL\n")
 *   8. exit_group(0)                           · sysno 231
 *
 * r12 tracks pass/fail (0 = still passing, 1 = a step diverged).
 *
 * Hand-derived asm · no libc · static ELF · committed binary.
 *
 * Build (host gcc, committed binary):
 *   gcc -no-pie -nostdlib -static -Wl,--build-id=none \
 *       -o syscall_test.bin syscall_test.S
 *   strip syscall_test.bin
 *
 * Or via the included Makefile.fixture target.
 */

.section .text
.global _start
_start:
    /* r12 = fail flag · starts 0 (passing) */
    xor %r12, %r12

    /* ============================================================ */
    /* 1. write(1, banner, banner_len) · stdout · sys 1            */
    /*    PR 5 · this fd-1 write must NOT count toward write_count  */
    /* ============================================================ */
    mov $1, %rax
    mov $1, %rdi
    lea banner(%rip), %rsi
    mov $banner_len, %rdx
    syscall

    /* ============================================================ */
    /* 2. open("/tmp/sc.tmp", O_CREAT|O_WRONLY|O_TRUNC, 0644) · sys2 */
    /* ============================================================ */
    mov $2, %rax
    lea path_tmp(%rip), %rdi
    mov $0x241, %rsi            /* O_CREAT|O_WRONLY|O_TRUNC */
    mov $0x1A4, %rdx            /* 0644 */
    syscall
    test %rax, %rax
    js   .Lopen_create_fail
    mov %rax, %r13             /* save fd */
    /* write(fd, "hello", 5) */
    mov $1, %rax
    mov %r13, %rdi
    lea body_hello(%rip), %rsi
    mov $5, %rdx
    syscall
    cmp $5, %rax
    jne .Lwrite_fail
    /* close(fd) · sys 3 */
    mov $3, %rax
    mov %r13, %rdi
    syscall
    jmp .Liov

.Lopen_create_fail:
    mov $1, %r12
    jmp .Liov
.Lwrite_fail:
    mov $1, %r12
    /* still close the fd best-effort */
    mov $3, %rax
    mov %r13, %rdi
    syscall

    /* ============================================================ */
    /* 3. writev/readv round-trip to /tmp/sc.iov · PR 3            */
    /*    writev two segments ("foo"+"bar"=6) · lseek 0 · readv    */
    /*    back into a 6-byte buffer · assert total==6 each side.   */
    /* ============================================================ */
.Liov:
    /* open("/tmp/sc.iov", O_CREAT|O_RDWR|O_TRUNC=0x242, 0644) */
    mov $2, %rax
    lea path_iov(%rip), %rdi
    mov $0x242, %rsi           /* O_CREAT|O_RDWR|O_TRUNC */
    mov $0x1A4, %rdx           /* 0644 */
    syscall
    test %rax, %rax
    js   .Liov_fail
    mov %rax, %r14             /* save iov fd */

    /* writev(fd, iov_write, 2) · sys 20 */
    mov $20, %rax
    mov %r14, %rdi
    lea iov_write(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $6, %rax               /* "foo"(3) + "bar"(3) = 6 */
    jne .Liov_close_fail

    /* lseek(fd, 0, SEEK_SET=0) · sys 8 */
    mov $8, %rax
    mov %r14, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    syscall

    /* readv(fd, iov_read, 2) · sys 19 · into iov_buf split 3+3 */
    mov $19, %rax
    mov %r14, %rdi
    lea iov_read(%rip), %rsi
    mov $2, %rdx
    syscall
    cmp $6, %rax
    jne .Liov_close_fail

    /* close(iov fd) */
    mov $3, %rax
    mov %r14, %rdi
    syscall

    /* unlink the iov scratch file (best-effort cleanup) · sys 87 */
    mov $87, %rax
    lea path_iov(%rip), %rdi
    syscall

    /* announce iov OK to stdout */
    mov $1, %rax
    mov $1, %rdi
    lea msg_iov(%rip), %rsi
    mov $msg_iov_len, %rdx
    syscall
    jmp .Lunlink

.Liov_close_fail:
    /* close the fd before flagging failure */
    mov $3, %rax
    mov %r14, %rdi
    syscall
.Liov_fail:
    mov $1, %r12

    /* ============================================================ */
    /* 4. unlink("/tmp/sc.tmp") · sys 87 · PR 1                    */
    /* ============================================================ */
.Lunlink:
    mov $87, %rax
    lea path_tmp(%rip), %rdi
    syscall
    test %rax, %rax
    jns  .Lreopen             /* rc>=0 · unlink ok */
    mov $1, %r12              /* unlink failed */

    /* ============================================================ */
    /* 5. open("/tmp/sc.tmp", O_RDONLY=0) · expect rc < 0 (ENOENT) */
    /* ============================================================ */
.Lreopen:
    mov $2, %rax
    lea path_tmp(%rip), %rdi
    xor %rsi, %rsi             /* O_RDONLY */
    xor %rdx, %rdx
    syscall
    test %rax, %rax
    js   .Lmadvise            /* rc<0 · ENOENT · correct, file is gone */
    /* rc>=0 · file still exists after unlink · FAIL */
    mov %rax, %r13            /* close the leaked fd */
    mov $3, %rax
    mov %r13, %rdi
    syscall
    mov $1, %r12

    /* ============================================================ */
    /* 6. madvise(0, 0, 0) · sys 28 · expect rc == 0 (PR 4 noop)   */
    /* ============================================================ */
.Lmadvise:
    mov $28, %rax
    xor %rdi, %rdi
    xor %rsi, %rsi
    xor %rdx, %rdx
    syscall
    test %rax, %rax
    jz   .Lverdict            /* rc==0 · noop ok */
    mov $1, %r12

    /* ============================================================ */
    /* 7. verdict · ALL PASS (r12==0) or FAIL                      */
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
    /* 8. exit_group(0) · sys 231                                 */
    /* ============================================================ */
.Lexit:
    mov $231, %rax
    xor %rdi, %rdi
    syscall
    ud2

.section .rodata
banner:
    .ascii "[syscall-test] alive\n"
banner_len   = . - banner

body_hello:
    .ascii "hello"

path_tmp:
    .ascii "/tmp/sc.tmp"
    .byte 0

path_iov:
    .ascii "/tmp/sc.iov"
    .byte 0

seg_foo:
    .ascii "foo"
seg_bar:
    .ascii "bar"

msg_iov:
    .ascii "[syscall-test] iov OK\n"
msg_iov_len  = . - msg_iov

msg_pass:
    .ascii "[syscall-test] ALL PASS\n"
msg_pass_len = . - msg_pass

msg_fail:
    .ascii "[syscall-test] FAIL\n"
msg_fail_len = . - msg_fail

.section .data
.align 8
/* writev iovec array · {base, len} x2 · 16 bytes each (x86_64) */
iov_write:
    .quad seg_foo
    .quad 3
    .quad seg_bar
    .quad 3

/* readv iovec array · split the 6 bytes back into two 3-byte segments */
iov_read:
    .quad iov_buf
    .quad 3
    .quad iov_buf + 3
    .quad 3

.section .bss
.align 8
iov_buf:
    .space 8
