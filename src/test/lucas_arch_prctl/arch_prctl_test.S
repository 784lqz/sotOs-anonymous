/*
 * sotOs · PY4 · arch_prctl minimal reproducer fixture.
 *
 * Diagnostic isolator for the Python `entry+2` mystery.
 *
 * Python's musl __set_thread_area is essentially:
 *     mov $0x9e,%eax       ; SYS_arch_prctl (158)
 *     mov $0x1002,%edi     ; ARCH_SET_FS
 *     mov %tlsptr,%rsi
 *     syscall
 *     ret
 * and CPython faults on the instruction at `rip_post+2` after that ret.
 *
 * This fixture reproduces the EXACT syscall+ret pattern in a ~100-byte
 * static ELF, well isolated from the 24 MiB CPython binary.  If we get
 * `AP-PASS` in the boot log, the syscall+ret sequence works in
 * isolation → the bug is specific to Python's code/data layout.
 * If we faultwith the same signature (fault at rip_post+2, RSP intact,
 * RAX corrupted), the bug is general and we've isolated it from Python.
 *
 * No libc, no PT_INTERP, no relocations.  Build:
 *   gcc -nostdlib -static -no-pie -fno-pie -Wl,--build-id=none \
 *       -o arch_prctl_test.bin arch_prctl_test.S && strip arch_prctl_test.bin
 */

.intel_syntax noprefix

.section .text
.global _start
_start:
    /* Mimic Python's musl __set_thread_area call site: a CALL
     * pushes a return address onto the stack, then the callee
     * issues syscall + ret.  After ret we land at the next
     * instruction below. */
    call __set_thread_area
    /* If we got here, the syscall+ret completed cleanly. */

    /* write(1, msg, 8) · sys 1 */
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg]
    mov rdx, 8
    syscall

    /* exit_group(0) · sys 231 */
    mov rax, 231
    xor rdi, rdi
    syscall
1:  jmp 1b

/* The critical pattern: arch_prctl(ARCH_SET_FS, 0xdeadbeef) immediately
 * followed by `ret`.  The bogus FS base is fine — we only need to
 * exercise the syscall+ret transition that crashes Python. */
__set_thread_area:
    mov rax, 158             /* SYS_arch_prctl */
    mov rdi, 0x1002          /* ARCH_SET_FS */
    mov rsi, 0xdeadbeef      /* bogus TLS base */
    syscall
    ret                       /* ← suspicious instruction */

.section .rodata
msg:
    .ascii "AP-PASS\n"
