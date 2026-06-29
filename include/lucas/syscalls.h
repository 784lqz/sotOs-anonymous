/*
 * sotOs · Linux x86_64 syscall numbers.
 *
 * Subset relevant to L1 (and forward to L2+). Source of truth is
 * Linux's arch/x86/entry/syscalls/syscall_64.tbl.
 */

#ifndef SOTOS_LUCAS_SYSCALLS_H
#define SOTOS_LUCAS_SYSCALLS_H

#include <stdint.h>
#include <limits.h>

#define LX_SYS_read          0
#define LX_SYS_write         1
#define LX_SYS_open          2
#define LX_SYS_creat         85  /* creat(path, mode) · GNU tar archive creation */
#define LX_SYS_close         3
#define LX_SYS_stat          4
#define LX_SYS_fstat         5
#define LX_SYS_lstat         6
#define LX_SYS_lseek         8
#define LX_SYS_mmap          9
#define LX_SYS_munmap        11
#define LX_SYS_brk           12
#define LX_SYS_rt_sigaction  13
#define LX_SYS_rt_sigprocmask 14
#define LX_SYS_ioctl         16
#define LX_SYS_readv         19
#define LX_SYS_writev        20
#define LX_SYS_access        21
#define LX_SYS_pipe          22
#define LX_SYS_pipe2         293
#define LX_SYS_sched_yield   24
#define LX_SYS_dup           32
#define LX_SYS_dup2          33
#define LX_SYS_nanosleep     35
#define LX_SYS_dup3         292
#define LX_SYS_close_range  436   /* apt ExecFork's fd-close fast path (else 524k-fcntl hang) */
#define LX_SYS_getpid        39
#define LX_SYS_clone         56
#define LX_SYS_fork          57
#define LX_SYS_vfork         58   /* vfork · busybox spawn path · treat as fork */
#define LX_SYS_execve        59
#define LX_SYS_exit          60
#define LX_SYS_wait4         61
#define LX_SYS_kill          62
#define LX_SYS_uname         63
#define LX_SYS_fcntl         72
#define LX_SYS_unlink        87
#define LX_SYS_getcwd        79
#define LX_SYS_readlink      89
#define LX_SYS_getrlimit     97
#define LX_SYS_sysinfo       99
#define LX_SYS_gettimeofday  96
#define LX_SYS_getuid        102
#define LX_SYS_getgid        104
#define LX_SYS_setuid        105
#define LX_SYS_setgid        106
#define LX_SYS_geteuid       107
#define LX_SYS_getegid       108
#define LX_SYS_arch_prctl    158
#define LX_SYS_getitimer     36
#define LX_SYS_setitimer     38
#define LX_SYS_sigaltstack      131
#define LX_SYS_set_tid_address  218
#define LX_SYS_clock_gettime 228
#define LX_SYS_exit_group    231
#define LX_SYS_newfstatat    262
#define LX_SYS_unlinkat      263
#define LX_SYS_getdents64    217
#define LX_SYS_prlimit64     302

/* L3c-T3: kill syscalls */
#define LX_SYS_tkill         200
#define LX_SYS_tgkill        234

/* L3b-T6: additional syscalls needed by busybox sh / ls / grep. */
#define LX_SYS_getppid       110
#define LX_SYS_ptrace        101  /* P3 · anti-debug stub · PTRACE_TRACEME(0)->0, else -1 */
#define LX_SYS_chdir         80
#define LX_SYS_fchdir        81
#define LX_SYS_set_robust_list 273
#define LX_SYS_getrandom     318
#define LX_SYS_memfd_create  319  /* L13 · wl_shm pool fd · ftruncate sizes/allocs the pool */
#define LX_SYS_rseq          334
#define LX_SYS_getpgrp       111
#define LX_SYS_setpgid       109
#define LX_SYS_getpgid       121
#define LX_SYS_setsid        112
#define LX_SYS_getsid        124

/* L10: syscall numbers needed by busybox vi during startup.
 * Linux x86_64 values from arch/x86/entry/syscalls/syscall_64.tbl */
#define LX_SYS_poll          7   /* poll(fds, nfds, timeout) */
#define LX_SYS_mprotect      10  /* mprotect(addr, len, prot) · musl uses at init */
#define LX_SYS_pread64       17  /* pread64(fd, buf, count, offset) */
#define LX_SYS_pwrite64      18  /* pwrite64(fd, buf, count, offset) · wineserver shm-file init */
#define LX_SYS_rt_sigreturn  15  /* signal trampoline · return from signal handler */
#define LX_SYS_select        23  /* select(n, rfds, wfds, efds, timeout) */
#define LX_SYS_openat        257 /* openat(dirfd, path, flags, mode) */
#define LX_SYS_pselect6      270 /* pselect6 · signal-safe select */
#define LX_SYS_ppoll         271 /* ppoll · signal-safe poll */

/* sotNet-α · socket-syscall ABI surface (spec §12.8.4).
 * Numbers match Linux x86_64 arch/x86/entry/syscalls/syscall_64.tbl. */
#define LX_SYS_socket       41
#define LX_SYS_connect      42
#define LX_SYS_accept       43
#define LX_SYS_sendto       44
#define LX_SYS_recvfrom     45
#define LX_SYS_sendmsg      46
#define LX_SYS_recvmsg      47
#define LX_SYS_shutdown     48
#define LX_SYS_bind         49
#define LX_SYS_listen       50
#define LX_SYS_getsockname  51
#define LX_SYS_getpeername  52
#define LX_SYS_socketpair   53
#define LX_SYS_setsockopt   54
#define LX_SYS_getsockopt   55
#define LX_SYS_accept4      288

/* L3b-T2: anomaly returned by lucas_sys_wait4 when it parks the caller.
 * orch_fault_loop sees this and skips seL4_Reply (the wakeup path sends
 * to the saved reply cap when the child exits). */
#define LUCAS_WAIT4_DEFERRED    ((int64_t)INT64_MIN)

/* L3b-T3: anomaly returned by lucas_sys_execve when the handler has already
 * set up fresh registers via TCB_WriteRegisters.  The fault loop must call
 * seL4_Reply (to unblock the client's syscall entry) but must NOT touch the
 * registers (rax/rip), because the new image starts at entry directly.
 * Distinct from LUCAS_WAIT4_DEFERRED which suppresses Reply entirely. */
#define LUCAS_EXEC_REPLY_RAW    ((int64_t)(INT64_MIN + 1))

/* PR 14 · canonical Linux CLONE_* flag values (uapi/linux/sched.h).
 *
 * Shared between lucas (src/lucas/handlers_proc.c) and procd
 * (src/procd/handlers_lifecycle.c) so the two layers agree on the bit
 * positions when interpreting clone() flag masks.  The legacy local
 * #defines inside lucas_sys_clone (handlers_proc.c) shadow the same
 * constants for backward source-compat; the names below use the LX_
 * prefix that the rest of the LUCAS ABI uses.  Values are stable across
 * kernel versions (set by the kernel ABI back in 2.4.x). */
#ifndef LX_CLONE_VM
#define LX_CLONE_VM             0x00000100ull
#define LX_CLONE_FS             0x00000200ull
#define LX_CLONE_FILES          0x00000400ull
#define LX_CLONE_SIGHAND        0x00000800ull
#define LX_CLONE_PIDFD          0x00001000ull
#define LX_CLONE_PTRACE         0x00002000ull
#define LX_CLONE_VFORK          0x00004000ull
#define LX_CLONE_PARENT         0x00008000ull
#define LX_CLONE_THREAD         0x00010000ull
#define LX_CLONE_NEWNS          0x00020000ull
#define LX_CLONE_SYSVSEM        0x00040000ull
#define LX_CLONE_SETTLS         0x00080000ull
#define LX_CLONE_PARENT_SETTID  0x00100000ull
#define LX_CLONE_CHILD_CLEARTID 0x00200000ull
#define LX_CLONE_DETACHED       0x00400000ull
#define LX_CLONE_UNTRACED       0x00800000ull
#define LX_CLONE_CHILD_SETTID   0x01000000ull
#define LX_CLONE_NEWCGROUP      0x02000000ull
#define LX_CLONE_NEWUTS         0x04000000ull
#define LX_CLONE_NEWIPC         0x08000000ull
#define LX_CLONE_NEWUSER        0x10000000ull
#define LX_CLONE_NEWPID         0x20000000ull
#define LX_CLONE_NEWNET         0x40000000ull
#define LX_CLONE_IO             0x80000000ull
#endif

/* PR 12 · Linux futex op codes (uapi/linux/futex.h).
 *
 * Mask FUTEX_PRIVATE_FLAG (128) + FUTEX_CLOCK_REALTIME (256) with
 * LX_FUTEX_CMD_MASK to obtain the bare op.  PRIVATE_FLAG signals a
 * proc-local optimization (futex visible only within the calling
 * process) · lucas is single-proc per sotbox so the flag is stripped
 * and the same handler path is taken.  CLOCK_REALTIME only affects
 * the timeout interpretation (lucas's futex_wait blocks indefinitely
 * today · the flag is stripped harmlessly).
 *
 * Defining the constants in the public header keeps the values in one
 * place and avoids the duplicate per-TU #defines we had in
 * handlers_python.c. */
#ifndef LX_FUTEX_WAIT
#define LX_FUTEX_WAIT             0
#define LX_FUTEX_WAKE             1
#define LX_FUTEX_REQUEUE          3
#define LX_FUTEX_CMP_REQUEUE      4
#define LX_FUTEX_WAKE_OP          5
#define LX_FUTEX_WAIT_BITSET      9
#define LX_FUTEX_WAKE_BITSET      10
#define LX_FUTEX_PRIVATE_FLAG     128
#define LX_FUTEX_CLOCK_REALTIME   256
#define LX_FUTEX_CMD_MASK         (~(LX_FUTEX_PRIVATE_FLAG | LX_FUTEX_CLOCK_REALTIME))
#endif

/* L11-α-1 · syscall stubs for Python/CPython compatibility.
 * Numbers from Linux x86_64 ABI (arch/x86/entry/syscalls/syscall_64.tbl). */
#define LX_SYS_madvise         28  /* madvise · PyMalloc arena trim · stub returns 0 */
#define LX_SYS_ftruncate       77  /* ftruncate · tempfile module */
#define LX_SYS_fallocate      285  /* fallocate · posix_fallocate sizes wl_shm pools (libwayland-cursor) */
#define LX_SYS_statfs         137  /* statfs · importlib filesystem type check */
#define LX_SYS_fstatfs        138  /* fstatfs · importlib filesystem type check */
#define LX_SYS_futex          202  /* futex · GIL + pthread mutex · CRITICAL */
#define LX_SYS_epoll_wait     232  /* epoll_wait · asyncio event loop */
#define LX_SYS_epoll_ctl      233  /* epoll_ctl · asyncio fd registration */
#define LX_SYS_get_robust_list 274 /* get_robust_list · musl thread init */
#define LX_SYS_getgroups      115  /* getgroups · STUB-AUDIT BUG-1 · was 185 (wrong); Python emits rax=115 */
#define LX_SYS_eventfd2       290  /* eventfd2 · asyncio self-pipe wakeup */
#define LX_SYS_epoll_create1  291  /* epoll_create1 · asyncio event loop */
#define LX_SYS_getcpu         309  /* getcpu · always cpu=0 node=0 */

/* N-MISC-SYS · syscalls Python may invoke during /simulated_attacker.py demo.
 * Numbers from Linux x86_64 ABI (arch/x86/entry/syscalls/syscall_64.tbl). */
#define LX_SYS_sendfile        40  /* sendfile · importlib zip loading · stub returns 0 (EOF) */
#define LX_SYS_epoll_pwait    281  /* epoll_pwait · Python 3.12 selectors · alias of epoll_wait */

/* L11-α-4 · close the 3 ENOSYS gaps for CPython hello-world. */
#define LX_SYS_gettid             186  /* gettid · musl thread bookkeeping · returns synthetic_pid */
#define LX_SYS_sched_getaffinity  204  /* sched_getaffinity · os.cpu_count() · single-CPU mask */
#define LX_SYS_readlinkat         267  /* readlinkat · /proc/self/exe probe · synthetic resolve */

/* WINE-M1 follow-up · POSIX scheduler family completeness (Linux x86_64 numbers
 * from arch/x86/entry/syscalls/syscall_64.tbl).  A real Linux never ENOSYS's
 * these; wine probes sched_setaffinity (203 → ENOSYS in run25).  Single-CPU,
 * SCHED_OTHER-only model: affinity is fixed to CPU 0, the only scheduling policy
 * is SCHED_OTHER (0) whose priority range is [0,0].  All satisfiable exactly. */
#define LX_SYS_sched_setparam        142  /* sched_setparam · accept (prio must be 0 for SCHED_OTHER) */
#define LX_SYS_sched_getparam        143  /* sched_getparam · sched_priority = 0 */
#define LX_SYS_sched_setscheduler    144  /* sched_setscheduler · only SCHED_OTHER accepted */
#define LX_SYS_sched_getscheduler    145  /* sched_getscheduler · always SCHED_OTHER (0) */
#define LX_SYS_sched_get_priority_max 146 /* SCHED_OTHER max static prio = 0 */
#define LX_SYS_sched_get_priority_min 147 /* SCHED_OTHER min static prio = 0 */
#define LX_SYS_sched_setaffinity     203  /* sched_setaffinity · accept (single CPU 0) → 0 */

/* SYSCALL-FIVE · post-L9 stub-audit top 5 fixes (docs/lucas-stub-audit.md §"Recommended next /batch").
 * Defense-in-depth for Python 3.12 boot · all are dispatch-level gaps today. */
#define LX_SYS_mremap             25   /* mremap · musl realloc / pymalloc arena grow */
#define LX_SYS_umask              95   /* umask · cpython posixmodule init r-m-w probe */
#define LX_SYS_getrusage          98   /* getrusage · resource module + _PyImport_BootstrapImp */
#define LX_SYS_setrlimit          160  /* setrlimit · Py_Main RLIMIT_STACK on some pyconfig.h builds */
#define LX_SYS_clock_getres       229  /* clock_getres · import time during module init */
#define LX_SYS_clock_nanosleep    230  /* clock_nanosleep · Python time.sleep() on modern libc */

/* U1 · MS-M1 · tar-metadata syscalls (stub-real · log + accept since sotFS
 * doesn't track perms/owners/timestamps). Linux x86_64 numbers from
 * arch/x86/entry/syscalls/syscall_64.tbl. */
#define LX_SYS_fchmod             91   /* fchmod(fd, mode) · accept silently · let tar proceed */
#define LX_SYS_fchown             93   /* fchown(fd, uid, gid) · accept silently */
#define LX_SYS_mknod              133  /* mknod(path, mode, dev) · -EPERM (no device files) */
#define LX_SYS_mknodat            259  /* mknodat(dirfd, path, mode, dev) · -EPERM */
#define LX_SYS_utimensat          280  /* utimensat(dirfd, path, times, flags) · accept */

/* PR 4 · hint-only syscalls in the safe_noop[] allowlist (src/lucas/dispatch.c).
 * Returning 0 affects only performance/advice, never correctness · numbers from
 * arch/x86/entry/syscalls/syscall_64.tbl.  (madvise=28, sched_yield=24 already
 * defined above.) */
#define LX_SYS_fsync         74   /* fsync · durability hint · sotfs persists per-write via WAL */
#define LX_SYS_fdatasync     75   /* fdatasync · as fsync */
#define LX_SYS_mlock        149   /* mlock · best-effort page lock · no swap in sotOs */
#define LX_SYS_munlock      150   /* munlock · inverse of mlock */
#define LX_SYS_fadvise64    221   /* fadvise64 · file-access advice · hint only */

/* OBSD-δ-1 · LUCAS-private syscall numbers, allocated above the Linux ABI
 * range to avoid collisions with arch/x86/entry/syscalls/syscall_64.tbl.
 * The dispatcher owns this namespace · userland calls into LUCAS via the
 * fault-loop, so we are free to pick numbers that Linux does not. The
 * memo originally suggested OpenBSD's 108/109, but those collide with
 * Linux getegid/setpgid (both defined in this header), so we land
 * pledge() at a high private slot instead. */
#define LX_SYS_pledge             1000 /* pledge · narrows the calling sotBox's mask */

/* U4 · shared-memory subsystem (LUCAS-private numbers).
 *
 * Linux x86_64 does NOT have shm_open / shm_unlink as syscalls · in glibc they
 * are wrappers around open("/dev/shm/<name>", ...) / unlink("/dev/shm/<name>").
 * To avoid colliding with the Linux ABI (where numbers 307/308 happen to be
 * unused today but could be allocated upstream tomorrow) we place them above
 * LX_SYS_pledge in the LUCAS-private namespace. The dispatcher owns this
 * range; userland reaches them via the LUCAS fault-loop, never via the
 * Linux syscall table. */
#define LX_SYS_shm_open           1001 /* shm_open(name, oflag, mode) · returns lucas fd */
#define LX_SYS_shm_unlink         1002 /* shm_unlink(name) · marks object for deletion */

/* UNVEIL-CORE · OpenBSD-style per-path access restriction (LUCAS-private).
 * Linux has no syscall for unveil(); we place it just above the shm range
 * in the LUCAS-private namespace, well clear of any current or near-future
 * Linux x86_64 syscall numbers. */
#define LX_SYS_unveil             1003 /* unveil(path, perms_str) · narrows path access */

/* ==========================================================================
 * Linux-ABI tiers (deception) · x86_64 numbers from syscall_64.tbl.
 *   Tier 1 · file mutations + realistic errno
 *   Tier 2 · modern-binary compatibility
 *   Tier 3 · capture juicy attacker behaviors
 * ========================================================================== */
/* Tier 1 · file mutations */
#define LX_SYS_truncate          76
#define LX_SYS_rename            82
#define LX_SYS_mkdir             83
#define LX_SYS_mkdirat           258
#define LX_SYS_rmdir             84
#define LX_SYS_link              86
#define LX_SYS_symlink           88
#define LX_SYS_chmod             90
#define LX_SYS_chown             92
#define LX_SYS_lchown            94
#define LX_SYS_utime             132
#define LX_SYS_utimes            235
#define LX_SYS_fchownat          260
#define LX_SYS_futimesat         261
#define LX_SYS_renameat          264
#define LX_SYS_linkat            265
#define LX_SYS_symlinkat         266
#define LX_SYS_fchmodat          268
#define LX_SYS_faccessat         269
#define LX_SYS_renameat2         316
#define LX_SYS_faccessat2        439
#define LX_SYS_fchmodat2         452
/* Tier 2 · modern-binary compatibility */
#define LX_SYS_flock             73
#define LX_SYS_setreuid          113
#define LX_SYS_setregid          114
#define LX_SYS_setgroups         116
#define LX_SYS_setresuid         117
#define LX_SYS_getresuid         118
#define LX_SYS_setresgid         119
#define LX_SYS_getresgid         120
#define LX_SYS_setfsuid          122
#define LX_SYS_setfsgid          123
#define LX_SYS_rt_sigpending     127
#define LX_SYS_rt_sigtimedwait   128
#define LX_SYS_rt_sigsuspend     130
#define LX_SYS_prctl             157
#define LX_SYS_waitid            247
#define LX_SYS_inotify_add_watch 254
#define LX_SYS_inotify_rm_watch  255
#define LX_SYS_timerfd_create    283
#define LX_SYS_timerfd_settime   286
#define LX_SYS_timerfd_gettime   287
#define LX_SYS_signalfd4         289
#define LX_SYS_inotify_init1     294
#define LX_SYS_recvmmsg          299
#define LX_SYS_sendmmsg          307
#define LX_SYS_membarrier        324
#define LX_SYS_statx             332
#define LX_SYS_clone3            435
/* Tier 3 · capture juicy attacker behaviors */
#define LX_SYS_pivot_root        155
#define LX_SYS_chroot            161
#define LX_SYS_settimeofday      164
#define LX_SYS_adjtimex          159
#define LX_SYS_clock_settime     227
#define LX_SYS_mount             165
#define LX_SYS_umount2           166
#define LX_SYS_reboot            169
#define LX_SYS_sethostname       170
#define LX_SYS_setdomainname     171
#define LX_SYS_init_module       175
#define LX_SYS_delete_module     176
#define LX_SYS_setxattr          188
#define LX_SYS_lsetxattr         189
#define LX_SYS_fsetxattr         190
#define LX_SYS_getxattr          191
#define LX_SYS_lgetxattr         192
#define LX_SYS_fgetxattr         193
#define LX_SYS_listxattr         194
#define LX_SYS_llistxattr        195
#define LX_SYS_flistxattr        196
#define LX_SYS_removexattr       197
#define LX_SYS_lremovexattr      198
#define LX_SYS_fremovexattr      199
#define LX_SYS_add_key           248
#define LX_SYS_keyctl            250
#define LX_SYS_perf_event_open   298
#define LX_SYS_bpf               321
#define LX_SYS_finit_module      313

#endif /* SOTOS_LUCAS_SYSCALLS_H */
