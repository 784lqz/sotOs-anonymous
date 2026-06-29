#include "dispatch.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/syscalls.h>
#include <lucas/pledge.h>
#include <lucas/functor.h>
#include <orch/proto.h>
#include <sotguard/event.h>
#include <stdio.h>
#include <string.h>

/* apk-fs · set the thread-local "current caller" for the whole syscall so the
 * VFS backends' per-session visibility gate (op_stat/op_read/op_getdents) sees
 * the REAL session caller.  Previously only open/read/the mutation handlers
 * bracketed this, so stat()/getdents()/access() ran with a NULL caller → the
 * backend treated them as the operator (cow_session 0) → a session-owned upper
 * inode was HIDDEN from its own session on stat/ls (ENOENT) even though open+read
 * served it (apk's `apk info`/dir-walk then failed though the DB was readable).
 * Setting it centrally fixes every read-side handler at once + preserves I1/I2
 * (a different session / the operator still resolve to a non-owner → hidden). */
extern void lucas_set_current_caller(lucas_state_t *st);

/* Forward declarations · defined in handlers_*.c (Tasks 13-19). */
int64_t lucas_sys_write       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_read        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_exit        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_exit_group  (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_brk         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_mmap        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_arch_prctl  (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_uname       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getpid      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_yield (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_open        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_creat       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_close       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_lseek       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_stat        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fstat       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_newfstatat  (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getdents64  (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_access      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_readlink    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_ioctl       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_rt_sigaction    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_rt_sigprocmask  (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sigaltstack     (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_set_tid_address (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_prlimit64       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getrlimit       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sysinfo         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setitimer       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getitimer       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getuid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getgid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setuid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setgid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_geteuid         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getegid         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_gettimeofday    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_clock_gettime   (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fcntl           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_munmap          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_writev          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_readv           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_clone           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fork            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_execve          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_wait4           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_pipe            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_pipe2           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_dup2            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_dup3            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_close_range     (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* L3b-T6: new syscall handlers for busybox sh support. */
int64_t lucas_sys_dup             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getppid         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_ptrace          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_chdir           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fchdir          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getcwd          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_nanosleep       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_set_robust_list (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getrandom       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_rseq            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getpgrp         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setpgid         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getpgid         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setsid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getsid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* L3c-T3: signal/kill syscalls */
int64_t lucas_sys_kill            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_tkill           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_tgkill          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* L10: busybox vi startup syscalls */
int64_t lucas_sys_mprotect        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_rt_sigreturn    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_select          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_poll            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_pselect6        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_ppoll           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_openat          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_unlink          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_unlinkat        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_pread64         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_pwrite64        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* L11-α-1 · Python compatibility stubs (handlers_python.c) */
int64_t lucas_sys_futex           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_epoll_create1   (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_epoll_ctl       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_epoll_wait      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_statfs          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fstatfs         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_eventfd2        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getcpu          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_madvise         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_ftruncate       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fallocate       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_memfd_create    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_get_robust_list (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getgroups       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* SYSCALL-FIVE · post-L9 stub-audit top 5 (handlers_python.c) */
int64_t lucas_sys_mremap          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_clock_getres    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_umask           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setrlimit       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getrusage       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* sotNet-α · socket-syscall ABI stubs (spec §12.8.4) */
int64_t lucas_sys_socket          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_connect         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_accept          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_accept4         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sendto          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_recvfrom        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sendmsg         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sendmmsg        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_recvmsg         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_shutdown        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_bind            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_listen          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getsockname     (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getpeername     (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_socketpair      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setsockopt      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getsockopt      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* L11-α-4 · close the 3 ENOSYS gaps for CPython hello-world. */
int64_t lucas_sys_gettid             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_readlinkat         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_getaffinity  (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* WINE-M1 follow-up · POSIX scheduler family completeness (handlers_sched.c). */
int64_t lucas_sys_sched_setaffinity     (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_getscheduler    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_setscheduler    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_getparam        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_setparam        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_get_priority_max(lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sched_get_priority_min(lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* OBSD-δ-1 · pledge syscall (defined in pledge.c) */
int64_t lucas_sys_pledge             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* UNVEIL-CORE · unveil syscall (defined in unveil.c) */
int64_t lucas_sys_unveil             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* U4 · shared-memory subsystem (handlers_shm.c) */
int64_t lucas_sys_shm_open           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_shm_unlink         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* U1 · MS-M1 · tar-metadata syscalls (handlers_fs.c) */
int64_t lucas_sys_fchmod             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fchown             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_utimensat          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_mknod              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_mknodat            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* Linux-ABI Tier 1 · file mutations (handlers_abi.c) */
int64_t lucas_sys_mkdir              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_mkdirat            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_rmdir              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_rename             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_renameat           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_renameat2          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_chmod              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fchmodat           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_chown              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_lchown             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fchownat           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_symlink            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_symlinkat          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_link               (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_linkat             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_truncate           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_utime              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_utimes             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_futimesat          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_faccessat          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_statx              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* Linux-ABI Tier 2 · modern-binary compatibility (handlers_abi.c) */
int64_t lucas_sys_prctl              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_clone3             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setresuid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setresgid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setreuid           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setregid           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setfsuid           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setfsgid           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setgroups          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getresuid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getresgid          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_membarrier         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_flock              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* Linux-ABI Tier 3 · capture juicy attacker behavior (handlers_abi.c) */
int64_t lucas_sys_init_module        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_finit_module       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_delete_module      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_mount              (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_umount2            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_chroot             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_pivot_root         (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setxattr           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_lsetxattr          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_fsetxattr          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_getxattr           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_listxattr          (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_removexattr        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_bpf                (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_perf_event_open    (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_keyctl             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_add_key            (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_sethostname        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_setdomainname      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_reboot             (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_settimeofday       (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_clock_settime      (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_adjtimex           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
/* N-MISC-SYS · misc syscalls Python may invoke during /simulated_attacker.py. */
int64_t lucas_sys_sendfile           (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);
int64_t lucas_sys_epoll_pwait        (lucas_state_t *, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t, uint64_t);

/* ENOSYS stub · logs which syscall hit it (need rax/sysno · plumbed from fault_loop). */
extern unsigned int lucas_last_enosys_sysno;  /* set by fault_loop before calling */
static int64_t sys_enosys(lucas_state_t *st,
                           uint64_t a0, uint64_t a1, uint64_t a2,
                           uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)st; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    printf("[lucas] ENOSYS sysno=%u (a0=0x%lx a1=0x%lx a2=0x%lx)\n",
           lucas_last_enosys_sysno,
           (unsigned long)a0, (unsigned long)a1, (unsigned long)a2);
    return -(int64_t)LX_ENOSYS;
}

/*
 * lucas_dispatch_call — obsd-δ: pledge gate + handler dispatch.
 *
 * Checks the pledge bitmask BEFORE calling the handler.  If the syscall's
 * category is not in the sotBox's pledge:
 *   - increment pledge_violations counter
 *   - promote tier to 1 (silenced mode / F_1 functor)
 *   - log the violation
 *   - return 0 (synthetic success · caller sees rax=0)
 *
 * If pledge is PLEDGE_ALL (the default) or the syscall is uncategorised
 * (pledge_category returns 0), the handler is called normally.
 *
 * Callers that need the raw function pointer (e.g. for the ENOSYS diagnostic
 * path) should still call lucas_dispatch() directly.
 */
int64_t lucas_dispatch_call(lucas_state_t *st, unsigned int sysno,
                             uint64_t a0, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5) {
    /* obsd-δ: pledge check.  Skip if pledge == PLEDGE_ALL (default).
     *
     * OBSD-δ-2 · use pledge_check_args() instead of plain pledge_category()
     * so that openat/open with O_WRONLY|O_RDWR is routed to PLEDGE_WPATH
     * rather than the read-only PLEDGE_RPATH bit. The args array passed
     * here (a0..a5) is exactly the syscall ABI in register order. */
    if (st->pledge != PLEDGE_ALL) {
        const uint64_t args_array[6] = { a0, a1, a2, a3, a4, a5 };
        uint64_t cat = pledge_check_args((uint64_t)sysno, args_array);
        if (cat != 0 && !(st->pledge & cat)) {
            st->pledge_violations++;
            printf("[pledge] pid=%d violated · sysno=%u cat=0x%llx not in 0x%llx · promoting Tier 0->1 (rollback #%u)\n",
                   st->synthetic_pid, sysno,
                   (unsigned long long)cat,
                   (unsigned long long)st->pledge,
                   (unsigned int)st->pledge_violations);
            lucas_set_tier(st, 1);
            /* TIER2-AUTO-ESCALATE · if this sotbox is ALREADY at Tier-1 and
             * still violating its pledge, the operator's deception strategy
             * is being evaded.  Escalate to Tier-2 (isolated-write path) so the
             * next sendto / recvfrom routes to the synth server.  Synth
             * data path is verified end-to-end at Phase 3-D.
             *
             * Note: pledge_violations was incremented above, so on the 3rd
             * violation the counter reads 3.  We check >=3 so the FIRST two
             * violations only set Tier-1 (existing behaviour) and the third
             * promotes to Tier-2. */
            if (st->tier == 1 && st->pledge_violations >= 3) {
                lucas_set_tier(st, 2);
                printf("[tier2-auto] pid=%d · escalated to Tier-2 after "
                       "%u pledge violations\n",
                       st->synthetic_pid, (unsigned int)st->pledge_violations);
            }
            {
                extern seL4_CPtr orch_get_anomaly_ep(void);
                seL4_CPtr anomaly_ep = orch_get_anomaly_ep();
                if (anomaly_ep != 0) {
                    seL4_SetMR(0, (seL4_Word)st->synthetic_pid);
                    seL4_SetMR(1, ANOMALY_EV_PLEDGE_VIOLATION);
                    seL4_SetMR(2, (seL4_Word)sysno);
                    seL4_Call(anomaly_ep,
                              seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 3));
                }
            }
            /* SG-FAULT Phase 2 · also emit into the sotGuard event bus.
             * Additive: the IPC above remains the load-bearing path; this
             * feeds the correlation engine.  Lossy ring · best effort. */
            {
                static uint64_t sg_pledge_seq;
                sotguard_event_t ev;
                memset(&ev, 0, sizeof(ev));
                ev.pid = (uint32_t)st->synthetic_pid;
                ev.type = SG_EV_PLEDGE_VIOL;
                ev.timestamp = ++sg_pledge_seq;
                ev.detail.fault.syscall_nr = (uint32_t)sysno;
                ev.detail.fault.rip = 0;
                (void)sotguard_emit(&ev);
            }
            return 0;   /* synthetic success */
        }
    }
    /* Pledge passed (or PLEDGE_ALL) · dispatch normally.  Bracket the handler so
     * the VFS session-visibility gate sees this caller for EVERY syscall (incl.
     * stat/getdents/access, which never set it themselves). */
    lucas_handler_fn handler = lucas_dispatch(sysno);
    lucas_set_current_caller(st);
    int64_t r = handler(st, a0, a1, a2, a3, a4, a5);
    lucas_set_current_caller(NULL);
    return r;
}

/* Spec A · hint-only syscalls that are safe to no-op (return 0) because
 * ignoring them affects only performance/advice, never correctness.  Each
 * entry is justified; the table is the single source of truth.  Everything
 * NOT here keeps returning ENOSYS (the honest default) — we never noop by
 * default, which would mask real gaps with synthetic success. */
static const unsigned int safe_noop[] = {
    LX_SYS_madvise,     /* 28  · memory-use advice · hint only */
    LX_SYS_fadvise64,   /* 221 · file-access advice · hint only */
    LX_SYS_sched_yield, /* 24  · cooperative yield · returning 0 is valid */
    LX_SYS_mlock,       /* 149 · best-effort page lock · no swap in sotOs */
    LX_SYS_munlock,     /* 150 · inverse of mlock */
    LX_SYS_fsync,       /* 74  · durability hint · sotfs persists per-write via WAL */
    LX_SYS_fdatasync,   /* 75  · as fsync */
};

static int64_t sys_noop(lucas_state_t *st,
                        uint64_t a0, uint64_t a1, uint64_t a2,
                        uint64_t a3, uint64_t a4, uint64_t a5) {
    (void)st; (void)a0; (void)a1; (void)a2; (void)a3; (void)a4; (void)a5;
    printf("[lucas] noop sysno=%u (hint·safe)\n", lucas_last_enosys_sysno);
    return 0;
}

static int is_safe_noop(unsigned int sysno) {
    for (size_t i = 0; i < sizeof(safe_noop)/sizeof(safe_noop[0]); ++i)
        if (safe_noop[i] == sysno) return 1;
    return 0;
}

lucas_handler_fn lucas_dispatch(unsigned int sysno) {
    switch (sysno) {
        case LX_SYS_read:         return lucas_sys_read;
        case LX_SYS_write:        return lucas_sys_write;
        case LX_SYS_open:         return lucas_sys_open;
        case LX_SYS_unlink:       return lucas_sys_unlink;
        case LX_SYS_close:        return lucas_sys_close;
        case LX_SYS_lseek:        return lucas_sys_lseek;
        case LX_SYS_stat:         return lucas_sys_stat;
        case LX_SYS_lstat:        return lucas_sys_stat;  /* L2: no symlinks · alias to stat */
        case LX_SYS_fstat:        return lucas_sys_fstat;
        case LX_SYS_newfstatat:   return lucas_sys_newfstatat;
        case LX_SYS_unlinkat:     return lucas_sys_unlinkat;
        case LX_SYS_getdents64:   return lucas_sys_getdents64;
        case LX_SYS_access:       return lucas_sys_access;
        case LX_SYS_readlink:     return lucas_sys_readlink;
        case LX_SYS_ioctl:            return lucas_sys_ioctl;
        case LX_SYS_rt_sigaction:     return lucas_sys_rt_sigaction;
        case LX_SYS_rt_sigprocmask:   return lucas_sys_rt_sigprocmask;
        case LX_SYS_sigaltstack:      return lucas_sys_sigaltstack;
        case LX_SYS_set_tid_address:  return lucas_sys_set_tid_address;
        case LX_SYS_prlimit64:        return lucas_sys_prlimit64;
        case LX_SYS_setitimer:        return lucas_sys_setitimer;
        case LX_SYS_getitimer:        return lucas_sys_getitimer;
        case LX_SYS_getrlimit:        return lucas_sys_getrlimit;
        case LX_SYS_sysinfo:          return lucas_sys_sysinfo;
        case LX_SYS_mmap:             return lucas_sys_mmap;
        case LX_SYS_brk:          return lucas_sys_brk;
        case LX_SYS_sched_yield:  return lucas_sys_sched_yield;
        case LX_SYS_getpid:       return lucas_sys_getpid;
        case LX_SYS_exit:         return lucas_sys_exit;
        case LX_SYS_uname:        return lucas_sys_uname;
        case LX_SYS_arch_prctl:   return lucas_sys_arch_prctl;
        case LX_SYS_exit_group:   return lucas_sys_exit_group;
        case LX_SYS_getuid:       return lucas_sys_getuid;
        case LX_SYS_getgid:       return lucas_sys_getgid;
        case LX_SYS_setuid:       return lucas_sys_setuid;
        case LX_SYS_setgid:       return lucas_sys_setgid;
        case LX_SYS_geteuid:      return lucas_sys_geteuid;
        case LX_SYS_getegid:      return lucas_sys_getegid;
        case LX_SYS_gettimeofday: return lucas_sys_gettimeofday;
        case LX_SYS_clock_gettime:return lucas_sys_clock_gettime;
        case LX_SYS_fcntl:        return lucas_sys_fcntl;
        case LX_SYS_munmap:       return lucas_sys_munmap;
        case LX_SYS_readv:        return lucas_sys_readv;
        case LX_SYS_writev:       return lucas_sys_writev;
        case LX_SYS_clone:        return lucas_sys_clone;
        case LX_SYS_fork:         return lucas_sys_fork;
        case LX_SYS_vfork:        return lucas_sys_fork;  /* vfork → fork (busybox spawn) */
        case LX_SYS_execve:       return lucas_sys_execve;
        case LX_SYS_wait4:        return lucas_sys_wait4;
        case LX_SYS_kill:         return lucas_sys_kill;
        case LX_SYS_tkill:        return lucas_sys_tkill;
        case LX_SYS_tgkill:       return lucas_sys_tgkill;
        case LX_SYS_pipe:         return lucas_sys_pipe;
        case LX_SYS_pipe2:        return lucas_sys_pipe2;
        case LX_SYS_dup2:         return lucas_sys_dup2;
        case LX_SYS_dup3:         return lucas_sys_dup3;
        case LX_SYS_close_range:  return lucas_sys_close_range;
        /* L3b-T6: syscalls needed by busybox sh / ls / grep */
        case LX_SYS_dup:          return lucas_sys_dup;
        case LX_SYS_getppid:      return lucas_sys_getppid;
        case LX_SYS_ptrace:       return lucas_sys_ptrace;
        case LX_SYS_chdir:        return lucas_sys_chdir;
        case LX_SYS_fchdir:       return lucas_sys_fchdir;
        case LX_SYS_getcwd:       return lucas_sys_getcwd;
        case LX_SYS_nanosleep:    return lucas_sys_nanosleep;
        case LX_SYS_clock_nanosleep: return lucas_sys_nanosleep;  /* clockid arg ignored · same monotonic semantics */
        case LX_SYS_set_robust_list: return lucas_sys_set_robust_list;
        case LX_SYS_getrandom:    return lucas_sys_getrandom;
        case LX_SYS_rseq:         return lucas_sys_rseq;
        case LX_SYS_getpgrp:      return lucas_sys_getpgrp;
        case LX_SYS_setpgid:      return lucas_sys_setpgid;
        case LX_SYS_getpgid:      return lucas_sys_getpgid;
        case LX_SYS_setsid:       return lucas_sys_setsid;
        case LX_SYS_getsid:       return lucas_sys_getsid;
        /* L10: busybox vi startup syscalls */
        case LX_SYS_mprotect:     return lucas_sys_mprotect;
        case LX_SYS_rt_sigreturn: return lucas_sys_rt_sigreturn;
        case LX_SYS_select:       return lucas_sys_select;
        case LX_SYS_poll:         return lucas_sys_poll;
        case LX_SYS_pselect6:     return lucas_sys_pselect6;
        case LX_SYS_ppoll:        return lucas_sys_ppoll;
        case LX_SYS_openat:       return lucas_sys_openat;
        case LX_SYS_creat:        return lucas_sys_creat;
        case LX_SYS_pread64:      return lucas_sys_pread64;
        case LX_SYS_pwrite64:     return lucas_sys_pwrite64;
        /* sotNet-α · socket-syscall ABI stubs (spec §12.8.4) */
        case LX_SYS_socket:       return lucas_sys_socket;
        case LX_SYS_connect:      return lucas_sys_connect;
        case LX_SYS_accept:       return lucas_sys_accept;
        case LX_SYS_accept4:      return lucas_sys_accept4;
        case LX_SYS_sendto:       return lucas_sys_sendto;
        case LX_SYS_recvfrom:     return lucas_sys_recvfrom;
        case LX_SYS_sendmsg:      return lucas_sys_sendmsg;
        case LX_SYS_sendmmsg:     return lucas_sys_sendmmsg;
        case LX_SYS_recvmsg:      return lucas_sys_recvmsg;
        case LX_SYS_shutdown:     return lucas_sys_shutdown;
        case LX_SYS_bind:         return lucas_sys_bind;
        case LX_SYS_listen:       return lucas_sys_listen;
        case LX_SYS_getsockname:  return lucas_sys_getsockname;
        case LX_SYS_getpeername:  return lucas_sys_getpeername;
        case LX_SYS_socketpair:   return lucas_sys_socketpair;
        case LX_SYS_setsockopt:   return lucas_sys_setsockopt;
        case LX_SYS_getsockopt:   return lucas_sys_getsockopt;
        /* L11-α-1 · Python compatibility stubs */
        case LX_SYS_futex:           return lucas_sys_futex;
        case LX_SYS_epoll_create1:   return lucas_sys_epoll_create1;
        case LX_SYS_epoll_ctl:       return lucas_sys_epoll_ctl;
        case LX_SYS_epoll_wait:      return lucas_sys_epoll_wait;
        case LX_SYS_statfs:          return lucas_sys_statfs;
        case LX_SYS_fstatfs:         return lucas_sys_fstatfs;
        case LX_SYS_eventfd2:        return lucas_sys_eventfd2;
        case LX_SYS_getcpu:          return lucas_sys_getcpu;
        case LX_SYS_madvise:         return lucas_sys_madvise;
        case LX_SYS_ftruncate:       return lucas_sys_ftruncate;
        case LX_SYS_fallocate:       return lucas_sys_fallocate;
        case LX_SYS_memfd_create:    return lucas_sys_memfd_create;
        case LX_SYS_get_robust_list: return lucas_sys_get_robust_list;
        case LX_SYS_getgroups:       return lucas_sys_getgroups;
        /* SYSCALL-FIVE · post-L9 stub-audit top 5 (handlers_python.c). */
        case LX_SYS_mremap:          return lucas_sys_mremap;
        case LX_SYS_clock_getres:    return lucas_sys_clock_getres;
        case LX_SYS_umask:           return lucas_sys_umask;
        case LX_SYS_setrlimit:       return lucas_sys_setrlimit;
        case LX_SYS_getrusage:       return lucas_sys_getrusage;
        /* L11-α-4 · close the 3 ENOSYS gaps for CPython hello-world. */
        case LX_SYS_gettid:               return lucas_sys_gettid;
        case LX_SYS_readlinkat:           return lucas_sys_readlinkat;
        case LX_SYS_sched_getaffinity:    return lucas_sys_sched_getaffinity;
        /* WINE-M1 follow-up · POSIX scheduler family completeness. */
        case LX_SYS_sched_setaffinity:     return lucas_sys_sched_setaffinity;
        case LX_SYS_sched_getscheduler:    return lucas_sys_sched_getscheduler;
        case LX_SYS_sched_setscheduler:    return lucas_sys_sched_setscheduler;
        case LX_SYS_sched_getparam:        return lucas_sys_sched_getparam;
        case LX_SYS_sched_setparam:        return lucas_sys_sched_setparam;
        case LX_SYS_sched_get_priority_max:return lucas_sys_sched_get_priority_max;
        case LX_SYS_sched_get_priority_min:return lucas_sys_sched_get_priority_min;
        /* OBSD-δ-1 · sotBox-self pledge narrowing. */
        case LX_SYS_pledge:               return lucas_sys_pledge;
        /* UNVEIL-CORE · sotBox-self per-path access narrowing. */
        case LX_SYS_unveil:               return lucas_sys_unveil;
        /* U4 · POSIX shared-memory subsystem. */
        case LX_SYS_shm_open:             return lucas_sys_shm_open;
        case LX_SYS_shm_unlink:           return lucas_sys_shm_unlink;
        /* U1 · MS-M1 · tar-metadata syscalls (no-op for perm/owner/time,
         * -EPERM for device-special files since sotFS has no /dev nodes). */
        case LX_SYS_fchmod:               return lucas_sys_fchmod;
        case LX_SYS_fchown:               return lucas_sys_fchown;
        case LX_SYS_utimensat:            return lucas_sys_utimensat;
        case LX_SYS_mknod:                return lucas_sys_mknod;
        case LX_SYS_mknodat:              return lucas_sys_mknodat;
        /* Linux-ABI Tier 1 · file mutations · don't leak the honeypot via ENOSYS. */
        case LX_SYS_mkdir:                return lucas_sys_mkdir;
        case LX_SYS_mkdirat:              return lucas_sys_mkdirat;
        case LX_SYS_rmdir:                return lucas_sys_rmdir;
        case LX_SYS_rename:               return lucas_sys_rename;
        case LX_SYS_renameat:             return lucas_sys_renameat;
        case LX_SYS_renameat2:            return lucas_sys_renameat2;
        case LX_SYS_chmod:                return lucas_sys_chmod;
        case LX_SYS_fchmodat:             return lucas_sys_fchmodat;
        /* fchmodat2 (452, Linux 6.6+) · same shape as fchmodat + a flags arg
         * (ignored here).  Real glibc/tar prefer it; left as ENOSYS it drove
         * tar's fallback into a "Bad file descriptor" error + faulting path. */
        case LX_SYS_fchmodat2:            return lucas_sys_fchmodat;
        case LX_SYS_chown:                return lucas_sys_chown;
        case LX_SYS_lchown:               return lucas_sys_lchown;
        case LX_SYS_fchownat:             return lucas_sys_fchownat;
        case LX_SYS_symlink:              return lucas_sys_symlink;
        case LX_SYS_symlinkat:            return lucas_sys_symlinkat;
        case LX_SYS_link:                 return lucas_sys_link;
        case LX_SYS_linkat:               return lucas_sys_linkat;
        case LX_SYS_truncate:             return lucas_sys_truncate;
        case LX_SYS_utime:                return lucas_sys_utime;
        case LX_SYS_utimes:               return lucas_sys_utimes;
        case LX_SYS_futimesat:            return lucas_sys_futimesat;
        case LX_SYS_faccessat:            return lucas_sys_faccessat;
        case LX_SYS_faccessat2:           return lucas_sys_faccessat;  /* same ABI */
        case LX_SYS_statx:                return lucas_sys_statx;
        /* Linux-ABI Tier 2 · modern-binary compatibility (no clean fallback). */
        case LX_SYS_prctl:                return lucas_sys_prctl;
        case LX_SYS_clone3:               return lucas_sys_clone3;
        case LX_SYS_setresuid:            return lucas_sys_setresuid;
        case LX_SYS_setresgid:            return lucas_sys_setresgid;
        case LX_SYS_setreuid:             return lucas_sys_setreuid;
        case LX_SYS_setregid:             return lucas_sys_setregid;
        case LX_SYS_setfsuid:             return lucas_sys_setfsuid;
        case LX_SYS_setfsgid:             return lucas_sys_setfsgid;
        case LX_SYS_setgroups:            return lucas_sys_setgroups;
        case LX_SYS_getresuid:            return lucas_sys_getresuid;
        case LX_SYS_getresgid:            return lucas_sys_getresgid;
        case LX_SYS_membarrier:           return lucas_sys_membarrier;
        case LX_SYS_flock:                return lucas_sys_flock;
        /* Linux-ABI Tier 3 · capture juicy attacker behavior (log + plausible). */
        case LX_SYS_init_module:          return lucas_sys_init_module;
        case LX_SYS_finit_module:         return lucas_sys_finit_module;
        case LX_SYS_delete_module:        return lucas_sys_delete_module;
        case LX_SYS_mount:                return lucas_sys_mount;
        case LX_SYS_umount2:              return lucas_sys_umount2;
        case LX_SYS_chroot:               return lucas_sys_chroot;
        case LX_SYS_pivot_root:           return lucas_sys_pivot_root;
        case LX_SYS_setxattr:             return lucas_sys_setxattr;
        case LX_SYS_lsetxattr:            return lucas_sys_lsetxattr;
        case LX_SYS_fsetxattr:            return lucas_sys_fsetxattr;
        case LX_SYS_getxattr:             return lucas_sys_getxattr;
        case LX_SYS_lgetxattr:            return lucas_sys_getxattr;
        case LX_SYS_fgetxattr:            return lucas_sys_getxattr;
        case LX_SYS_listxattr:            return lucas_sys_listxattr;
        case LX_SYS_llistxattr:           return lucas_sys_listxattr;  /* no xattrs · return 0 (was ENOSYS · strace tell) */
        case LX_SYS_flistxattr:           return lucas_sys_listxattr;
        case LX_SYS_removexattr:          return lucas_sys_removexattr;
        case LX_SYS_lremovexattr:         return lucas_sys_removexattr;
        case LX_SYS_fremovexattr:         return lucas_sys_removexattr;
        case LX_SYS_bpf:                  return lucas_sys_bpf;
        case LX_SYS_perf_event_open:      return lucas_sys_perf_event_open;
        case LX_SYS_keyctl:               return lucas_sys_keyctl;
        case LX_SYS_add_key:              return lucas_sys_add_key;
        case LX_SYS_sethostname:          return lucas_sys_sethostname;
        case LX_SYS_setdomainname:        return lucas_sys_setdomainname;
        case LX_SYS_reboot:               return lucas_sys_reboot;
        case LX_SYS_settimeofday:         return lucas_sys_settimeofday;
        case LX_SYS_clock_settime:        return lucas_sys_clock_settime;
        case LX_SYS_adjtimex:             return lucas_sys_adjtimex;
        /* N-MISC-SYS · syscalls Python may invoke during the demo. */
        case LX_SYS_sendfile:             return lucas_sys_sendfile;
        case LX_SYS_epoll_pwait:          return lucas_sys_epoll_pwait;
        default:
            /* PR 4 · consult the hint-only allowlist before ENOSYS.  An
             * explicit case above (e.g. madvise) still takes precedence;
             * the table only governs the otherwise-unhandled fall-through. */
            return is_safe_noop(sysno) ? sys_noop : sys_enosys;
    }
}
