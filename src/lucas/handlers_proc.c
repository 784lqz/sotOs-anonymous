/*
 * sotOs · LUCAS · proc handlers · exit, exit_group, and (in later tasks)
 * getpid, sched_yield, uname, arch_prctl.
 *
 * L1 scope. Other procs go into L2+.
 */

#include "handlers.h"
#include "state.h"
#include "antidos.h"        /* P2b · SOTBOX_FORK_QUOTA + lucas_antidos_quarantine */
#include <lucas/linux_abi.h>
#include <lucas/tty_termios.h>   /* TUI · per-session termios round-trip helpers */
#include <lucas/syscalls.h>
#include <lucas/clock.h>
#include <lucas/fs_trace.h>
#include <lucas/procd_view.h>
#include <lucas/persona_session.h>   /* M3 · per-session persona context (uname nodename) */
#include <procd/functor.h>
#include <sotos/random.h>
#include <sotos/pidrand.h>   /* C2 #10 · deterministic display_pid (ASLR-independent) */
#include <stdbool.h>

#include <sel4/sel4.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <vspace/vspace.h>
#include <vka/capops.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>

extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *src_buf, size_t size);

/* L3b-T2: declared in include/orch/sotbox.h but also forward-declared here
 * so handlers_proc.c (part of the lucas static lib) can call them. */
extern void sotbox_record_exit(int pid, int exit_code);
extern int  sotbox_try_wakeup_waiter(int exited_pid, int exit_code);
extern lucas_state_t *sotbox_get_slot(int idx);

/* Forward declarations for functions defined in handlers_fs.c (used by dup stub). */
int64_t lucas_sys_dup2(lucas_state_t *st, uint64_t oldfd, uint64_t newfd,
                        uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5);

/* Forward declaration (defined in handlers_fs.c). */
void lucas_close_all_fds(lucas_state_t *st);

/* Forward declaration (defined in threading.c).  Suspends all child TCBs
 * created via clone(CLONE_VM|CLONE_THREAD) so they don't outlive the
 * parent sotBox.  Critical for slot recycling: without this, leftover
 * child TCBs keep issuing syscalls via the shared badged fault EP, and
 * those land in whatever new sotBox is later allocated to the same slot
 * (L7 investigated this as the futex WAKE-storm contaminating Python's
 * slot after pthread_test exits). */
extern void lucas_threads_suspend_all(lucas_state_t *st);

int64_t lucas_sys_exit_group(lucas_state_t *st, uint64_t code,
                              uint64_t _a1, uint64_t _a2, uint64_t _a3,
                              uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* C2 #3 (v2) · flush any buffered partial guest stdout line (a program that
     * exits without a trailing newline) before the system trace below. */
    extern void lucas_guest_line_flush(lucas_state_t *st);
    lucas_guest_line_flush(st);
    printf("[lucas] lucas_sys_exit_group(%lu) · client terminating\n",
           (unsigned long)code);

    /* Close all file descriptors: releases pipe refcounts and unblocks
     * any process waiting for EOF on the read end of a pipe we hold. */
    lucas_close_all_fds(st);

    /* WINE-M1 · drop any fcntl record locks this process held.  This is the
     * wineserver-liveness release: when wineserver exits/crashes, its prefix
     * F_WRLCK frees so the next wine launcher's F_SETLK is GRANTED and it
     * starts a fresh server (no permanently-wedged prefix). */
    {
        extern void lucas_reclock_release_owner(int synth_pid);
        lucas_reclock_release_owner(st->synthetic_pid);
    }

    /* M2-bug-5 · suspend any pthread child TCBs BEFORE the parent's TCB
     * is suspended.  Without this, the children outlive the parent and
     * keep issuing syscalls under the parent's badge, contaminating the
     * next sotBox that takes this slot (pthread_test → Python WAKE
     * storm on 0x402030 documented in L7).  This is a no-op when
     * n_threads == 0 (the common single-threaded L1 path). */
    lucas_threads_suspend_all(st);

    /* OBSD-ε OMALLOC · junk on free · the sotBox is about to be released
     * (st->exited = 1 below).  Zero all sotbox-local tracking tables AFTER
     * the close-fds + suspend-threads cleanup above so the next user of
     * this slot cannot observe stale tracking metadata from the exiting
     * client.  Defense-in-depth: orch's bootstrap path already memsets
     * the whole struct on spawn, but a future change that reuses a slot
     * without re-bootstrapping would otherwise expose residual state.
     * Each block targets a distinct sotbox-local tracking table; we do
     * NOT touch the slot's seL4 caps or the exit bookkeeping below. */
    memset(st->signal_handlers,  0, sizeof(st->signal_handlers));
    memset(st->signal_flags,     0, sizeof(st->signal_flags));
    memset(st->signal_restorers, 0, sizeof(st->signal_restorers));
    memset(st->signal_sa_mask,   0, sizeof(st->signal_sa_mask));
    memset(st->pending_signals,  0, sizeof(st->pending_signals));
    st->n_pending           = 0;
    st->signal_mask         = 0;
    st->sigaltstack_sp      = 0;
    st->sigaltstack_size    = 0;
    st->in_signal_handler   = 0;
    memset(st->futex_waiters, 0, sizeof(st->futex_waiters));
    st->n_futex_waiters     = 0;
    memset(st->epoll_table,    0, sizeof(st->epoll_table));
    st->n_epoll_instances   = 0;
    st->epoll_wait_slot     = -1;
    memset(st->eventfd_counters, 0, sizeof(st->eventfd_counters));
    st->n_eventfds          = 0;
    st->clear_child_tid     = 0;
    st->robust_list_head    = 0;
    st->robust_list_len     = 0;
    st->rseq_addr           = 0;
    st->rseq_registered     = 0;

    st->exited    = 1;
    st->exit_code = (int)code;
    seL4_TCB_Suspend(st->client_tcb);

    /* WINE-M1 · if this is a vfork child exiting WITHOUT having execve()d
     * (e.g. exec failed → glibc spawn helper _exit()s), the parent is still
     * parked in WAITING_FOR_VFORK · resume it now (no-op for non-vfork). */
    {
        extern void sotbox_vfork_resume_parent(lucas_state_t *child);
        sotbox_vfork_resume_parent(st);
    }

    /* L3b-T2: wake any parent blocked in wait4 via SaveCaller.
     * We call try_wakeup_waiter NOW (before returning to orch_fault_loop)
     * so the parent is unblocked while this handler is still on the call
     * stack.  sotbox_record_exit is called by orch_fault_loop after we
     * return (result==1 path); we do NOT call it here to avoid a double
     * entry in the zombie table for the normal exit path. */
    {
        extern int sotbox_try_wakeup_waiter_p(int exited_pid, int exit_code, int parent_pid);
        int ppid = (st->parent_slot >= 0) ? (st->parent_slot + 1) : 0;
        sotbox_try_wakeup_waiter_p(st->synthetic_pid, st->exit_code, ppid);
    }

    /* PR 6/7 · shadow-announce the exit to procd so procd's view of the
     * proc_t flips to ZOMBIE and a PROC_EXITED + SIGCHLD event lands on
     * the ring for subscribers.  Lucas's authoritative SaveCaller path
     * stays in charge of unblocking blocked wait4 callers · procd's
     * polling wait does NOT replace it (blocking wait moves to procd
     * once reply-cap saving lands · a future PR).  PR 7 dropped the
     * PROCD_TAKEOVER_SPAWN gate · the announce is now unconditional.
     *
     * caller_slot is the procd-side slot cached on lucas_state_t at
     * spawn/fork announce time.  0 means "not announced" (announce
     * failed) · we skip the call to avoid handing procd the reserved
     * "no parent" slot 0. */
    if (st->procd_slot != 0) {
        extern int orch_procd_exit(uint32_t caller_slot, int32_t exit_status);
        int pd_rc = orch_procd_exit(st->procd_slot, (int32_t)code);
        if (pd_rc < 0) {
            printf("[lucas] procd OP_EXIT announce failed rc=%d (slot=%u)\n",
                   pd_rc, st->procd_slot);
        }
    }

    /* Return value irrelevant · client is gone. */
    return 0;
}

int64_t lucas_sys_exit(lucas_state_t *st, uint64_t code,
                       uint64_t a1, uint64_t a2, uint64_t a3,
                       uint64_t a4, uint64_t a5) {
    /* exit() and exit_group() are equivalent for single-threaded L1. */
    return lucas_sys_exit_group(st, code, a1, a2, a3, a4, a5);
}

int64_t lucas_sys_arch_prctl(lucas_state_t *st, uint64_t code, uint64_t addr,
                              uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Target the CALLING thread, not always the main thread.  A WORKER thread
     * (a GLib/GTK pool thread) that sets its OWN TLS via arch_prctl must set ITS
     * tcb's FS base — using st->client_tcb set the MAIN thread's %fs instead, so
     * the worker's %fs stayed garbage → it read %fs:0x10 (the glibc pthread
     * self-pointer / pointer-guard) as garbage → garbage rbp/rdi → #GP (the GTK
     * render-thread crash).  cur_fault_tcb is the syscalling thread (SP-matched
     * by the fault loop); fall back to client_tcb single-thread. */
    seL4_CPtr tcb = st->cur_fault_tcb ? st->cur_fault_tcb : st->client_tcb;
    switch (code) {
        case LX_ARCH_SET_FS: {
            /* seL4 x86_64 provides seL4_TCB_SetTLSBase to set the FS base. */
            int err = seL4_TCB_SetTLSBase(tcb, addr);
            if (err) {
                printf("[lucas] arch_prctl SET_FS: TCB_SetTLSBase failed (%d)\n", err);
                return -(int64_t)LX_EINVAL;
            }
            printf("[lucas] arch_prctl SET_FS · base=0x%lx\n", (unsigned long)addr);
            return 0;
        }
        case LX_ARCH_SET_GS: {
            /* WINE-M1 · the Windows TEB lives in the %gs base: ntdll reads the
             * TEB self-pointer via `mov %gs:0x30,%rax`.  seL4 has no SetGSBase
             * (SetTLSBase is FS-only), but seL4_UserContext carries gs_base
             * (reg 20).  Read the TCB context, set gs_base, write it back.  The
             * fault-loop syscall return writes only the 18 general regs
             * (rip..r15), NOT fs_base/gs_base, so this value survives the return.
             * Without this, arch_prctl(SET_GS) returned -EINVAL → the spawned
             * wineboot's %gs base was never set → gs:[0x30] read garbage → #GP. */
            seL4_UserContext ctx;
            int err = seL4_TCB_ReadRegisters(tcb, false, 0,
                                              sizeof(ctx)/sizeof(seL4_Word), &ctx);
            if (err) {
                printf("[lucas] arch_prctl SET_GS: ReadRegisters failed (%d)\n", err);
                return -(int64_t)LX_EINVAL;
            }
            ctx.gs_base = (seL4_Word)addr;
            err = seL4_TCB_WriteRegisters(tcb, false, 0,
                                          sizeof(ctx)/sizeof(seL4_Word), &ctx);
            if (err) {
                printf("[lucas] arch_prctl SET_GS: WriteRegisters failed (%d)\n", err);
                return -(int64_t)LX_EINVAL;
            }
            {
                seL4_UserContext rb;
                if (seL4_TCB_ReadRegisters(tcb, false, 0,
                                           sizeof(rb)/sizeof(seL4_Word), &rb) == 0)
                    printf("[lucas] arch_prctl SET_GS readback gs_base=0x%lx\n",
                           (unsigned long)rb.gs_base);
            }
            printf("[lucas] arch_prctl SET_GS · base=0x%lx\n", (unsigned long)addr);
            return 0;
        }
        case LX_ARCH_GET_FS:
        case LX_ARCH_GET_GS: {
            /* Read the current FS/GS base from the TCB context and store it at
             * the user pointer `addr` (arch_prctl GET_* semantics). */
            seL4_UserContext ctx;
            int err = seL4_TCB_ReadRegisters(st->client_tcb, false, 0,
                                              sizeof(ctx)/sizeof(seL4_Word), &ctx);
            if (err) return -(int64_t)LX_EINVAL;
            uint64_t base = (code == LX_ARCH_GET_FS) ? (uint64_t)ctx.fs_base
                                                     : (uint64_t)ctx.gs_base;
            if (lucas_copy_to_client(st, (uintptr_t)addr, &base, sizeof(base)) != 0)
                return -(int64_t)LX_EFAULT;
            return 0;
        }
        default:
            return -(int64_t)LX_EINVAL;
    }
}

int64_t lucas_sys_uname(lucas_state_t *st, uint64_t buf_vaddr,
                        uint64_t _a1, uint64_t _a2, uint64_t _a3,
                        uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    struct lx_utsname utsname;
    memset(&utsname, 0, sizeof(utsname));
    strcpy(utsname.sysname,  "Linux");
    /* Fidelity · ONE coherent identity across uname / /etc/hostname / /proc /
     * /sys: a real Alpine 3.20 box on the linux-lts 6.6.30 kernel.  nodename
     * MUST equal `cat /etc/hostname`, else `uname -n` vs hostname is a tell.
     * M3 · per-session persona seam: an SSH session resolves its nodename from
     * its OWN persona context (lucas_persona_session_get → host), so a future
     * session can wear a different identity without a global flip.  Fallback to
     * the per-tier default for the operator / compat guests with no ctx (Tier-2
     * canary = prod-db-01, Tier 0/1 = alpine-host). */
    {
        extern int lucas_persona_session_get(uint32_t, lucas_persona_t *);
        lucas_persona_t pc;
        int have_ctx = (st->cow_session != 0 &&
                        lucas_persona_session_get(st->cow_session, &pc));
        if (have_ctx && pc.host[0])
            strcpy(utsname.nodename, pc.host);
        else
            strcpy(utsname.nodename, (st->tier == 2) ? "prod-db-01" : "alpine-host");
        /* release/version are persona-aware too — a session's `uname -a` MUST
         * match its own /proc/version.  Debian → the trixie 6.12 kernel; everyone
         * else → the Alpine linux-lts kernel. */
        if (have_ctx && pc.profile == LUCAS_PERSONA_DEBIAN) {
            strcpy(utsname.release, "6.12.43+deb13-amd64");
            strcpy(utsname.version, "#1 SMP PREEMPT_DYNAMIC Debian 6.12.43-1 (2025-08-21)");
        } else {
            strcpy(utsname.release, "6.6.30-0-lts");
            strcpy(utsname.version, "#1-Alpine SMP PREEMPT_DYNAMIC 2024-05-22 10:00:00");
        }
    }
    strcpy(utsname.machine,  "x86_64");
    /* domainname stays empty (memset above) */

    /* Copy the struct into the client's vspace at buf_vaddr. Same
     * mechanism handlers_fs.c uses for reading: temporarily map the
     * frame backing buf_vaddr into our vspace and memcpy. T13 used
     * sel4utils_dup_and_map (via vspace_get_cap) since
     * sel4utils_copy_data_to_vspace doesn't exist in our seL4_libs.
     *
     * Implement an inline copy following the same pattern as
     * handlers_fs.c. Since utsname is small (< 4KB), it fits in a
     * single frame in practice. */

    const size_t to_copy = sizeof(utsname);
    const uint8_t *src = (const uint8_t *)&utsname;
    size_t copied = 0;

    while (copied < to_copy) {
        uintptr_t client_addr = buf_vaddr + copied;
        uintptr_t page_base = client_addr & ~0xFFFUL;
        size_t offset_in_page = client_addr - page_base;
        size_t chunk = 0x1000 - offset_in_page;
        if (chunk > (to_copy - copied)) chunk = to_copy - copied;

        seL4_CPtr frame_cap = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
        if (!frame_cap) {
            printf("[lucas] uname: no frame at client vaddr 0x%lx\n",
                   (unsigned long)page_base);
            return -(int64_t)LX_EFAULT;
        }

        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                             frame_cap, seL4_PageBits);
        if (!local) {
            printf("[lucas] uname: dup_and_map failed\n");
            return -(int64_t)LX_EFAULT;
        }

        memcpy((uint8_t *)local + offset_in_page, src + copied, chunk);
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);

        copied += chunk;
    }

    printf("[lucas] uname · returned Linux 6.6.30-0-lts / x86_64 (%s)\n",
           utsname.nodename);
    return 0;
}

/* OBSD-ζ PID-DISPLAY-RANDOM · getpid/gettid return a per-sotbox random
 * uint32_t (anti-fingerprinting); internal LUCAS state still indexes by
 * the sequential synthetic_pid. */
int64_t lucas_sys_getpid(lucas_state_t *st, uint64_t _a0, uint64_t _a1,
                          uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (st->display_pid == 0) st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid); /* C2 #10 */
    return (int64_t)st->display_pid;
}

/* L11-α-4 · gettid stub.  LUCAS has no real threading yet (α-4 will share
 * vspace between TCBs), so a single-threaded process has tid == pid.
 * OBSD-ζ · return the randomized display_pid for anti-fingerprinting. */
int64_t lucas_sys_gettid(lucas_state_t *st, uint64_t _a0, uint64_t _a1,
                          uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (st->display_pid == 0) st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid); /* C2 #10 */
    return (int64_t)st->display_pid;
}

int64_t lucas_sys_sched_yield(lucas_state_t *st, uint64_t _a0, uint64_t _a1,
                               uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Fast-path: single-thread sotbox has no peer to yield to — the yield is
     * semantically a no-op, so skip the seL4_Yield() kernel IPC entirely.
     * This keeps the fast-path latency in the hundreds of cycles (matching
     * getpid) rather than the thousands that a seL4_Yield() IPC would cost.
     * Multi-thread boxes still yield cooperatively (n_threads > 0 → else). */
    if (st->n_threads == 0) return 0;
    seL4_Yield();
    return 0;
}

/* Defined below · TIOCGPGRP must mirror its value (see the case). */
int64_t lucas_sys_getpgrp(lucas_state_t *st, uint64_t, uint64_t, uint64_t,
                          uint64_t, uint64_t, uint64_t);

static int proc_exe_is_wine(const lucas_state_t *st);   /* WINE-M1 · fwd decl, defined below */

int64_t lucas_sys_ioctl(lucas_state_t *st, uint64_t fd, uint64_t request,
                         uint64_t arg, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;

    /* Doom Phase 1a · fbdev ioctls on a /dev/fb0 fd → early dispatch. */
    if (fd < LUCAS_MAX_FDS && st->fds[fd].kind == LUCAS_FD_FB) {
        extern int64_t lucas_fb_ioctl(lucas_state_t*, uint64_t, uint64_t);
        return lucas_fb_ioctl(st, request, arg);
    }

    /* For tty-related ioctls, check whether the fd is actually a terminal.
     * Pipe ends are NOT terminals; return ENOTTY so apps (ls, grep, …) detect
     * they are writing/reading from a pipe and avoid colour/column formatting. */
    bool fd_is_tty = false;
    if (fd < LUCAS_MAX_FDS) {
        lucas_fd_kind_t k = st->fds[fd].kind;
        /* STDIO fds (kind==STDIO or is_std && kind==INVALID) are ttys.
         * Pipe fds are not ttys. */
        fd_is_tty = (k == LUCAS_FD_STDIO) ||
                    (k == LUCAS_FD_INVALID && st->fds[fd].is_std);
        /* WINE-M1 · the wine launcher loads+runs the console PE in-process, so its
         * std fds 0/1/2 are hello.exe's std handles. If we report them as ttys,
         * wine's get_initial_console attaches a (nonexistent) conhost and NULLs
         * hStdOutput/hStdError → GetStdHandle returns NULL → WriteFile no-ops.
         * Force ENOTTY here: wine keeps CONSOLE_HANDLE_SHELL_NO_WINDOW, the valid
         * file handles survive into the PEB, and WriteFile reaches write_serial. */
        if (fd <= 2 && proc_exe_is_wine(st)) fd_is_tty = false;
    }

    switch (request) {
        case LX_TCGETS: {
            if (!fd_is_tty) return -(int64_t)25;  /* -ENOTTY */
            if (!st->tty_init) { lucas_tty_termios_default(&st->cur_termios); st->tty_init = 1; }
            if (lucas_copy_to_client(st, arg, &st->cur_termios, sizeof(st->cur_termios)) != 0)
                return -(int64_t)LX_EFAULT;
            return 0;
        }
        case LX_TCSETS:
        case LX_TCSETSW:
        case LX_TCSETSF: {
            if (!fd_is_tty) return -(int64_t)25;  /* -ENOTTY */
            struct lx_termios in;
            if (lucas_copy_from_client(st, (uintptr_t)arg, &in, sizeof(in)) != 0)
                return -(int64_t)LX_EFAULT;
            lucas_tty_termios_set(&st->cur_termios, &in);
            st->tty_init = 1;
            return 0;   /* round-trips now: a follow-up TCGETS returns these flags */
        }
        case LX_TIOCGWINSZ: {
            if (!fd_is_tty) return -(int64_t)25;  /* -ENOTTY */
            if (st->ws.ws_row == 0 || st->ws.ws_col == 0) {
                st->ws.ws_row = 24; st->ws.ws_col = 80;   /* default until a pty-req sets it */
            }
            if (lucas_copy_to_client(st, arg, &st->ws, sizeof(st->ws)) != 0)
                return -(int64_t)LX_EFAULT;
            return 0;
        }
        case LX_TIOCSWINSZ: {
            if (!fd_is_tty) return -(int64_t)25;  /* -ENOTTY */
            struct lx_winsize in;
            if (lucas_copy_from_client(st, (uintptr_t)arg, &in, sizeof(in)) != 0)
                return -(int64_t)LX_EFAULT;
            if (in.ws_row && in.ws_col) st->ws = in;
            return 0;
        }
        case LX_TIOCGPGRP: {
            if (!fd_is_tty) return -(int64_t)25;  /* -ENOTTY */
            /* MUST return the SAME value as getpgrp() — busybox ash's
             * setjobctl spins `while (tcgetpgrp(tty) != getpgrp()) killpg(SIGTTIN)`
             * to become the foreground pgrp.  Returning synthetic_pid here while
             * getpgrp() returns display_pid (anti-fingerprint) made the two
             * never match → an infinite job-control loop that hung the
             * interactive shell before it ever printed a prompt.  Reuse the
             * exact getpgrp path so they always agree. */
            int64_t pg = lucas_sys_getpgrp(st, 0, 0, 0, 0, 0, 0);
            int32_t pgrp = (int32_t)(pg < 0 ? st->synthetic_pid : pg);
            if (lucas_copy_to_client(st, arg, &pgrp, sizeof(pgrp)) != 0)
                return -(int64_t)LX_EFAULT;
            return 0;
        }
        case LX_TIOCSPGRP:
            if (!fd_is_tty) return -(int64_t)25;  /* -ENOTTY */
            /* Just accept the new pgrp · no-op. */
            return 0;
        case LX_FIONREAD: {
            uint32_t avail = 0;
            /* On a socket fd, report the byte count of the first pending RX
             * datagram (matching the connected peer).  glibc's parallel-A/AAAA
             * resolver calls ioctl(FIONREAD) to size its on-demand answer
             * buffer BEFORE recvfrom; a flat 0 left the AAAA buffer 0-length so
             * the answer was read into nothing and lost (DNS never completed).
             * Mirrors the source filter recvfrom uses on connected UDP. */
            if (fd < LUCAS_MAX_FDS && st->fds[fd].kind == LUCAS_FD_SOCKET) {
                extern int sotnet_recv_peek_len(uint32_t pid, uint32_t want_ip_be);
                int n = sotnet_recv_peek_len((uint32_t)st->synthetic_pid,
                                             st->fds[fd].connect_peer_ip_be);
                if (n > 0) avail = (uint32_t)n;
            }
            if (lucas_copy_to_client(st, arg, &avail, sizeof(avail)) != 0)
                return -(int64_t)LX_EFAULT;
            return 0;
        }
        case LX_FIONBIO: {
            /* N-MISC-SYS · FIONBIO(*int) toggles non-blocking mode on the
             * fd.  Mirror the per-fd flag that fcntl(F_SETFL, O_NONBLOCK)
             * already manipulates so that Python's socket / selectors
             * paths see consistent state regardless of which ABI surface
             * they use.  Linux value: O_NONBLOCK == 04000 (octal). */
            #define LX_O_NONBLOCK_LOCAL 04000
            if (fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
            lucas_fd_t *e = &st->fds[fd];
            if (e->kind == LUCAS_FD_INVALID && !e->is_std)
                return -(int64_t)LX_EBADF;
            if (arg == 0) return -(int64_t)LX_EFAULT;
            uint32_t on = 0;
            if (lucas_copy_from_client(st, (uintptr_t)arg,
                                         &on, sizeof(on)) != 0)
                return -(int64_t)LX_EFAULT;
            if (on)
                e->flags |= LX_O_NONBLOCK_LOCAL;
            else
                e->flags &= ~LX_O_NONBLOCK_LOCAL;
            return 0;
        }
        default:
            return -(int64_t)25;  /* -ENOTTY */
    }
}

int64_t lucas_sys_rt_sigaction(lucas_state_t *st, uint64_t sig, uint64_t act,
                                uint64_t oact, uint64_t sigsetsize,
                                uint64_t _a4, uint64_t _a5) {
    (void)_a4; (void)_a5;
    /* Defined in signals.c · function-local extern keeps the include out
     * of file scope per worker-brief constraints. */
    extern int64_t lucas_signals_rt_sigaction(lucas_state_t *st, int sig,
                                               uint64_t act_uptr,
                                               uint64_t oact_uptr,
                                               size_t sigsetsize);
    return lucas_signals_rt_sigaction(st, (int)sig, act, oact,
                                       (size_t)sigsetsize);
}

int64_t lucas_sys_rt_sigprocmask(lucas_state_t *st, uint64_t how, uint64_t set,
                                  uint64_t oset, uint64_t sigsetsize,
                                  uint64_t _a4, uint64_t _a5) {
    (void)_a4; (void)_a5;
    extern int64_t lucas_signals_rt_sigprocmask(lucas_state_t *st, int how,
                                                 uint64_t set_uptr,
                                                 uint64_t oset_uptr,
                                                 size_t sigsetsize);
    return lucas_signals_rt_sigprocmask(st, (int)how, set, oset,
                                         (size_t)sigsetsize);
}

int64_t lucas_sys_sigaltstack(lucas_state_t *st, uint64_t ss, uint64_t oss,
                               uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    extern int64_t lucas_signals_sigaltstack(lucas_state_t *st,
                                              uint64_t ss_uptr,
                                              uint64_t oss_uptr);
    return lucas_signals_sigaltstack(st, ss, oss);
}

int64_t lucas_sys_set_tid_address(lucas_state_t *st, uint64_t tidptr,
                                   uint64_t _a1, uint64_t _a2, uint64_t _a3,
                                   uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* POST-L9-BUDGET diagnostic: count invocations so we can disambiguate
     * a true spin-loop (many calls, growing counter, no FS progress) from
     * a slow-init/silent hang (single call, then no further activity).
     * The static counter is per-process · which is exactly the scope we
     * want for the per-thread set_tid_address ABI.  No-op when
     * CONFIG_LUCAS_FS_TRACE is undefined. */
    static unsigned int set_tid_calls = 0;
    set_tid_calls++;
    /* L8-set_tid · Linux semantics: store tidptr in TCB.clear_child_tid
     * and return the calling thread's TID.  The handler has no other
     * side effects · Python's musl __init_tp uses the return value to
     * populate `td->tid` and continues the init path on a positive int.
     * Returning synthetic_pid (always >= 1) keeps that invariant intact. */
    if (st->synthetic_pid == 0) st->synthetic_pid = 1;
    st->clear_child_tid = tidptr;
    int64_t ret = (int64_t)st->synthetic_pid;
    LUCAS_FS_TRACE("set_tid n=%u tidptr=0x%lx -> %ld",
                   set_tid_calls, (unsigned long)tidptr, (long)ret);
    return ret;
}

struct lx_rlimit { uint64_t rlim_cur, rlim_max; };
struct lx_sysinfo {
    int64_t  uptime;
    uint64_t loads[3];
    uint64_t totalram, freeram, sharedram, bufferram;
    uint64_t totalswap, freeswap;
    uint16_t procs;
    char     pad0[6];
    uint64_t totalhigh, freehigh;
    uint32_t mem_unit;
    char     pad1[4];
};

int64_t lucas_sys_prlimit64(lucas_state_t *st, uint64_t pid, uint64_t resource,
                             uint64_t new_lim, uint64_t old_lim,
                             uint64_t _a4, uint64_t _a5) {
    (void)pid; (void)new_lim; (void)_a4; (void)_a5;
    if (!old_lim) return 0;
    struct lx_rlimit r = { ~0UL, ~0UL };
    switch (resource) {
        case 0: r.rlim_cur = 0; break;                                  /* RLIMIT_CPU */
        case 3: r.rlim_cur = 8 * 1024 * 1024; break;                    /* RLIMIT_STACK */
        case 4: r.rlim_cur = 0; break;                                   /* RLIMIT_CORE */
        case 7: r.rlim_cur = 524288; r.rlim_max = 524288; break;        /* RLIMIT_NOFILE · match Alpine 3.20 default */
        default: break;
    }
    return lucas_copy_to_client(st, old_lim, &r, sizeof(r))
            ? -(int64_t)LX_EFAULT : 0;
}

int64_t lucas_sys_getrlimit(lucas_state_t *st, uint64_t resource, uint64_t rlim,
                             uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    return lucas_sys_prlimit64(st, 0, resource, 0, rlim, _a4, _a5);
}

/* setitimer/getitimer · no-op.  busybox wget arms an ITIMER_REAL alarm around
 * the openssl s_client helper as a watchdog; we never deliver SIGALRM (the
 * guest read paths have their own poll budgets, so no real timer is needed).
 * Accept the call and clear *old_value so callers that read it see "disarmed". */
int64_t lucas_sys_setitimer(lucas_state_t *st, uint64_t which, uint64_t new_val,
                             uint64_t old_val, uint64_t _a3,
                             uint64_t _a4, uint64_t _a5) {
    (void)which; (void)new_val; (void)_a3; (void)_a4; (void)_a5;
    if (old_val) {
        struct lx_itimerval { int64_t it_iv_s, it_iv_us, it_v_s, it_v_us; } z = { 0, 0, 0, 0 };
        if (lucas_copy_to_client(st, old_val, &z, sizeof(z))) return -(int64_t)LX_EFAULT;
    }
    return 0;
}

int64_t lucas_sys_getitimer(lucas_state_t *st, uint64_t which, uint64_t cur_val,
                             uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)which; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (cur_val) {
        struct lx_itimerval { int64_t it_iv_s, it_iv_us, it_v_s, it_v_us; } z = { 0, 0, 0, 0 };
        if (lucas_copy_to_client(st, cur_val, &z, sizeof(z))) return -(int64_t)LX_EFAULT;
    }
    return 0;
}

int64_t lucas_sys_sysinfo(lucas_state_t *st, uint64_t info_vaddr,
                           uint64_t _a1, uint64_t _a2, uint64_t _a3,
                           uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    struct lx_sysinfo si = { 0 };
    si.uptime    = 3600;
    si.totalram  = 2ULL * 1024 * 1024 * 1024;
    si.freeram   = 1ULL * 1024 * 1024 * 1024;
    si.procs     = 16;
    si.mem_unit  = 1;
    return lucas_copy_to_client(st, info_vaddr, &si, sizeof(si))
            ? -(int64_t)LX_EFAULT : 0;
}

/* === L3a-T9 / L3b-T2: fork / clone / wait4 ============================== */

extern int64_t sotbox_fork(lucas_state_t *parent);
extern int     sotbox_reap(int pid_want, int *out_exit);
extern bool    sotbox_has_children(int caller_slot);

int64_t lucas_sys_fork(lucas_state_t *st,
                       uint64_t _0, uint64_t _1, uint64_t _2,
                       uint64_t _3, uint64_t _4, uint64_t _5) {
    (void)_0; (void)_1; (void)_2; (void)_3; (void)_4; (void)_5;
    if (++st->fork_attempts > SOTBOX_FORK_QUOTA)
        return lucas_antidos_quarantine(st);
    printf("[lucas] fork()\n");
    return sotbox_fork(st);
}

/* x86-64 raw clone ABI: clone(flags, stack, parent_tid, child_tid, tls)
 * = (rdi, rsi, rdx, r10, r8).  The dispatcher passes args positionally as
 * (a0..a5) = (rdi, rsi, rdx, r10, r8, r9), so the 4th handler arg is r10
 * (child_tid = ctid) and the 5th is r8 (tls).  These were previously NAMED
 * the other way round (tls, ctid), so CLONE_SETTLS handed the child_tid
 * POINTER to seL4_TCB_SetTLSBase instead of the real TLS base → the child's
 * %fs:0 self-pointer was bogus → the first TLS-relative access (e.g.
 * pthread_setcanceltype reading %fs:0 then [self+0x41]) faulted on a
 * near-NULL address.  Latent until Chocolate Doom: doomgeneric/doomsdl never
 * open audio so never spawn a pthread; Chocolate's sound thread is the first. */
int64_t lucas_sys_clone(lucas_state_t *st, uint64_t flags, uint64_t newsp,
                        uint64_t ptid, uint64_t ctid, uint64_t tls,
                        uint64_t _5) {
    /* L11-α-3 · log threading flags for visibility.  Python uses
     * CLONE_VM | CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD
     * | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID |
     * CLONE_CHILD_CLEARTID = 0x3d0f00.  Detect and log.
     *
     * PR 14 · LX_CLONE_* values come from lucas/syscalls.h (canonical
     * source shared with procd) instead of local #defines so the bit
     * positions stay in lockstep across the ABI. */

    int is_thread_create = (flags & LX_CLONE_VM) && (flags & LX_CLONE_THREAD);
    /* WINE-M1 · TRUE vfork: CLONE_VM | CLONE_VFORK without CLONE_THREAD is what
     * glibc's posix_spawn / vfork-based exec helper uses (wine starts wineserver
     * this way · flags 0x4111 = CLONE_VM|CLONE_VFORK|SIGCHLD).  The child must
     * SHARE the parent's live address space (not a copy-fork snapshot) and the
     * parent must block until the child execs/exits — see sotbox_vfork(). */
    int is_vfork = (flags & LX_CLONE_VM) && (flags & LX_CLONE_VFORK)
                   && !(flags & LX_CLONE_THREAD);
    printf("[clone] pid=%d flags=0x%lx %s%s%s%s%s%s%s%s%s· %s\n",
           st->synthetic_pid, (unsigned long)flags,
           (flags & LX_CLONE_VM)             ? "VM "      : "",
           (flags & LX_CLONE_FS)             ? "FS "      : "",
           (flags & LX_CLONE_FILES)          ? "FILES "   : "",
           (flags & LX_CLONE_SIGHAND)        ? "SIGHAND " : "",
           (flags & LX_CLONE_THREAD)         ? "THREAD "  : "",
           (flags & LX_CLONE_SETTLS)         ? "SETTLS "  : "",
           (flags & LX_CLONE_PARENT)         ? "PARENT "  : "",
           (flags & LX_CLONE_VFORK)          ? "VFORK "   : "",
           (flags & LX_CLONE_PIDFD)          ? "PIDFD "   : "",
           is_thread_create
               ? "POSIX-thread-create · real-TCB shared-vspace path (U2)"
               : "(treating as fork)");

    (void)_5;

    if (is_thread_create) {
        /* U2 · real threading: allocate a fresh TCB sharing parent's
         * vspace + cnode.  Helper is in threading.c · extern in-body to
         * comply with U2's no-file-scope-additions constraint.
         *
         * PR 13 · pass ctid (child_tid_ptr) through so the helper can
         * stash it in thread_list[slot].clear_tid_ptr for the per-thread
         * exit path's futex(addr, 1) wake (joiners block on this
         * address inside pthread_join). */
        (void)ptid;  /* thread-path: parent_tid_ptr handled by glibc-side
                       PARENT_SETTID flag which we honour for fork-like
                       below; the thread path doesn't write back. */
        extern int64_t lucas_thread_clone(lucas_state_t *, uint64_t newsp,
                                          uint64_t tls, uint64_t flags,
                                          uint64_t ctid);
        return lucas_thread_clone(st, newsp, tls, flags, ctid);
    }

    if (is_vfork) {
        /* WINE-M1 · share-vspace child + park the parent (deferred reply).
         * Counted toward the fork-bomb quota like any fork-like clone. */
        (void)ptid; (void)tls; (void)ctid;
        if (++st->fork_attempts > SOTBOX_FORK_QUOTA)
            return lucas_antidos_quarantine(st);
        extern int64_t sotbox_vfork(lucas_state_t *parent, uint64_t newsp);
        printf("[clone] pid=%d · routing to TRUE vfork (CLONE_VM|CLONE_VFORK)\n",
               st->synthetic_pid);
        return sotbox_vfork(st, newsp);
    }

    /* L3a: ignore clone-specific flags · treat as plain fork.
     *
     * PR 14 · honour CLONE_PARENT_SETTID and CLONE_PIDFD on the
     * fork-like path · both write a uint32_t into the caller's
     * parent_tid_ptr (Linux ABI · the ptr serves double duty).  We do
     * the fork first so we have a child pid to report, then write back
     * to the parent's vspace before returning.
     *
     * CLONE_PIDFD scope reduction · we don't allocate a real
     * "pidfd" object (procd has no per-sotbox fd table accessible
     * from procd's vspace today).  Instead we write the child's
     * synthetic_pid into parent_tid_ptr · operator-visible note logged so
     * a future PR landing real pidfd_open() can stop fudging this. */
    (void)newsp; (void)tls;
    /* P2b · count a fork-like clone toward the fork-bomb quota (a real pthread
     * thread-create — CLONE_VM|CLONE_THREAD — is handled above and NOT counted). */
    if (++st->fork_attempts > SOTBOX_FORK_QUOTA)
        return lucas_antidos_quarantine(st);
    printf("[clone] forwarding to fork (no CLONE_THREAD)\n");
    int64_t child_pid = sotbox_fork(st);

    if (child_pid > 0 && ptid != 0) {
        if (flags & LX_CLONE_PARENT_SETTID) {
            uint32_t pid32 = (uint32_t)child_pid;
            if (lucas_copy_to_client(st, (uintptr_t)ptid,
                                       &pid32, sizeof(pid32)) != 0) {
                printf("[clone] CLONE_PARENT_SETTID · copy_to_client failed "
                       "(ptid=0x%lx child=%ld)\n",
                       (unsigned long)ptid, (long)child_pid);
            } else {
                printf("[clone] CLONE_PARENT_SETTID · wrote child_pid=%u to "
                       "ptid=0x%lx\n", pid32, (unsigned long)ptid);
            }
        }
        if (flags & LX_CLONE_PIDFD) {
            /* PR 14 scope reduction · no real pidfd object today.  We
             * stash the child's synthetic_pid in ptid so the caller can
             * still address the child via the existing kill / waitpid
             * surfaces.  A future PR adding a real per-sotbox fd table
             * accessible across vspaces can replace this with a true
             * pidfd. */
            uint32_t pidfd_placeholder = (uint32_t)child_pid;
            if (lucas_copy_to_client(st, (uintptr_t)ptid,
                                       &pidfd_placeholder,
                                       sizeof(pidfd_placeholder)) != 0) {
                printf("[clone] CLONE_PIDFD recorded · copy_to_client failed\n");
            } else {
                printf("[clone] CLONE_PIDFD recorded · fd allocation deferred · "
                       "placeholder=%u at ptid=0x%lx\n",
                       pidfd_placeholder, (unsigned long)ptid);
            }
        }
    }
    return child_pid;
}

/*
 * L3b-T2: blocking wait4 via SaveCaller + async reply.
 *
 * Quick path: zombie already in the reap table → return immediately.
 * Slow path:  allocate a fresh cslot, SaveCaller into it, park the
 *             sotBox in WAITING_FOR_CHILD state, return the anomaly
 *             LUCAS_WAIT4_DEFERRED.  orch_fault_loop sees the anomaly
 *             and skips seL4_Reply; when the child exits,
 *             sotbox_try_wakeup_waiter sends to the saved reply cap.
 */
int64_t lucas_sys_wait4(lucas_state_t *st, uint64_t pid, uint64_t status_vaddr,
                        uint64_t options, uint64_t rusage,
                        uint64_t _4, uint64_t _5) {
    (void)rusage; (void)_4; (void)_5;

    /* F_proc · if pid > 0 names a synth child, return 0 immediately even
     * without WNOHANG (no real zombie will ever materialize).  BUT a canary-shell
     * real-fork child (e.g. dpkg-deb's decompressor/tar over SSH) is announced to
     * procd as FPROC_SYNTH_FORK yet runs for REAL — for it the shortcut must NOT
     * fire (it made dpkg-deb's blocking waitpid(tar) return 0 → "wait for tar
     * subprocess failed: Success" → abort, even though the extraction completed).
     * Skip the shortcut when a live TCB backs the pid; fall through to the real
     * blocking wait/reap. */
    if ((int64_t)pid > 0) {
        extern int sotbox_pid_has_real_tcb(int synthetic_pid);
        lucas_proc_view_t target_view;
        if (lucas_proct_find_synthetic_pid((uint32_t)pid, &target_view) == 0 &&
            target_view.functor_proc == FPROC_SYNTH_FORK &&
            !sotbox_pid_has_real_tcb((int)pid)) {
            printf("[lucas] wait4(pid=%d) synth child · returning 0 (no real zombie)\n",
                   (int)pid);
            return 0;
        }
    }

    /* Quick path: zombie already reaped.  Pass our OWN synthetic_pid so we can
     * only reap our OWN direct children — a grandparent's wait4(-1) must not
     * steal a grandchild's zombie (Linux semantics; the apt-get update hang). */
    extern int sotbox_reap_p(int pid_want, int caller_pid, int *out_exit);
    int exit_code = 0;
    int reaped = sotbox_reap_p((int)(int64_t)pid, st->synthetic_pid, &exit_code);
    if (reaped >= 0) {
        /* Fork-bomb accounting: reaping a child cancels one outstanding fork, so
         * fork_attempts tracks LIVE un-reaped children, not lifetime forks.  A
         * normal interactive shell (fork→exec→exit→reap per command) stays near 0
         * and never trips the quota; a real fork bomb (children never reaped, they
         * keep forking) climbs past it.  Without this, ANY session that runs >16
         * commands was SIGKILL'd as a "fork bomb" (a usability + deception tell). */
        if (st->fork_attempts > 0) st->fork_attempts--;
        int wstatus = (exit_code & 0xff) << 8;
        if (status_vaddr) {
            if (lucas_copy_to_client(st, status_vaddr, &wstatus, sizeof(wstatus)) != 0)
                return -(int64_t)LX_EFAULT;
        }
        printf("[lucas] wait4(pid=%d): reaped pid=%d exit_code=%d (immediate)\n",
               (int)(int64_t)pid, reaped, exit_code);
        /* PR 6/7 · shadow-announce the wait to procd so procd flips the
         * zombie slot to DEAD and publishes PROC_REAPED.  The legacy
         * sotbox_reap above already produced the wait4 return value ·
         * procd's reply is informational (procd may report -ECHILD
         * because the zombie wasn't shadow-announced via OP_EXIT yet,
         * which is fine · the announce path is best-effort).  PR 7
         * dropped the PROCD_TAKEOVER_SPAWN gate · announce is now
         * unconditional. */
        if (st->procd_slot != 0) {
            extern int orch_procd_wait(uint32_t caller_slot, int32_t which,
                                        int32_t options_, int32_t *out_pid,
                                        int32_t *out_status);
            int32_t  out_pid = 0, out_status = 0;
            int pd_rc = orch_procd_wait(st->procd_slot,
                                         (int32_t)(int64_t)pid,
                                         (int32_t)options,
                                         &out_pid, &out_status);
            if (pd_rc >= 0) {
                printf("[lucas] procd OP_WAIT reaped slot=%u pd_pid=%d status=%d\n",
                       st->procd_slot, out_pid, out_status);
            } else {
                /* PR 7 code-review carry-over · log the failure side for
                 * symmetry with the success path above.  The local result
                 * (`reaped` / `exit_code`) is already authoritative · this
                 * trace makes the announce-failed case operator-visible
                 * instead of silently hidden behind the >=0 branch. */
                printf("[lucas] procd OP_WAIT announce failed rc=%d · using local result\n",
                       pd_rc);
            }
        }
        return (int64_t)reaped;
    }

    /* If there are no living children and no zombies, return -ECHILD immediately.
     * sotbox_has_children checks the slot table (skip caller's own slot) and
     * the zombie table.  Without this, sh would park forever after reaping all
     * children since there's no one left to wake it. */
    if (!sotbox_has_children(st->slot_index)) {
        printf("[lucas] wait4(pid=%d): no children · -ECHILD\n", (int)(int64_t)pid);
        return -(int64_t)10;  /* -ECHILD */
    }

    /* PR 11 · WNOHANG (options & 1) · return 0 immediately instead of
     * parking the caller.  Necessary for synth-fork demos where the
     * "child" never produces a real exit (no TCB · silenced slot in procd
     * only).  Linux semantics: wait4 returns 0 when WNOHANG is set and
     * no zombie is reapable.  Pre-PR-11 lucas ignored options entirely;
     * the only known caller relying on WNOHANG before this PR was the
     * simulated_attacker Stage 6 fork, which only exists in PR 11+. */
#define LX_WNOHANG 0x00000001ull
    if (options & LX_WNOHANG) {
        printf("[lucas] wait4(pid=%d) WNOHANG · no zombie ready · returning 0\n",
               (int)(int64_t)pid);
        return 0;
    }

    /* Slow path: no zombie but children still alive · SaveCaller + park. */
    seL4_CPtr cslot;
    int err = vka_cspace_alloc(st->vka, &cslot);
    if (err) {
        printf("[lucas] wait4: vka_cspace_alloc failed (err=%d)\n", err);
        return -(int64_t)11;  /* -EAGAIN */
    }
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        printf("[lucas] wait4: SaveCaller failed (err=%d)\n", err);
        vka_cspace_free(st->vka, cslot);
        return -(int64_t)11;
    }

    st->waiting_reply_cap    = cslot;
    st->waiting_for_pid      = (int)(int64_t)pid;
    st->waiting_status_vaddr = status_vaddr;
    st->state                = SOTBOX_STATE_WAITING_FOR_CHILD;

    printf("[lucas] wait4 PARKED · pid=%d (slot=%d) waiting_for=%d cslot=%lu\n",
           st->synthetic_pid, st->slot_index, (int)(int64_t)pid, (unsigned long)cslot);

    /* Signal orch_fault_loop: do NOT call seL4_Reply. */
    return LUCAS_WAIT4_DEFERRED;
}

/* === L3b-T6: process-group / session / getppid stubs ==================== */

int64_t lucas_sys_getppid(lucas_state_t *st,
                           uint64_t _a0, uint64_t _a1, uint64_t _a2,
                           uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    lucas_proc_view_t view;
    if (lucas_proct_load(st->procd_slot, &view) == 0 &&
        view.valid && view.ppid != 0) {
        printf("[lucas] getppid -> %u (via procd)\n", view.ppid);
        return (int64_t)view.ppid;
    }
    /* Fallback · report parent as init (pid 1). */
    return 1;
}

/* P3 · ptrace stub for anti-debug fidelity.  Pre-state was -ENOSYS, itself an
 * anomaly a debugger-detection probe can flag.  A clean, untraced Linux
 * process calling ptrace(PTRACE_TRACEME=0) gets 0; any other request we do
 * not implement returns -1.  No real tracing occurs. */
int64_t lucas_sys_ptrace(lucas_state_t *st,
                          uint64_t request, uint64_t pid, uint64_t addr,
                          uint64_t data, uint64_t a4, uint64_t a5) {
    (void)st; (void)pid; (void)addr; (void)data; (void)a4; (void)a5;
    return request == 0 /*PTRACE_TRACEME*/ ? 0 : -1;
}

/* PR 9 · setsid / setpgid / getpgid / getpgrp · route through procd so
 * the proc_t.sid / .pgid fields stay in sync across the audit + anomaly
 * views.  When procd_slot == 0 (announce failed at spawn, or feature
 * gate disabled) we keep the legacy stub semantics so the smoke + demo
 * stay green.  See src/procd/handlers_lifecycle.c for the procd-side
 * Linux-semantics rules (EPERM on duplicate setsid, target_pid==0 = self,
 * etc.). */
int64_t lucas_sys_getpgrp(lucas_state_t *st,
                           uint64_t _a0, uint64_t _a1, uint64_t _a2,
                           uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (st->procd_slot != 0) {
        extern int orch_procd_getpgid(uint32_t caller_slot,
                                       uint32_t target_pid,
                                       uint32_t *out_pgid);
        uint32_t pgid = 0;
        int pd_rc = orch_procd_getpgid(st->procd_slot, 0, &pgid);
        if (pd_rc < 0) {
            printf("[lucas] procd OP_GETPGID(getpgrp) announce failed rc=%d\n",
                   pd_rc);
            return (int64_t)pd_rc;
        }
        return (int64_t)pgid;
    }
    /* OBSD-ζ · process-group id mirrors the randomized display_pid so
     * anti-fingerprinting is consistent across all pid-returning calls. */
    if (st->display_pid == 0) st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid); /* C2 #10 */
    return (int64_t)st->display_pid;
}

int64_t lucas_sys_setpgid(lucas_state_t *st,
                           uint64_t pid, uint64_t pgid,
                           uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    uint32_t target_pid = (uint32_t)pid;
    uint32_t new_pgid   = (uint32_t)pgid;
    if (st->procd_slot != 0) {
        extern int orch_procd_setpgid(uint32_t caller_slot,
                                       uint32_t target_pid_,
                                       uint32_t new_pgid_);
        int pd_rc = orch_procd_setpgid(st->procd_slot, target_pid, new_pgid);
        /* Tolerate "target not found": GNU bash's job control calls
         * setpgid(child,child) right after fork, but a fast/transient child can
         * exit before procd registers it → ESRCH, which makes bash print a noisy
         * "child setpgid: No such process" tell on every external command.  We do
         * not enforce process groups for the honey shell, so report success. */
        if (pd_rc < 0) return 0;
        return (int64_t)pd_rc;
    }
    /* No-op: L3b has a single process group. */
    return 0;
}

int64_t lucas_sys_getpgid(lucas_state_t *st,
                           uint64_t pid,
                           uint64_t _a1, uint64_t _a2, uint64_t _a3,
                           uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    uint32_t target_pid = (uint32_t)pid;
    if (st->procd_slot != 0) {
        extern int orch_procd_getpgid(uint32_t caller_slot,
                                       uint32_t target_pid_,
                                       uint32_t *out_pgid);
        uint32_t pgid = 0;
        int pd_rc = orch_procd_getpgid(st->procd_slot, target_pid, &pgid);
        if (pd_rc < 0) return (int64_t)pd_rc;
        return (int64_t)pgid;
    }
    /* OBSD-ζ · anti-fingerprinting: return randomized display_pid. */
    if (st->display_pid == 0) st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid); /* C2 #10 */
    return (int64_t)st->display_pid;
}

int64_t lucas_sys_setsid(lucas_state_t *st,
                          uint64_t _a0, uint64_t _a1, uint64_t _a2,
                          uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (st->procd_slot != 0) {
        extern int orch_procd_setsid(uint32_t caller_slot, uint32_t *out_sid);
        uint32_t sid = 0;
        int pd_rc = orch_procd_setsid(st->procd_slot, &sid);
        if (pd_rc < 0) {
            /* -1 (Linux EPERM) is expected when the caller is already a
             * pgrp leader · forward unchanged.  Other negatives are
             * announce failures · log for operator visibility. */
            if (pd_rc != -1) {
                printf("[lucas] procd OP_SETSID announce failed rc=%d\n", pd_rc);
            }
            return (int64_t)pd_rc;
        }
        return (int64_t)sid;
    }
    /* OBSD-ζ · anti-fingerprinting: return randomized display_pid. */
    if (st->display_pid == 0) st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid); /* C2 #10 */
    return (int64_t)st->display_pid;
}

int64_t lucas_sys_getsid(lucas_state_t *st,
                          uint64_t pid,
                          uint64_t _a1, uint64_t _a2, uint64_t _a3,
                          uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    lucas_proc_view_t view;
    int ok;
    if (pid == 0) {
        ok = (lucas_procd_view_load(st->procd_slot, &view) == 0);
    } else {
        ok = (lucas_procd_view_by_synthetic_pid((uint32_t)pid, &view) == 0);
    }
    if (ok && view.valid && view.sid != 0) return (int64_t)view.sid;

    /* Fallback · OBSD-ζ anti-fingerprinting: return randomized display_pid. */
    if (st->display_pid == 0) st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid); /* C2 #10 */
    return (int64_t)st->display_pid;
}

/* chdir / fchdir stubs: pretend we're always at "/". */
extern int lucas_copy_cstr_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                       char *out, size_t cap);

int64_t lucas_sys_chdir(lucas_state_t *st,
                         uint64_t path_vaddr,
                         uint64_t _a1, uint64_t _a2, uint64_t _a3,
                         uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Fidelity · resolve + validate the target dir against the VFS and store it
     * as the per-sotbox cwd so `cd X; ls`/relative paths behave like a real FS. */
    char raw[LUCAS_PATH_MAX];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)path_vaddr, raw, sizeof(raw)) < 0)
        return -(int64_t)LX_EFAULT;
    return lucas_chdir_resolve(st, raw);
}

int64_t lucas_sys_fchdir(lucas_state_t *st,
                          uint64_t fd,
                          uint64_t _a1, uint64_t _a2, uint64_t _a3,
                          uint64_t _a4, uint64_t _a5) {
    (void)st; (void)fd; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    return 0;
}

/* getcwd: always return "/" to the client. */
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *src_buf, size_t size);
int64_t lucas_sys_getcwd(lucas_state_t *st,
                          uint64_t buf_vaddr, uint64_t size,
                          uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    const char *cwd = (st->cwd[0]) ? st->cwd : "/";   /* fidelity · real per-sotbox cwd */
    size_t len = 0; while (cwd[len]) len++; len++;     /* include NUL */
    if ((uint64_t)len > size) return -(int64_t)LX_EINVAL;
    if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, cwd, len) != 0)
        return -(int64_t)LX_EFAULT;
    /* The Linux getcwd(2) SYSCALL returns the LENGTH written (incl. NUL), NOT the
     * buffer pointer — that's the glibc/musl WRAPPER's return.  musl tolerated the
     * pointer (it only checks ret>=0 then returns buf), but glibc uses the returned
     * length and a huge pointer value made it distrust the result → the manual
     * getcwd fallback failed ("cannot access parent directories").  Return len. */
    return (int64_t)len;
}

/* nanosleep stub: return 0 immediately (no real sleep). */
int64_t lucas_sys_nanosleep(lucas_state_t *st,
                              uint64_t req, uint64_t rem,
                              uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)st; (void)req; (void)rem; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    return 0;
}

/* set_robust_list: pthread thread init publishes its robust-futex list head.
 *
 * PR 13 · we now ALSO:
 *   1. Stash head into thread_list[i].robust_list_head for the most likely
 *      calling thread (the most recently spawned worker that hasn't yet
 *      published a robust head), so the per-thread exit path can walk
 *      this list and mark owned mutexes FUTEX_OWNER_DIED.  Falls back to
 *      st->robust_list_head when no thread slot is a plausible match
 *      (main thread case).
 *   2. Shadow-announce to procd via OP_SET_ROBUST so procd's thread_t
 *      entry tracks the same head pointer · operator sees the
 *      `[procd] set_robust tid=N head=0x..` line at every pthread init.
 *
 * Lucas single-vCPU model means we can't reliably tell which thread issued
 * the syscall from the badge alone (all threads share the parent badge in
 * the shared fault EP); the "most-recent-with-empty-head" heuristic is
 * deliberate scope reduction · pthread init's set_robust_list happens
 * immediately after the clone returns, so the heuristic matches in
 * practice.  If main calls set_robust_list (glibc's first thread), there
 * are no thread_list slots yet and we fall back to st->robust_list_head +
 * tid=0 (procd's "main thread" anomaly). */
int64_t lucas_sys_set_robust_list(lucas_state_t *st,
                                    uint64_t head, uint64_t len,
                                    uint64_t _a2, uint64_t _a3,
                                    uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    /* Find the most-recent thread slot that has no robust head yet ·
     * that's the most likely caller.  Scan in reverse so newer threads
     * win over older ones if both happen to be empty. */
    uint32_t pd_tid = 0;
    int target_idx = -1;
    for (int i = 7; i >= 0; --i) {
        if (st->thread_list[i].tcb != 0 &&
            st->thread_list[i].robust_list_head == 0) {
            target_idx = i;
            pd_tid     = st->thread_list[i].procd_tid;
            break;
        }
    }
    if (target_idx >= 0) {
        st->thread_list[target_idx].robust_list_head = head;
    } else {
        /* Main thread or fallback · store on the legacy per-state slot. */
        st->robust_list_head = head;
        st->robust_list_len  = (size_t)len;
    }

    /* Shadow-announce to procd · best-effort.  pd_tid == 0 means "main
     * thread" · procd's handler can interpret 0 by falling back to the
     * proc's first thread_t entry (we keep the call so the smoke gate
     * fires even on the main-thread path). */
    if (st->procd_slot != 0) {
        extern int orch_procd_set_robust(uint32_t caller_slot, uint32_t tid,
                                           uint64_t robust_head);
        int pd_rc = orch_procd_set_robust(st->procd_slot, pd_tid, head);
        if (pd_rc < 0) {
            printf("[lucas] procd OP_SET_ROBUST announce failed rc=%d (tid=%u head=0x%lx)\n",
                   pd_rc, pd_tid, (unsigned long)head);
        }
    }
    printf("[lucas] set_robust_list head=0x%lx len=%lu local_tid=%d pd_tid=%u\n",
           (unsigned long)head, (unsigned long)len, target_idx, pd_tid);
    return 0;
}

/* getrandom (sysno 318): fill client buffer with CSPRNG bytes.
 * obsd-β: backed by sotos_arc4random_buf (ChaCha20).
 * flags (GRND_RANDOM / GRND_NONBLOCK) are ignored at L4 — all paths
 * return immediately with bytes from the arc4random pool.
 * count is capped at 4096 bytes per call to bound the stage buffer. */
int64_t lucas_sys_getrandom(lucas_state_t *st, uint64_t buf_vaddr,
                              uint64_t count, uint64_t flags,
                              uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)flags; (void)_a3; (void)_a4; (void)_a5;
    if (count == 0) return 0;
    if (count > 4096) count = 4096;
    /* Stack-allocated: avoids BSS bloat in the orch binary.
     * 4096 bytes on stack is safe: orch's fault-loop stack is 64 KiB. */
    uint8_t stage[4096];
    sotos_arc4random_buf(stage, (size_t)count);
    if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, stage, (size_t)count) != 0)
        return -(int64_t)LX_EFAULT;
    return (int64_t)count;
}

/* rseq: restartable sequences · U6 records the registration so glibc/musl
 * treat us as having opted-in.  We never actually fire the abort handler,
 * but musl's fallback path is gated by "rseq returned success" and that
 * is fine for now (single-threaded fast path is identical). */
int64_t lucas_sys_rseq(lucas_state_t *st,
                        uint64_t rseq_ptr, uint64_t rseq_len,
                        uint64_t flags, uint64_t sig,
                        uint64_t _a4, uint64_t _a5) {
    (void)rseq_len; (void)flags; (void)sig; (void)_a4; (void)_a5;
    st->rseq_addr       = rseq_ptr;
    st->rseq_registered = 1;
    return 0;
}

/* dup(oldfd): single-arg dup, creates a new fd referencing the same file. */
int64_t lucas_sys_dup(lucas_state_t *st, uint64_t oldfd,
                       uint64_t _a1, uint64_t _a2, uint64_t _a3,
                       uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (oldfd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *src = &st->fds[oldfd];
    if (src->kind == LUCAS_FD_INVALID && !src->is_std) return -(int64_t)LX_EBADF;

    /* Find the lowest unused fd >= 0. */
    int newfd = -1;
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID && !st->fds[i].is_std) {
            newfd = i;
            break;
        }
    }
    if (newfd < 0) return -(int64_t)24;  /* -EMFILE */

    /* Reuse dup2 logic (it handles the pipe refcount bump). */
    return lucas_sys_dup2(st, oldfd, (uint64_t)newfd, 0, 0, 0, 0);
}

/* === L2 additions: uid/gid + time syscalls ============================== */

/* Wine M1 · the wine loader chain (trusted, operator-run) must present a
 * COHERENT identity for its WINEPREFIX ownership check: wine compares
 * stat(prefix).st_uid against geteuid() and refuses ("'…' is not owned by you")
 * on mismatch.  The VFS reports files as uid 0, so the wine sotbox must see
 * euid 0.  Gated on exe_path containing "wine" so the attacker-facing identity
 * persona (uid 1000) is unchanged for every other sotbox.  Substring scan
 * (exe_path is a 128-byte NUL-terminated buffer; no strstr dependency). */
static int proc_exe_is_wine(const lucas_state_t *st) {
    const char *p = st->exe_path;
    for (; *p; ++p)
        if (p[0] == 'w' && p[1] == 'i' && p[2] == 'n' && p[3] == 'e') return 1;
    return 0;
}
int64_t lucas_sys_getuid(lucas_state_t *st,
                          uint64_t _a0, uint64_t _a1, uint64_t _a2,
                          uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Install-arc · a TRUSTED (operator/Tier-0) process IS the real system → root
     * (dpkg refuses non-root: "requires superuser privilege").  The attacker-
     * facing Tier-2 persona stays uid/gid 1000 (the honey shell is untrusted). */
    return (st->trusted || st->euid_root || proc_exe_is_wine(st)) ? 0 : 1000;  /* wine: root identity · else lucas (spec §8) */
}
int64_t lucas_sys_geteuid(lucas_state_t *st,
                           uint64_t _a0, uint64_t _a1, uint64_t _a2,
                           uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Install-arc · a TRUSTED (operator/Tier-0) process IS the real system → root
     * (dpkg refuses non-root: "requires superuser privilege").  The attacker-
     * facing Tier-2 persona stays uid/gid 1000 (the honey shell is untrusted). */
    return (st->trusted || st->euid_root || proc_exe_is_wine(st)) ? 0 : 1000;
}
int64_t lucas_sys_getgid(lucas_state_t *st,
                          uint64_t _a0, uint64_t _a1, uint64_t _a2,
                          uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Install-arc · a TRUSTED (operator/Tier-0) process IS the real system → root
     * (dpkg refuses non-root: "requires superuser privilege").  The attacker-
     * facing Tier-2 persona stays uid/gid 1000 (the honey shell is untrusted). */
    return (st->trusted || st->euid_root || proc_exe_is_wine(st)) ? 0 : 1000;
}
int64_t lucas_sys_getegid(lucas_state_t *st,
                           uint64_t _a0, uint64_t _a1, uint64_t _a2,
                           uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    /* Install-arc · a TRUSTED (operator/Tier-0) process IS the real system → root
     * (dpkg refuses non-root: "requires superuser privilege").  The attacker-
     * facing Tier-2 persona stays uid/gid 1000 (the honey shell is untrusted). */
    return (st->trusted || st->euid_root || proc_exe_is_wine(st)) ? 0 : 1000;
}
int64_t lucas_sys_setuid(lucas_state_t *st, uint64_t uid,
                          uint64_t _a1, uint64_t _a2, uint64_t _a3,
                          uint64_t _a4, uint64_t _a5) {
    (void)st; (void)uid; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    return 0;  /* claim success no-op · matches busybox expectation */
}
int64_t lucas_sys_setgid(lucas_state_t *st, uint64_t gid,
                          uint64_t _a1, uint64_t _a2, uint64_t _a3,
                          uint64_t _a4, uint64_t _a5) {
    (void)st; (void)gid; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    return 0;
}

/* Linux struct timespec / timeval for time syscalls. */
struct lx_timespec { int64_t tv_sec; int64_t tv_nsec; };
struct lx_timeval  { int64_t tv_sec; int64_t tv_usec; };

extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *src_buf, size_t size);

int64_t lucas_sys_gettimeofday(lucas_state_t *st, uint64_t tv_vaddr,
                                uint64_t tz_vaddr, uint64_t _a2, uint64_t _a3,
                                uint64_t _a4, uint64_t _a5) {
    (void)tz_vaddr; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (tv_vaddr) {
        int64_t sec, nsec;
        lucas_now_realtime(&sec, &nsec);
        struct lx_timeval tv = { sec, nsec / 1000 };  /* usec */
        if (lucas_copy_to_client(st, tv_vaddr, &tv, sizeof(tv)) != 0)
            return -(int64_t)LX_EFAULT;
    }
    return 0;
}

#define LX_CLOCK_MONOTONIC 1
int64_t lucas_sys_clock_gettime(lucas_state_t *st, uint64_t clockid,
                                 uint64_t tp_vaddr, uint64_t _a2, uint64_t _a3,
                                 uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (tp_vaddr) {
        int64_t sec, nsec;
        if ((int)clockid == LX_CLOCK_MONOTONIC) lucas_now_monotonic(&sec, &nsec);
        else                                    lucas_now_realtime(&sec, &nsec);
        struct lx_timespec tp = { sec, nsec };
        if (lucas_copy_to_client(st, tp_vaddr, &tp, sizeof(tp)) != 0)
            return -(int64_t)LX_EFAULT;
    }
    return 0;
}

/* === L3c-T3: kill / signal delivery ===================================== */

#define LX_SIGINT   2
#define LX_SIGKILL  9
#define LX_SIGTERM 15
#define LX_SIGPIPE 13
#define LX_SIGCHLD 17

int64_t lucas_sys_kill(lucas_state_t *st, uint64_t pid, uint64_t signo,
                       uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5) {
    (void)_2; (void)_3; (void)_4; (void)_5;

    /* F_proc · load caller's view to know if we're in SYNTH_FORK mode. */
    lucas_proc_view_t caller, target_view;
    int have_caller = (lucas_proct_load(st->procd_slot, &caller) == 0);

    /* Try to resolve target via procd's synthetic_pid table. */
    int have_target = (lucas_proct_find_synthetic_pid((uint32_t)pid, &target_view) == 0);

    if (have_target && target_view.functor_proc == FPROC_SYNTH_FORK) {
        /* Target is a synth child · pretend the signal landed. */
        printf("[lucas] kill(pid=%d, signo=%d) to synth slot · synthetic success rc=0\n",
               (int)pid, (int)signo);
        return 0;
    }

    if (!have_target && have_caller &&
        caller.functor_proc == FPROC_SYNTH_FORK &&
        pid >= 1 && pid <= 65535) {
        /* Hybrid lie · believable Linux pid range, no procd record.
         * Tier-2 sotbox sees any pid in [1, 65535] as alive. */
        printf("[lucas] kill(pid=%d, signo=%d) Tier-2 lie · synthetic success rc=0\n",
               (int)pid, (int)signo);
        return 0;
    }

    /* Fallback: existing slot-arithmetic path (preserve PR-baseline behavior).
     * Find the target sotBox by pid (= slot_index + 1). */
    if (pid == 0 || pid > 8) return -(int64_t)3;  /* -ESRCH */
    int slot = (int)pid - 1;
    lucas_state_t *target = sotbox_get_slot(slot);
    if (!target) return -(int64_t)3;
    if (target->exited) return 0;  /* zombie · accept the signal silently */

    printf("[lucas] kill(pid=%lu, signo=%lu) · target_slot=%d\n",
           (unsigned long)pid, (unsigned long)signo, slot);

    switch (signo) {
        case LX_SIGKILL:
        case LX_SIGTERM:
        case LX_SIGINT: {
            /* Default action: terminate. Suspend the TCB and mark
             * the sotBox as exited with code 128+signo. */
            seL4_TCB_Suspend(target->client_tcb);
            target->exited    = 1;
            target->exit_code = 128 + (int)signo;
            /* A suspended TCB never faults again, so the orch fault loop's
             * exit-reap path (result==1) is never reached for it — its arena
             * would LEAK.  Flag it for the loop's marked_for_teardown sweep,
             * which reaps suspended cells explicitly (sotbox_destroy → arena
             * revoked).  Without this, apt's speculative gpgv method (SIGINT'd
             * after trusted=yes makes verification unnecessary) leaked a heavy
             * arena per kill, exhausting the pool so the next method OOM'd. */
            target->marked_for_teardown = 1;
            {
                extern void sotbox_record_exit_p(int pid, int exit_code, int parent_pid);
                extern int  sotbox_try_wakeup_waiter_p(int exited_pid, int exit_code, int parent_pid);
                int ppid = (target->parent_slot >= 0) ? (target->parent_slot + 1) : 0;
                sotbox_record_exit_p(target->synthetic_pid, target->exit_code, ppid);
                /* If the genuine parent is waiting for this pid · wake it. */
                sotbox_try_wakeup_waiter_p(target->synthetic_pid, target->exit_code, ppid);
            }
            return 0;
        }
        case LX_SIGPIPE:
        case LX_SIGCHLD:
            /* SIGPIPE default: terminate. SIGCHLD default: ignore.
             * For L3c we just accept both · pipes already deliver
             * EPIPE return codes synchronously (T4 of L3b) so SIGPIPE
             * doesn't need to terminate. */
            return 0;
        default:
            /* Unknown signal · accept but ignore. */
            return 0;
    }
}

int64_t lucas_sys_tkill(lucas_state_t *st, uint64_t tid, uint64_t signo,
                        uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5) {
    /* In L3c we have no thread vs process distinction · alias to kill. */
    return lucas_sys_kill(st, tid, signo, 0, 0, 0, 0);
}

int64_t lucas_sys_tgkill(lucas_state_t *st, uint64_t tgid, uint64_t tid, uint64_t signo,
                         uint64_t _3, uint64_t _4, uint64_t _5) {
    (void)tgid;
    return lucas_sys_kill(st, tid, signo, 0, 0, 0, 0);
}

/* ===================================================================
 * L10: minimal stubs for busybox vi startup
 * ===================================================================
 *
 * vi probes these during initialisation.  The -c :q flag causes vi to
 * quit before any blocking input wait, so stubs that return "timeout /
 * nothing ready" are sufficient for this dispatch's goal.
 *
 * Full PTY / line-discipline support is deferred to L10 Phase 2.
 */

/* mprotect: musl calls this to mark stack guard + program segments.
 *
 * U5 · real seL4 page-protection ops.
 *
 * Translates Linux PROT_{NONE,READ,WRITE,EXEC} bits into seL4_CapRights
 * and remaps every frame in [addr, addr+len) at its current vaddr with
 * the new rights via seL4_X86_Page_Map (re-map = update permissions on
 * x86_64).  Pages that aren't mapped report -EACCES per Linux semantics. */
int64_t lucas_sys_mprotect(lucas_state_t *st,
                            uint64_t addr, uint64_t len, uint64_t prot,
                            uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;

    printf("[mprotect] pid=%d addr=0x%lx len=%lu prot=0x%lx\n",
           st->synthetic_pid,
           (unsigned long)addr,
           (unsigned long)len,
           (unsigned long)prot);

    /* Validate page-alignment of addr + len (U5 spec).  Linux's man-page
     * defines EINVAL for misaligned addr; len is rounded up there, but
     * the U5 contract is stricter — reject both. */
    if (addr & 0xFFFUL)            return -(int64_t)LX_EINVAL;
    if (len & 0xFFFUL)             return -(int64_t)LX_EINVAL;
    if (len == 0)                  return 0;  /* glibc-compatible no-op */

    /* Build seL4 rights from Linux PROT_* bits.
     * Linux: PROT_NONE=0 PROT_READ=1 PROT_WRITE=2 PROT_EXEC=4.
     * seL4 on x86_64 has no separate execute bit; PROT_EXEC implies
     * read.  PROT_WRITE without PROT_READ is unusual but mappable.
     *
     * SP1 PR 4 · note on W^X: unlike the mmap rights blocks in
     * handlers_mem.c, mprotect has never carried the OBSD-ε W^X
     * rejection — a PROT_WRITE|PROT_EXEC request here maps to
     * can_read=1,can_write=1 (ReadWrite caprights, executable via the
     * default no-NX VMAttributes below) for trusted AND untrusted alike.
     * That already satisfies the trusted in-OS compiler's need for
     * writable-executable memory, so no trusted bypass is added here;
     * adding an untrusted W^X rejection would CHANGE existing untrusted
     * behavior, which SP1 PR 4 explicitly must not do. */
    seL4_CapRights_t rights;
    if (prot == 0) {
        /* PROT_NONE · drop all access. */
        rights = seL4_NoRights;
    } else {
        int can_read  = (prot & (LX_PROT_READ | LX_PROT_EXEC)) ? 1 : 0;
        int can_write = (prot & LX_PROT_WRITE) ? 1 : 0;
        rights = seL4_CapRights_new(0, 0, can_read, can_write);
    }

    /* Iterate page-by-page across the requested range.  addr and len are
     * now both 4 KiB-aligned · end = addr + len.  Guard the addition
     * against wrap (huge len from a buggy/hostile client). */
    if (len > (UINTPTR_MAX - addr)) return -(int64_t)LX_EINVAL;
    uintptr_t end = addr + len;
    for (uintptr_t va = addr; va < end; va += 0x1000UL) {
        seL4_CPtr frame_cap = vspace_get_cap(&st->client_vspace_abs,
                                              (void *)va);
        if (!frame_cap) {
            /* Wine-prep · the page may lie in a logical address-space RESERVATION
             * (a large PROT_NONE mmap · see handlers_mem.c).  mprotect-to-
             * accessible commits a frame there (reserve-then-commit pattern);
             * PROT_NONE leaves it reserved-unmapped.  commit_reserved returns 1
             * if va is in a reservation (handled), 0 otherwise → real EACCES. */
            extern int lucas_mmap_commit_reserved(lucas_state_t *, uintptr_t, uint64_t);
            if (lucas_mmap_commit_reserved(st, va, prot)) continue;
            /* Linux returns EACCES (errno 13) for unmapped pages in the
             * range.  We log once and return immediately · pages already
             * remapped are left at their new rights (matches Linux best-
             * effort semantics on partial failure). */
            printf("[mprotect] pid=%d unmapped page at 0x%lx · -EACCES\n",
                   st->synthetic_pid, (unsigned long)va);
            return -(int64_t)13;  /* -EACCES */
        }

        int err = seL4_X86_Page_Map(frame_cap,
                                    st->client_vspace,
                                    (seL4_Word)va,
                                    rights,
                                    seL4_X86_Default_VMAttributes);
        if (err) {
            printf("[mprotect] pid=%d Page_Map failed at 0x%lx (err=%d)\n",
                   st->synthetic_pid, (unsigned long)va, err);
            return -(int64_t)LX_EINVAL;
        }
    }

    return 0;
}

/* rt_sigreturn: signal trampoline return.  Pops the signal frame from the
 * user stack, restores RIP/RSP/regs, and signals the fault loop to send a
 * raw reply (LUCAS_EXEC_REPLY_RAW · the same anomaly execve uses to skip
 * the rax/rip mutation in lucas_handle_one_fault). */
int64_t lucas_sys_rt_sigreturn(lucas_state_t *st,
                                uint64_t _a0, uint64_t _a1, uint64_t _a2,
                                uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a0; (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    extern int64_t lucas_signals_rt_sigreturn(lucas_state_t *st,
                                               seL4_UserContext *regs);
    seL4_UserContext regs;
    int err = seL4_TCB_ReadRegisters(st->client_tcb, false, 0,
                                      sizeof(regs)/sizeof(seL4_Word), &regs);
    if (err) {
        printf("[signals] rt_sigreturn pid=%d · ReadRegisters err=%d\n",
               st->synthetic_pid, err);
        return 0;
    }
    (void)lucas_signals_rt_sigreturn(st, &regs);
    /* Mirror RIP into RCX in case seL4 returns via sysret. */
    regs.rcx = regs.rip;
    regs.r11 = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
    printf("[l:wr-handlers_proc:883] tcb=%lu rax=0x%lx rip=0x%lx (rt_sigreturn)\n",
           (unsigned long)st->client_tcb,
           (unsigned long)regs.rax,
           (unsigned long)regs.rip);
#endif
    err = seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
    if (err) {
        printf("[signals] rt_sigreturn pid=%d · WriteRegisters err=%d\n",
               st->synthetic_pid, err);
    }
    return LUCAS_EXEC_REPLY_RAW;
}

/* U3 · forward declarations · real implementations live in iomux.c. */
extern int64_t iomux_select_scan(lucas_state_t *st, int nfds,
                                  uintptr_t rfds_vaddr, uintptr_t wfds_vaddr,
                                  uintptr_t efds_vaddr);
extern int64_t iomux_poll_scan  (lucas_state_t *st, uintptr_t fds_vaddr,
                                  unsigned int nfds);
extern int     iomux_poll_is_stdin_block(lucas_state_t *st, uintptr_t fds_vaddr,
                                          unsigned int nfds);
extern int     iomux_poll_has_pipe_read_block(lucas_state_t *st,
                                          uintptr_t fds_vaddr, unsigned int nfds);
/* apt arc · park a blocking poll on a not-ready pipe-read fd · iomux.c. */
extern int64_t lucas_poll_pipe_park(lucas_state_t *st, uintptr_t fds_vaddr,
                                    unsigned int nfds);
extern int64_t lucas_console_poll_park(lucas_state_t *st, uint64_t fds_vaddr,
                                       uint32_t nfds);

/* When a process has a live egress TCP connection, PUMP the real network a
 * bounded amount before an immediate select/poll scan.  select/poll otherwise
 * never drives sotnet_poll, so a select-driven egress client (python's ssl
 * socket with a timeout sets the fd non-blocking + select-waits for the next
 * record / FIN) would spin its own timeout without the arriving bytes ever
 * being processed → TimeoutError mid-download.  Gated to egress conns so
 * interactive/non-network poll-parkers (the busybox shell) are untouched. */
static void lucas_egress_poll_pump(lucas_state_t *st) {
    int tcpfd[LUCAS_MAX_FDS], ntcp = 0;
    int uxfd[LUCAS_MAX_FDS],  nux  = 0;
    int lwfd[LUCAS_MAX_FDS],  nlw  = 0;
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind != LUCAS_FD_SOCKET) continue;
        if (st->fds[i].lwip_sess != NULL)   lwfd[nlw++]   = i;   /* lwIP-egress fd */
        else if (st->fds[i].tcp_conn)       tcpfd[ntcp++] = i;
        /* connected-UDP egress (glibc's resolver UDP:53 socket) pays the pump TOO,
         * so the inbound DNS answer gets pumped (lucas_inet_poll_readable reports a
         * DGRAM fd readable on a queued answer · BG2). */
        else if (st->fds[i].connect_peer_ip_be != 0) tcpfd[ntcp++] = i;
        else if (st->fds[i].unix_chan_idx1) uxfd[nux++]   = i;
    }
    if (ntcp == 0 && nlw == 0) return;   /* gate: an egress socket pays the pump */
    extern int  sotnet_poll(void);
    extern void virtio_net_rx_kick(void);
    extern void tcp_timer_tick(void);
    extern int  lucas_inet_poll_readable(const lucas_state_t *st, int fd);
    extern int  lucas_unix_poll_readable(const lucas_state_t *st, int fd);
    extern void orch_lwip_egress_pump_once(void *handle);
    /* BLOCK (pump the wire) until SOMETHING the caller could be select()ing on is
     * readable — an egress socket got data / FIN'd, OR a socketpair end is ready.
     * select otherwise returns 0 IMMEDIATELY, which python's _ssl reads as "the
     * timeout elapsed" → TimeoutError on a download's final record.  We ALSO bail
     * the moment a socketpair is readable so the openssl s_client relay (which
     * select()s on BOTH its TLS socket AND its stdin socketpair) is never starved
     * of stdin while we wait on the wire. */
    for (long i = 0; i < 6000000L; ++i) {
        for (int k = 0; k < nux;  ++k)
            if (lucas_unix_poll_readable(st, uxfd[k])) return;
        for (int k = 0; k < ntcp; ++k)
            if (lucas_inet_poll_readable(st, tcpfd[k])) return;
        /* lwIP egress: drive its OWN stack (raw_poll · flush queued GET + RX), then
         * the cheap readable check — return the moment the response lands. */
        for (int k = 0; k < nlw; ++k) {
            orch_lwip_egress_pump_once(st->fds[lwfd[k]].lwip_sess);
            if (lucas_inet_poll_readable(st, lwfd[k])) return;
        }
        (void)sotnet_poll();
        virtio_net_rx_kick();
        if ((i & 0xFF) == 0) tcp_timer_tick();
        /* KVM host-CPU YIELD · the load-bearing one (demo-ssh-watch): under
         * -enable-kvm a tight guest spin never yields the host CPU, so QEMU's
         * iothread never DMAs the SLIRP-received inbound (DNS answer / HTTP body)
         * into the virtio RX ring.  rx_kick / rdtsc spins do NOT help (BQL).  A
         * paced UART write (seL4_DebugPutChar → VM-exit → serial chardev) is the
         * ONLY thing that yields host-CPU so the iothread runs.  Paced so it does
         * not flood; the loop exits the instant the answer lands. */
        if ((i & 0x3FF) == 0) seL4_DebugPutChar('.');
    }
}

/* select: walk the fd_set bitmaps via iomux.c · timeout is honoured as
 * "return immediately with whatever's ready right now" (no real timer). */
/* fd0 set in the select read-set? Read BEFORE iomux_select_scan overwrites it. */
static int sel_fd0_requested(lucas_state_t *st, uint64_t rfds) {
    if (rfds == 0) return 0;
    uint8_t b0 = 0;
    if (lucas_copy_from_client(st, (uintptr_t)rfds, &b0, 1) != 0) return 0;
    return (b0 & 1u) != 0;   /* fd0 == bit 0 of byte 0 */
}

/* A blocking (NULL-timeout) select/pselect whose read-set waits on the interactive
 * console fd0 must PARK like poll(stdin,-1) — GNU bash's readline blocks here.
 * Returns the park sentinel (propagate) or the immediate scan result. */
extern int iomux_select_has_pipe_read_block(lucas_state_t *st, int nfds,
                                            uintptr_t rfds_vaddr,
                                            uintptr_t wfds_vaddr,
                                            uintptr_t efds_vaddr);
extern int64_t lucas_select_pipe_park(lucas_state_t *st, int nfds,
                                      uintptr_t rfds_vaddr, uintptr_t wfds_vaddr,
                                      uintptr_t efds_vaddr,
                                      const uint64_t *rfds_orig);

/* Does the select WRITE-set request an egress socket?  Then the client is waiting
 * to WRITE (e.g. apt's WaitFd(POLLOUT) after connect→EINPROGRESS, to send the GET)
 * — a connected egress socket is writable NOW, so we must NOT run the read-wait
 * pump (which would block for data the client hasn't requested → deadlock). */
static int select_egress_write_interest(lucas_state_t *st, uint64_t nfds, uint64_t wfds) {
    if (wfds == 0) return 0;
    unsigned rn = (unsigned)nfds; if (rn > LUCAS_MAX_FDS) rn = LUCAS_MAX_FDS;
    uint64_t bits[(LUCAS_MAX_FDS + 63) / 64] = {0};
    size_t rb = (size_t)((rn + 63) / 64) * sizeof(uint64_t);
    if (rb > sizeof(bits)) rb = sizeof(bits);
    if (lucas_copy_from_client(st, (uintptr_t)wfds, bits, rb) != 0) return 0;
    for (unsigned fd = 0; fd < rn; ++fd) {
        if (!(bits[fd / 64] & (1ULL << (fd % 64)))) continue;
        if (st->fds[fd].kind != LUCAS_FD_SOCKET) continue;
        if (st->fds[fd].lwip_sess || st->fds[fd].tcp_conn || st->fds[fd].connect_peer_ip_be)
            return 1;
    }
    return 0;
}

static int64_t console_select(lucas_state_t *st, uint64_t nfds, uint64_t rfds,
                              uint64_t wfds, uint64_t efds, uint64_t timeout_vaddr) {
    if (!select_egress_write_interest(st, nfds, wfds)) lucas_egress_poll_pump(st);
    extern int64_t lucas_console_select_park(lucas_state_t *, uint32_t,
                                             uint64_t, uint64_t, uint64_t);
    int fd0req = (timeout_vaddr == 0 && st->console_interactive)
                     ? sel_fd0_requested(st, rfds) : 0;

    /* apt arc · capture the pipe-read-park eligibility from the ORIGINAL fd-sets
     * BEFORE iomux_select_scan runs — the scan OVERWRITES the client's rfds/wfds
     * with the (mostly-zero) result bitmaps, so checking after it always reports
     * "no read interest".  A blocking (p)select whose sole readable interest is
     * a not-ready pipe-read fd must PARK (cooperative-yield fix): apt's
     * pkgAcquire pselect6()s its forked http method's stdout pipe for the
     * `100 Capabilities` handshake; an immediate-0 return never yielded the
     * fault loop → the method child was never scheduled to execve+write → apt
     * SIGINT'd it.  pipe.c wakes the parked select on data OR HUP (a forked
     * method always writes or closes).  {0,0} timeout = non-blocking → no park. */
    int sel_blocking = 1;
    if (timeout_vaddr != 0) {
        struct { int64_t tv_sec; int64_t tv_nsec; } tv = { 0, 0 };
        if (lucas_copy_from_client(st, (uintptr_t)timeout_vaddr, &tv, sizeof(tv)) == 0 &&
            tv.tv_sec == 0 && tv.tv_nsec == 0) {
            sel_blocking = 0;   /* {0,0} · non-blocking select · must return now */
        }
    }
    int pipe_block = sel_blocking &&
        iomux_select_has_pipe_read_block(st, (int)nfds, (uintptr_t)rfds,
                                         (uintptr_t)wfds, (uintptr_t)efds);

    /* Snapshot the ORIGINAL read-set before the destructive scan, so a pipe
     * park can restore it on each wake re-scan (the scan zeroes non-ready bits
     * in the client's rfds). */
    uint64_t rfds_orig[(LUCAS_MAX_FDS + 63) / 64] = {0};
    if (pipe_block && rfds) {
        unsigned rn = (unsigned)nfds; if (rn > LUCAS_MAX_FDS) rn = LUCAS_MAX_FDS;
        size_t rb = (size_t)((rn + 63) / 64) * sizeof(uint64_t);
        if (rb > sizeof(rfds_orig)) rb = sizeof(rfds_orig);
        if (lucas_copy_from_client(st, (uintptr_t)rfds, rfds_orig, rb) != 0)
            pipe_block = 0;   /* copy failed · don't park (safe immediate scan) */
    }

    int64_t r = iomux_select_scan(st, (int)nfds, (uintptr_t)rfds,
                                   (uintptr_t)wfds, (uintptr_t)efds);
    if (r != 0) return r;   /* something ready, or a copy error */

    if (pipe_block) {
        int64_t pk = lucas_select_pipe_park(st, (int)nfds, (uintptr_t)rfds,
                                            (uintptr_t)wfds, (uintptr_t)efds,
                                            rfds_orig);
        if (pk == LUCAS_WAIT4_DEFERRED) return pk;
        /* park unavailable → fall through to the immediate scan result. */
    }
    if (fd0req) {
        int64_t pk = lucas_console_select_park(st, (uint32_t)nfds, rfds, wfds, efds);
        if (pk == LUCAS_WAIT4_DEFERRED) return pk;
    }
    return r;
}

int64_t lucas_sys_select(lucas_state_t *st,
                          uint64_t nfds, uint64_t rfds, uint64_t wfds,
                          uint64_t efds, uint64_t timeout, uint64_t _a5) {
    (void)_a5;
    return console_select(st, nfds, rfds, wfds, efds, timeout);
}

/* poll: walk the struct-pollfd array via iomux.c.
 *
 * Task 5 · busybox's interactive ash blocks in poll(stdin, -1).  An immediate
 * scan returns 0 (nothing ready) → busybox busy-loops, pinning the CPU.  When
 * the scan finds nothing ready, the timeout is infinite (<0), and the only
 * readable interest is stdin, PARK the caller on the console (reuses the
 * read-park machinery) so it sleeps until the operator types — the idle pump
 * (lucas_console_resume_parked) re-scans on UART data and wakes with the
 * ready-count.  Finite/zero timeouts and non-stdin polls keep the existing
 * immediate-scan behaviour. */
int64_t lucas_sys_poll(lucas_state_t *st,
                       uint64_t fds, uint64_t nfds, uint64_t timeout,
                       uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;
    /* Scan FIRST (cheap, non-pumping): a POLLOUT-only poll on a connected egress
     * socket is writable NOW and returns here — without the read-wait pump (which
     * would otherwise block waiting for data the client hasn't requested yet, e.g.
     * curl/apt's poll(POLLOUT) to send the GET → deadlock). */
    int64_t scanned = iomux_poll_scan(st, (uintptr_t)fds, (unsigned int)nfds);
    if (scanned != 0) return scanned;   /* something ready, or a copy error */
    /* Nothing ready → the client is waiting to READ; drive the wire until readable. */
    lucas_egress_poll_pump(st);
    scanned = iomux_poll_scan(st, (uintptr_t)fds, (unsigned int)nfds);
    if (scanned != 0) return scanned;

    /* apt arc · a BLOCKING poll() whose sole readable interest is a not-ready
     * pipe-read fd parks here (cooperative-yield fix): the immediate-0 return
     * never yielded the fault loop, so a forked method child (apt's http) was
     * never scheduled to exec+write its handshake.  Park the poller on the
     * pipe-read fd; pipe.c wakes it on data OR HUP — a forked method ALWAYS
     * writes the handshake or closes its end, so the wake is guaranteed and no
     * timer is needed (timeout==0 is non-blocking → must return immediately).
     * Preferred over the stdin-park (apt's case has only the pipe).  NARROW:
     * iomux_poll_has_pipe_read_block requires EVERY POLLIN fd to be a pipe. */
    if (timeout != 0 &&
        iomux_poll_has_pipe_read_block(st, (uintptr_t)fds, (unsigned int)nfds)) {
        int64_t pk = lucas_poll_pipe_park(st, (uintptr_t)fds, (unsigned int)nfds);
        if (pk == LUCAS_WAIT4_DEFERRED) return pk;
        /* park unavailable (cap-alloc/SaveCaller failed) → fall through. */
    }
    if ((int)timeout < 0 &&
        iomux_poll_is_stdin_block(st, (uintptr_t)fds, (unsigned int)nfds)) {
        int64_t pk = lucas_console_poll_park(st, fds, (uint32_t)nfds);
        if (pk == LUCAS_WAIT4_DEFERRED) return pk;
        /* park unavailable (cap-alloc/SaveCaller failed) → fall through to the
         * immediate-scan result (0) rather than hang. */
    }
    return scanned;   /* 0 · immediate-timeout / non-stdin / non-blocking */
}

/* pselect6: signal-safe select · we ignore the sigmask (U1 owns signals). */
int64_t lucas_sys_pselect6(lucas_state_t *st,
                            uint64_t nfds, uint64_t rfds, uint64_t wfds,
                            uint64_t efds, uint64_t timeout, uint64_t sigmask) {
    (void)sigmask;
    return console_select(st, nfds, rfds, wfds, efds, timeout);
}

/* ppoll: signal-safe poll · sigmask ignored (U1 owns signals).
 *
 * apt arc · apt's pkgAcquire uses ppoll() (NOT poll()) to wait on its forked
 * http method's stdout pipe for the `100 Capabilities` handshake.  Same fix as
 * lucas_sys_poll: park a BLOCKING ppoll whose sole readable interest is a
 * not-ready pipe-read fd, woken from pipe.c on data-or-HUP.  ppoll's `timeout`
 * is a `struct timespec *` (vaddr): NULL(0) = infinite; non-NULL = finite (we
 * still park — the pipe wake is prompt and guaranteed for a forked method).  An
 * explicit zero timespec {0,0} = non-blocking → must NOT park. */
int64_t lucas_sys_ppoll(lucas_state_t *st,
                        uint64_t fds, uint64_t nfds, uint64_t timeout,
                        uint64_t sigmask, uint64_t sigsetsize, uint64_t _a5) {
    (void)sigmask; (void)sigsetsize; (void)_a5;
    /* Scan FIRST (cheap) — a POLLOUT-only egress poll returns here without the
     * read-wait pump (see lucas_sys_poll). */
    int64_t scanned = iomux_poll_scan(st, (uintptr_t)fds, (unsigned int)nfds);
    if (scanned != 0) return scanned;   /* something ready, or a copy error */
    lucas_egress_poll_pump(st);
    scanned = iomux_poll_scan(st, (uintptr_t)fds, (unsigned int)nfds);
    if (scanned != 0) return scanned;

    /* Determine if this ppoll blocks: NULL timeout = infinite; a non-NULL
     * timespec is non-blocking ONLY if it is exactly {0,0}. */
    int blocking = 1;
    if (timeout != 0) {
        struct { int64_t tv_sec; int64_t tv_nsec; } ts = { 0, 0 };
        if (lucas_copy_from_client(st, (uintptr_t)timeout, &ts, sizeof(ts)) == 0 &&
            ts.tv_sec == 0 && ts.tv_nsec == 0) {
            blocking = 0;   /* {0,0} · non-blocking poll · must return now */
        }
    }
    if (blocking &&
        iomux_poll_has_pipe_read_block(st, (uintptr_t)fds, (unsigned int)nfds)) {
        int64_t pk = lucas_poll_pipe_park(st, (uintptr_t)fds, (unsigned int)nfds);
        if (pk == LUCAS_WAIT4_DEFERRED) return pk;
        /* park unavailable → fall through to the immediate-scan result. */
    }
    return scanned;
}
