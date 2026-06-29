/*
 * sotOs · LUCAS · U3 · I/O multiplexing infrastructure.
 *
 * Implements:
 *   - iomux_fd_ready(st, fd)      · readiness bitmask for one LUCAS fd
 *   - iomux_epoll_create()        · alloc an epoll instance slot + LUCAS fd
 *   - iomux_epoll_ctl()           · ADD / MOD / DEL an (fd, events) pair
 *   - iomux_epoll_wait()          · drain ready set; park if requested
 *   - iomux_check_epoll_waiters() · wake-up hook called from pipe.c
 *   - iomux_select_scan()         · bitmap helper for select / pselect6
 *   - iomux_poll_scan()           · struct-pollfd helper for poll / ppoll
 *
 * No malloc · fixed bounded tables live inside lucas_state_t under the U3
 * anomaly.  Pipes use the lucas_pipe_*_ready predicates exported by
 * src/orch/pipe.c.  Sockets are stubs (sotNet has no real readiness yet)
 * and are reported as "never ready" per the U3 spec.
 */

#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/syscalls.h>
#include <orch/pipe.h>
#include <sotnet/bytepipe.h>

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/capops.h>

#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/* Forward declarations · same helpers used by handlers_*.c. */
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *host_buf, size_t len);
extern int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                    void *buf, size_t size);
/* v2.7 · stage synthesized wl_pointer events into a wayland fd's wl_rx (defined
 * in handlers_net.c); 1 if it staged bytes (fd now readable), 0 if nothing. */
extern int lucas_wl_try_stage_input(lucas_state_t *st, lucas_fd_t *e);

/* ---- Linux ABI constants (subset · only what U3 needs) ------------------- */

/* epoll_event flags (subset). */
#define LX_EPOLLIN   0x001u
#define LX_EPOLLOUT  0x004u
#define LX_EPOLLERR  0x008u
#define LX_EPOLLHUP  0x010u
#define LX_EPOLLRDHUP 0x2000u

/* epoll_ctl ops. */
#define LX_EPOLL_CTL_ADD 1
#define LX_EPOLL_CTL_DEL 2
#define LX_EPOLL_CTL_MOD 3

/* Linux x86_64 packs epoll_event with __attribute__((packed)) so the layout
 * is { uint32_t events; uint64_t data; } back-to-back = 12 bytes total. */
struct lx_epoll_event {
    uint32_t events;
    uint64_t data;
} __attribute__((packed));

/* poll(2) struct pollfd. */
struct lx_pollfd {
    int      fd;
    short    events;
    short    revents;
};

#define LX_POLLIN   0x001
#define LX_POLLOUT  0x004
#define LX_POLLERR  0x008
#define LX_POLLHUP  0x010
#define LX_POLLNVAL 0x020

/* iomux_fd_ready return mask. */
#define IOMUX_READABLE 0x1
#define IOMUX_WRITABLE 0x2
#define IOMUX_HUP      0x4

/* ---- Readiness oracle ---------------------------------------------------- */

/* Return a bitmask of IOMUX_{READABLE,WRITABLE,HUP} for a single LUCAS fd.
 * Sockets are treated as never-ready (sotNet stubs · future batch).
 * STDIO is always writable; never readable (no real input source yet). */
static int iomux_fd_ready(lucas_state_t *st, int fd) {
    if (fd < 0 || fd >= LUCAS_MAX_FDS) return 0;
    const lucas_fd_t *e = &st->fds[fd];
    switch (e->kind) {
        case LUCAS_FD_STDIO: {
            /* stdout/stderr always writable. stdin (fd 0) is readable when the
             * serial UART has a byte waiting — lets an interactive shell's
             * poll(stdin,-1) wake when the operator types.  Phase B: an SSH
             * canary-shell box's stdin source is the SHELL_IN bytepipe ring
             * (console_src == SSH_RING), NOT the UART — poll/select/epoll must
             * report fd0 readable when the ring has unread bytes (w != rd) or a
             * pending ANSI-DSR reply (dsr_emit), otherwise busybox's poll(stdin)
             * parks forever while net-synth's commands sit in the ring. */
            int mask = IOMUX_WRITABLE;
            if (fd == 0 || e->is_console_tty) {   /* fd0, or /dev/tty (bash readline) */
                if (st->console_src == LUCAS_CONSOLE_SRC_SSH_RING) {
                    bytepipe_ring_t *in = (bytepipe_ring_t *)BYTEPIPE_SHELL_IN_VADDR;
                    if (st->dsr_emit > 0 ||
                        __atomic_load_n(&in->w, __ATOMIC_ACQUIRE) != st->shell_in_rd)
                        mask |= IOMUX_READABLE;
                } else {
                    /* SERIAL/keyboard console: report readable when a pending
                     * ANSI-DSR reply (dsr_emit) is queued too — else after
                     * busybox writes ESC[6n, poll(stdin) parks and the DSR reply
                     * only flows once a key arrives, racing the keystrokes (the
                     * SSH_RING branch above already does this). */
                    extern int lucas_console_data_ready(void);
                    if (st->dsr_emit > 0 || lucas_console_data_ready())
                        mask |= IOMUX_READABLE;
                }
            }
            return mask;
        }
        case LUCAS_FD_PIPE_READ: {
            int mask = 0;
            if (lucas_pipe_read_ready(e->pipe)) mask |= IOMUX_READABLE;
            if (lucas_pipe_hup(e->pipe))         mask |= IOMUX_HUP;
            return mask;
        }
        case LUCAS_FD_PIPE_WRITE: {
            int mask = 0;
            if (lucas_pipe_write_ready(e->pipe)) mask |= IOMUX_WRITABLE;
            if (lucas_pipe_hup(e->pipe))          mask |= IOMUX_HUP;
            return mask;
        }
        case LUCAS_FD_VFS:
            /* Regular files are always readable + writable in POSIX. */
            return IOMUX_READABLE | IOMUX_WRITABLE;
        case LUCAS_FD_SOCKET:
            /* Wayland broker fd: requests are accepted synchronously (always
             * writable); readable iff a buffered compositor reply (wl_rx) is
             * pending.  libwayland polls POLLIN before recvmsg in roundtrip.
             * v2.7 · also readable when there is fresh virtio-tablet pointer input
             * to deliver — lucas_wl_try_stage_input synthesizes the wl_pointer wire
             * events into wl_rx AT POLL TIME (so the subsequent read never sees an
             * empty readable fd → no EOF/disconnect race); it is idempotent and a
             * no-op when headless / no pointer object yet. */
            if (e->wayland_connected) {
                int mask = IOMUX_WRITABLE;
                if (e->wl_rx_cursor < e->wl_rx_len      /* compositor reply pending     */
                    || e->wl_in_cursor < e->wl_in_len   /* staged pointer input pending */
                    || lucas_wl_try_stage_input(st, e)) /* or stage fresh input now     */
                    mask |= IOMUX_READABLE;
                return mask;
            }
            /* WINE-M1 · AF_UNIX rendezvous (wineserver IPC).  A listener is
             * readable when its backlog has a pending connection; a connected
             * stream endpoint is readable when its read ring has bytes or the
             * peer closed (HUP/EOF).  Always reported writable (send buffer). */
            {
                extern int lucas_unix_is_rendezvous(const lucas_state_t *st, int fd);
                extern int lucas_unix_poll_readable(const lucas_state_t *st, int fd);
                if (lucas_unix_is_rendezvous(st, fd)) {
                    int mask = IOMUX_WRITABLE;
                    if (lucas_unix_poll_readable(st, fd)) mask |= IOMUX_READABLE;
                    return mask;
                }
            }
            /* sotNet-δ · INET socket (DNS/HTTP egress).  Always writable (send
             * buffer); readable when a forwarded/synth datagram is queued for
             * this pid (the DNS answer) OR a connected egress TCP socket has rx
             * bytes / closed — so a poll-first client (musl getaddrinfo, busybox
             * wget) sees the data instead of timing out. */
            {
                extern int lucas_inet_poll_readable(const lucas_state_t *st, int fd);
                int mask = 0;
                if (st->fds[fd].lwip_sess != NULL) {
                    /* lwIP-egress fd · WRITABLE reflects async-connect completion
                     * (orch_lwip_egress_poll_out pumps the handshake) — so a
                     * non-blocking client's WaitFd(POLLOUT) after connect→EINPROGRESS
                     * blocks here until ESTABLISHED, then writes its request. */
                    extern int orch_lwip_egress_poll_out(void *handle);
                    if (orch_lwip_egress_poll_out(st->fds[fd].lwip_sess)) mask |= IOMUX_WRITABLE;
                } else {
                    mask |= IOMUX_WRITABLE;   /* δ socket · send buffer always ready */
                }
                if (lucas_inet_poll_readable(st, fd)) mask |= IOMUX_READABLE;
                return mask;
            }
        case LUCAS_FD_EPOLL:
            /* Epoll fds are "readable" iff at least one registered fd has
             * pending events.  This lets epoll_wait on an epoll fd work
             * (uncommon but legal). */
            return 0;
        default:
            return 0;
    }
}

/* ---- Free LUCAS fd allocator (matching pipe.c pattern) ------------------- */

static int alloc_lucas_fd(lucas_state_t *st) {
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID && !st->fds[i].is_std) {
            return i;
        }
    }
    return -1;
}

/* ---- Epoll-table helpers ------------------------------------------------- */

#define EPOLL_TABLE_SIZE   (int)(sizeof(((lucas_state_t *)0)->epoll_table) / \
                                 sizeof(((lucas_state_t *)0)->epoll_table[0]))
#define EPOLL_ENTRIES_PER_INSTANCE \
    (int)(sizeof(((lucas_state_t *)0)->epoll_table[0].entries) / \
          sizeof(((lucas_state_t *)0)->epoll_table[0].entries[0]))

/* Locate the epoll_table slot whose epfd matches.  Returns -1 if none. */
static int epoll_slot_for_fd(lucas_state_t *st, int epfd) {
    for (int s = 0; s < EPOLL_TABLE_SIZE; ++s) {
        if (st->epoll_table[s].in_use && st->epoll_table[s].epfd == epfd) {
            return s;
        }
    }
    return -1;
}

/* Allocate an unused epoll_table slot.  Returns -1 if exhausted. */
static int epoll_alloc_slot(lucas_state_t *st) {
    for (int s = 0; s < EPOLL_TABLE_SIZE; ++s) {
        if (!st->epoll_table[s].in_use) {
            memset(&st->epoll_table[s], 0, sizeof(st->epoll_table[s]));
            st->epoll_table[s].in_use = 1;
            return s;
        }
    }
    return -1;
}

/* ---- Drain-ready helper (shared by epoll_wait + wake-up hook) ------------ */

/* Scan epoll_table[slot]'s registered fds, build up to `maxevents`
 * struct lx_epoll_event entries describing currently-ready fds, copy them
 * into the client's vspace at events_vaddr, and return the count.
 * Returns 0 if nothing is ready · negative errno on copy failure. */
static int64_t epoll_drain_ready(lucas_state_t *st, int slot,
                                 uintptr_t events_vaddr, int maxevents) {
    if (slot < 0 || slot >= EPOLL_TABLE_SIZE) return -(int64_t)LX_EINVAL;
    if (maxevents <= 0)                       return -(int64_t)LX_EINVAL;

    /* Bounded staging buffer · at most EPOLL_ENTRIES_PER_INSTANCE events
     * since that's the upper bound on registered fds. */
    struct lx_epoll_event staged[16];
    int produced = 0;

    int n = st->epoll_table[slot].n_entries;
    if (n > EPOLL_ENTRIES_PER_INSTANCE) n = EPOLL_ENTRIES_PER_INSTANCE;

    for (int i = 0; i < n && produced < maxevents
                          && produced < (int)(sizeof(staged) / sizeof(staged[0]));
         ++i) {
        int      fd       = st->epoll_table[slot].entries[i].fd;
        uint32_t want     = st->epoll_table[slot].entries[i].events;
        uint64_t userdata = st->epoll_table[slot].entries[i].user_data;
        int      mask     = iomux_fd_ready(st, fd);

        uint32_t got = 0;
        if ((want & LX_EPOLLIN)  && (mask & IOMUX_READABLE)) got |= LX_EPOLLIN;
        if ((want & LX_EPOLLOUT) && (mask & IOMUX_WRITABLE)) got |= LX_EPOLLOUT;
        if (mask & IOMUX_HUP) got |= LX_EPOLLHUP;   /* always delivered */

        if (got == 0) continue;

        staged[produced].events = got;
        staged[produced].data   = userdata;
        produced++;
    }

    if (produced == 0) return 0;

    /* Copy out · bytes count = produced * sizeof(struct lx_epoll_event).
     * sizeof is 12 because of the packed attribute. */
    size_t bytes = (size_t)produced * sizeof(struct lx_epoll_event);
    if (lucas_copy_to_client(st, events_vaddr, staged, bytes) != 0) {
        return -(int64_t)LX_EFAULT;
    }
    return (int64_t)produced;
}

/* ---- Park / resume helpers ----------------------------------------------- */

/* Park the caller in WAITING_FOR_EPOLL state with reply cap saved.
 * Returns LUCAS_WAIT4_DEFERRED on success · negative errno on cap-alloc fail. */
static int64_t epoll_park(lucas_state_t *st, int slot,
                          uintptr_t events_vaddr, int maxevents) {
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)LX_ENOMEM;
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        return -(int64_t)LX_ENOMEM;
    }
    st->waiting_reply_cap        = cslot;
    st->epoll_wait_slot          = slot;
    st->epoll_wait_events_vaddr  = events_vaddr;
    st->epoll_wait_maxevents     = maxevents;
    st->state                    = SOTBOX_STATE_WAITING_FOR_EPOLL;
    printf("[epoll] PARK pid=%d slot=%d maxevents=%d\n",
           st->synthetic_pid, slot, maxevents);
    return LUCAS_WAIT4_DEFERRED;
}

/* Unblock a sotBox that was parked in epoll_wait, returning `retval` as the
 * syscall result.  Mirrors pipe_resume_sotbox in src/orch/pipe.c. */
static void epoll_resume_sotbox(lucas_state_t *st, int64_t retval) {
    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)retval;
        regs.rip += 2;          /* advance past the syscall instruction */
        regs.rcx  = regs.rip;
        regs.r11  = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
        printf("[l:wr-iomux:243] tcb=%lu rax=0x%lx rip=0x%lx\n",
               (unsigned long)st->client_tcb,
               (unsigned long)regs.rax,
               (unsigned long)regs.rip);
#endif
        seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
    }
    seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    vka_cspace_free(st->vka, st->waiting_reply_cap);
    st->waiting_reply_cap       = 0;
    st->epoll_wait_slot         = -1;
    st->epoll_wait_events_vaddr = 0;
    st->epoll_wait_maxevents    = 0;
    st->state                   = SOTBOX_STATE_RUNNING;
}

/* Called from pipe.c on every event that could change pipe readiness
 * (new bytes written, writer/reader close).  Walks every live sotBox and
 * wakes any whose parked epoll slot now has at least one ready fd. */
extern lucas_state_t *sotbox_get_slot(int i);
#ifndef SOTBOX_MAX_SLOTS
#define SOTBOX_MAX_SLOTS 8   /* fall-back · matches include/orch/sotbox.h */
#endif

void iomux_check_epoll_waiters(struct lucas_pipe *p) {
    (void)p;  /* we re-scan all registered fds · the pipe identity isn't
                 needed because epoll_drain_ready calls iomux_fd_ready which
                 inspects state->fds[].pipe directly. */
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_EPOLL) continue;
        int slot = st->epoll_wait_slot;
        if (slot < 0) continue;

        int64_t produced = epoll_drain_ready(st, slot,
                                              st->epoll_wait_events_vaddr,
                                              st->epoll_wait_maxevents);
        if (produced > 0) {
            printf("[epoll] WAKE pid=%d · %lld ready fds\n",
                   st->synthetic_pid, (long long)produced);
            epoll_resume_sotbox(st, produced);
        } else if (produced < 0) {
            /* Copy-out failed · deliver the error so the syscaller sees it. */
            epoll_resume_sotbox(st, produced);
        }
        /* produced == 0 · still nothing · leave parked. */
    }
}

/* ---- apt arc · poll() pipe-read park / resume ---------------------------- */

/* Forward decls · iomux_poll_scan is defined below; lx_pollfd lives in the
 * client-ABI header already included for the scan/eligibility helpers. */
int64_t iomux_poll_scan(lucas_state_t *st, uintptr_t fds_vaddr,
                        unsigned int nfds);

/* Park the caller in WAITING_FOR_POLL with the reply cap saved.  Mirrors
 * epoll_park verbatim · records the poll fds_vaddr/nfds for the re-scan.
 * Returns LUCAS_WAIT4_DEFERRED on success · negative errno on cap-alloc fail. */
static int64_t poll_park(lucas_state_t *st, uintptr_t fds_vaddr,
                         unsigned int nfds) {
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)LX_ENOMEM;
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        return -(int64_t)LX_ENOMEM;
    }
    st->waiting_reply_cap    = cslot;
    st->poll_wait_fds_vaddr  = fds_vaddr;
    st->poll_wait_nfds       = nfds;
    st->state                = SOTBOX_STATE_WAITING_FOR_POLL;
    printf("[poll] PARK pid=%d nfds=%u (pipe-read)\n", st->synthetic_pid, nfds);
    return LUCAS_WAIT4_DEFERRED;
}

/* Public wrapper · called from lucas_sys_poll (handlers_proc.c) once the scan
 * returned 0 and iomux_poll_has_pipe_read_block confirmed eligibility. */
int64_t lucas_poll_pipe_park(lucas_state_t *st, uintptr_t fds_vaddr,
                             unsigned int nfds) {
    return poll_park(st, fds_vaddr, nfds);
}

/* ---- apt arc · (p)select() pipe-read park / resume ----------------------- */

int64_t iomux_select_scan(lucas_state_t *st, int nfds,
                          uintptr_t rfds_vaddr, uintptr_t wfds_vaddr,
                          uintptr_t efds_vaddr);
/* fd_set word helpers · defined later in this file (select scan section). */
static int    fdset_get(const uint64_t *set, int fd);
static size_t fdset_bytes(int nfds);

/* Park the caller in WAITING_FOR_SELECT with the reply cap saved.  Mirrors
 * poll_park · records the select fd-set vaddrs + nfds for the re-scan.
 * apt's pkgAcquire uses pselect6() (NOT poll) to wait on its forked http
 * method's stdout pipe for the `100 Capabilities` handshake. */
static int64_t select_park(lucas_state_t *st, int nfds, uintptr_t rfds_vaddr,
                           uintptr_t wfds_vaddr, uintptr_t efds_vaddr,
                           const uint64_t *rfds_orig) {
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)LX_ENOMEM;
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        return -(int64_t)LX_ENOMEM;
    }
    st->waiting_reply_cap    = cslot;
    st->sel_wait_nfds        = nfds;
    st->sel_wait_rfds_vaddr  = rfds_vaddr;
    st->sel_wait_wfds_vaddr  = wfds_vaddr;
    st->sel_wait_efds_vaddr  = efds_vaddr;
    for (unsigned i = 0; i < sizeof(st->sel_wait_rfds_orig)/sizeof(uint64_t); ++i)
        st->sel_wait_rfds_orig[i] = rfds_orig ? rfds_orig[i] : 0;
    st->state                = SOTBOX_STATE_WAITING_FOR_SELECT;
    printf("[select] PARK pid=%d nfds=%d (pipe-read)\n", st->synthetic_pid, nfds);
    return LUCAS_WAIT4_DEFERRED;
}

int64_t lucas_select_pipe_park(lucas_state_t *st, int nfds, uintptr_t rfds_vaddr,
                               uintptr_t wfds_vaddr, uintptr_t efds_vaddr,
                               const uint64_t *rfds_orig) {
    return select_park(st, nfds, rfds_vaddr, wfds_vaddr, efds_vaddr, rfds_orig);
}

static void select_resume_sotbox(lucas_state_t *st, int64_t retval) {
    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)retval;
        regs.rip += 2;
        regs.rcx  = regs.rip;
        regs.r11  = regs.rflags;
        seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
    }
    seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    vka_cspace_free(st->vka, st->waiting_reply_cap);
    st->waiting_reply_cap   = 0;
    st->sel_wait_nfds       = 0;
    st->sel_wait_rfds_vaddr = 0;
    st->sel_wait_wfds_vaddr = 0;
    st->sel_wait_efds_vaddr = 0;
    st->state               = SOTBOX_STATE_RUNNING;
}

/* Called from pipe.c on every pipe-readiness change.  Wakes any sotBox parked
 * in (p)select() whose saved fd-sets now have a ready fd.  iomux_select_scan
 * writes the result bitmaps back into the client sets AND returns the ready
 * count — including the efds/HUP path when a method child exec-fails. */
void iomux_check_select_waiters(struct lucas_pipe *p) {
    (void)p;
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_SELECT) continue;

        /* Restore the ORIGINAL read-set into the client before the scan — the
         * prior scan (and any earlier wake re-scan that found nothing) zeroed
         * the client's rfds, so without this the re-scan would see an empty set
         * and never wake.  Only the read-set is restored: the pipe-read-park
         * eligibility guarantees the write/except sets were empty. */
        if (st->sel_wait_rfds_vaddr) {
            size_t nb = fdset_bytes(st->sel_wait_nfds);
            if (nb > sizeof(st->sel_wait_rfds_orig)) nb = sizeof(st->sel_wait_rfds_orig);
            (void)lucas_copy_to_client(st, st->sel_wait_rfds_vaddr,
                                       st->sel_wait_rfds_orig, nb);
        }
        int64_t ready = iomux_select_scan(st, st->sel_wait_nfds,
                                          st->sel_wait_rfds_vaddr,
                                          st->sel_wait_wfds_vaddr,
                                          st->sel_wait_efds_vaddr);
        if (ready > 0) {
            printf("[select] WAKE pid=%d · %lld ready fds\n",
                   st->synthetic_pid, (long long)ready);
            select_resume_sotbox(st, ready);
        } else if (ready < 0) {
            select_resume_sotbox(st, ready);
        }
    }
}

/* Eligibility · returns 1 iff EVERY fd set in the read-set is a
 * LUCAS_FD_PIPE_READ fd (at least one present) AND the write/except sets are
 * EMPTY.  The caller only reaches here after iomux_select_scan returned 0, so
 * every read-fd is currently not-ready → parking is safe (the pipe wake on
 * data-or-HUP is guaranteed for a forked method).  Any non-pipe read-fd, or any
 * write/except interest, disqualifies (NARROW).  Returns 0 on copy failure. */
int iomux_select_has_pipe_read_block(lucas_state_t *st, int nfds,
                                     uintptr_t rfds_vaddr, uintptr_t wfds_vaddr,
                                     uintptr_t efds_vaddr) {
    if (nfds <= 0 || rfds_vaddr == 0) return 0;
    if (nfds > LUCAS_MAX_FDS) nfds = LUCAS_MAX_FDS;

    uint64_t rin[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t win[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t ein[(LUCAS_MAX_FDS + 63) / 64] = {0};
    size_t nbytes = fdset_bytes(nfds);
    if (nbytes > sizeof(rin)) nbytes = sizeof(rin);

    if (lucas_copy_from_client(st, rfds_vaddr, rin, nbytes) != 0) return 0;
    if (wfds_vaddr && lucas_copy_from_client(st, wfds_vaddr, win, nbytes) != 0) return 0;
    if (efds_vaddr && lucas_copy_from_client(st, efds_vaddr, ein, nbytes) != 0) return 0;

    int pipe_in = 0;
    for (int fd = 0; fd < nfds; ++fd) {
        if (wfds_vaddr && fdset_get(win, fd)) return 0;   /* any write interest → no park */
        if (efds_vaddr && fdset_get(ein, fd)) return 0;   /* any except interest → no park */
        if (!fdset_get(rin, fd)) continue;
        if (fd < LUCAS_MAX_FDS && st->fds[fd].kind == LUCAS_FD_PIPE_READ) {
            pipe_in = 1;
        } else {
            return 0;   /* a non-pipe fd wants to read → not a pure pipe-read block */
        }
    }
    return pipe_in;
}

/* Unblock a sotBox parked in poll(), returning `retval` (the ready count) as
 * the syscall result.  Mirrors epoll_resume_sotbox · clears poll_wait_* fields. */
static void poll_resume_sotbox(lucas_state_t *st, int64_t retval) {
    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)retval;
        regs.rip += 2;          /* advance past the syscall instruction */
        regs.rcx  = regs.rip;
        regs.r11  = regs.rflags;
        seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
    }
    seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    vka_cspace_free(st->vka, st->waiting_reply_cap);
    st->waiting_reply_cap   = 0;
    st->poll_wait_fds_vaddr = 0;
    st->poll_wait_nfds      = 0;
    st->state               = SOTBOX_STATE_RUNNING;
}

/* Called from pipe.c on every event that could change pipe readiness (new
 * bytes, writer/reader close).  Walks every live sotBox and wakes any whose
 * parked poll set now has at least one ready fd.  The re-scan (iomux_poll_scan)
 * writes the revents back into the client array AND returns the ready count, so
 * the woken poller observes the completed poll() exactly as Linux would —
 * including POLLHUP when a method child exec-fails and closes its pipe end. */
void iomux_check_poll_waiters(struct lucas_pipe *p) {
    (void)p;  /* iomux_poll_scan inspects state->fds[].pipe directly. */
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_POLL) continue;

        int64_t ready = iomux_poll_scan(st, st->poll_wait_fds_vaddr,
                                        st->poll_wait_nfds);
        if (ready > 0) {
            printf("[poll] WAKE pid=%d · %lld ready fds\n",
                   st->synthetic_pid, (long long)ready);
            poll_resume_sotbox(st, ready);
        } else if (ready < 0) {
            /* copy-out failed · deliver the error so the syscaller sees it. */
            poll_resume_sotbox(st, ready);
        }
        /* ready == 0 · still nothing · leave parked. */
    }
}

/* ---- Public epoll API (called from handlers_python.c) ------------------- */

int64_t iomux_epoll_create(lucas_state_t *st, uint32_t flags) {
    (void)flags;   /* EPOLL_CLOEXEC is accepted but not enforced. */
    int fd = alloc_lucas_fd(st);
    if (fd < 0) return -(int64_t)24;  /* -EMFILE */
    int slot = epoll_alloc_slot(st);
    if (slot < 0) return -(int64_t)24;
    st->epoll_table[slot].epfd       = fd;
    st->epoll_table[slot].n_entries  = 0;
    st->fds[fd].kind  = LUCAS_FD_EPOLL;
    st->fds[fd].pipe  = NULL;
    st->fds[fd].mount = NULL;
    st->fds[fd].handle= NULL;
    st->n_epoll_instances++;
    printf("[epoll] create1 epfd=%d\n", fd);
    return (int64_t)fd;
}

int64_t iomux_epoll_ctl(lucas_state_t *st, int epfd, int op, int fd,
                         uintptr_t event_vaddr) {
    int slot = epoll_slot_for_fd(st, epfd);
    if (slot < 0) return -(int64_t)LX_EBADF;
    if (fd < 0 || fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;

    /* Find an existing entry for this fd (so MOD/DEL can locate it). */
    int existing = -1;
    int n = st->epoll_table[slot].n_entries;
    for (int i = 0; i < n; ++i) {
        if (st->epoll_table[slot].entries[i].fd == fd) {
            existing = i;
            break;
        }
    }

    if (op == LX_EPOLL_CTL_DEL) {
        if (existing < 0) return -(int64_t)2;  /* -ENOENT */
        /* Compact the array · last entry takes the deleted slot's place. */
        int last = st->epoll_table[slot].n_entries - 1;
        if (existing != last) {
            st->epoll_table[slot].entries[existing] =
                st->epoll_table[slot].entries[last];
        }
        st->epoll_table[slot].n_entries--;
        printf("[epoll] ctl op=DEL fd=%d epfd=%d\n", fd, epfd);
        return 0;
    }

    /* ADD / MOD need to read the lx_epoll_event from the client. */
    struct lx_epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    if (lucas_copy_from_client(st, event_vaddr, &ev, sizeof(ev)) != 0) {
        return -(int64_t)LX_EFAULT;
    }

    if (op == LX_EPOLL_CTL_ADD) {
        if (existing >= 0) return -(int64_t)17;  /* -EEXIST */
        if (n >= EPOLL_ENTRIES_PER_INSTANCE) return -(int64_t)LX_ENOMEM;
        st->epoll_table[slot].entries[n].fd        = fd;
        st->epoll_table[slot].entries[n].events    = ev.events;
        st->epoll_table[slot].entries[n].user_data = ev.data;
        st->epoll_table[slot].n_entries = n + 1;
        printf("[epoll] ctl op=ADD fd=%d events=0x%x epfd=%d\n",
               fd, (unsigned)ev.events, epfd);
        return 0;
    }
    if (op == LX_EPOLL_CTL_MOD) {
        if (existing < 0) return -(int64_t)2;  /* -ENOENT */
        st->epoll_table[slot].entries[existing].events    = ev.events;
        st->epoll_table[slot].entries[existing].user_data = ev.data;
        printf("[epoll] ctl op=MOD fd=%d events=0x%x epfd=%d\n",
               fd, (unsigned)ev.events, epfd);
        return 0;
    }
    return -(int64_t)LX_EINVAL;
}

int64_t iomux_epoll_wait(lucas_state_t *st, int epfd, uintptr_t events_vaddr,
                          int maxevents, int timeout) {
    int slot = epoll_slot_for_fd(st, epfd);
    if (slot < 0) return -(int64_t)LX_EBADF;
    if (maxevents <= 0) return -(int64_t)LX_EINVAL;

    int64_t got = epoll_drain_ready(st, slot, events_vaddr, maxevents);
    if (got != 0) {
        if (got > 0) {
            printf("[epoll] wait returned %lld ready fds (epfd=%d)\n",
                   (long long)got, epfd);
        }
        return got;
    }

    /* Nothing ready right now. */
    if (timeout == 0) {
        return 0;   /* immediate timeout · don't park */
    }
    /* timeout > 0 (real timeout) and timeout < 0 (infinite) both park.
     * We don't implement timed wake-ups yet · the caller will be parked
     * until a pipe event wakes them.  Future U3-extension: hook into a
     * monotonic-clock tick to enforce timeout. */
    return epoll_park(st, slot, events_vaddr, maxevents);
}

/* ---- select / pselect6 bitmap scan -------------------------------------- */

/* fd_set is an array of 64-bit words on x86_64 (FD_SETSIZE / 64 longs).
 * We only honour LUCAS_MAX_FDS · everything past that returns ENOSPC-style
 * silence (bits left zero). */

static int fdset_get(const uint64_t *set, int fd) {
    return (set[fd / 64] >> (fd % 64)) & 1u;
}
static void fdset_set(uint64_t *set, int fd) {
    set[fd / 64] |= ((uint64_t)1 << (fd % 64));
}

/* Bytes the client passed: ceil(nfds/8), rounded up to 8 for the word ops. */
static size_t fdset_bytes(int nfds) {
    if (nfds <= 0) return 0;
    int words = (nfds + 63) / 64;
    return (size_t)words * sizeof(uint64_t);
}

int64_t iomux_select_scan(lucas_state_t *st, int nfds,
                           uintptr_t rfds_vaddr, uintptr_t wfds_vaddr,
                           uintptr_t efds_vaddr) {
    if (nfds <= 0) return 0;
    if (nfds > LUCAS_MAX_FDS) nfds = LUCAS_MAX_FDS;

    uint64_t rin[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t win[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t ein[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t rout[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t wout[(LUCAS_MAX_FDS + 63) / 64] = {0};
    uint64_t eout[(LUCAS_MAX_FDS + 63) / 64] = {0};

    size_t nbytes = fdset_bytes(nfds);
    if (nbytes > sizeof(rin)) nbytes = sizeof(rin);

    if (rfds_vaddr && lucas_copy_from_client(st, rfds_vaddr, rin, nbytes) != 0)
        return -(int64_t)LX_EFAULT;
    if (wfds_vaddr && lucas_copy_from_client(st, wfds_vaddr, win, nbytes) != 0)
        return -(int64_t)LX_EFAULT;
    if (efds_vaddr && lucas_copy_from_client(st, efds_vaddr, ein, nbytes) != 0)
        return -(int64_t)LX_EFAULT;

    int ready = 0;
    for (int fd = 0; fd < nfds; ++fd) {
        int mask = iomux_fd_ready(st, fd);
        if (rfds_vaddr && fdset_get(rin, fd) && (mask & IOMUX_READABLE)) {
            fdset_set(rout, fd);
            ready++;
        }
        if (wfds_vaddr && fdset_get(win, fd) && (mask & IOMUX_WRITABLE)) {
            fdset_set(wout, fd);
            ready++;
        }
        if (efds_vaddr && fdset_get(ein, fd) && (mask & IOMUX_HUP)) {
            fdset_set(eout, fd);
            ready++;
        }
    }

    if (rfds_vaddr && lucas_copy_to_client(st, rfds_vaddr, rout, nbytes) != 0)
        return -(int64_t)LX_EFAULT;
    if (wfds_vaddr && lucas_copy_to_client(st, wfds_vaddr, wout, nbytes) != 0)
        return -(int64_t)LX_EFAULT;
    if (efds_vaddr && lucas_copy_to_client(st, efds_vaddr, eout, nbytes) != 0)
        return -(int64_t)LX_EFAULT;

    return (int64_t)ready;
}

/* ---- poll / ppoll struct-pollfd scan ------------------------------------ */

int64_t iomux_poll_scan(lucas_state_t *st, uintptr_t fds_vaddr,
                         unsigned int nfds) {
    if (nfds == 0 || fds_vaddr == 0) return 0;
    if (nfds > LUCAS_MAX_FDS) nfds = LUCAS_MAX_FDS;

    struct lx_pollfd pfds[LUCAS_MAX_FDS];
    size_t bytes = (size_t)nfds * sizeof(struct lx_pollfd);

    if (lucas_copy_from_client(st, fds_vaddr, pfds, bytes) != 0) {
        return -(int64_t)LX_EFAULT;
    }

    int ready = 0;
    for (unsigned int i = 0; i < nfds; ++i) {
        pfds[i].revents = 0;
        if (pfds[i].fd < 0) continue;
        int mask = iomux_fd_ready(st, pfds[i].fd);
        if ((pfds[i].events & LX_POLLIN)  && (mask & IOMUX_READABLE))
            pfds[i].revents |= LX_POLLIN;
        if ((pfds[i].events & LX_POLLOUT) && (mask & IOMUX_WRITABLE))
            pfds[i].revents |= LX_POLLOUT;
        if (mask & IOMUX_HUP) pfds[i].revents |= LX_POLLHUP;
        if (pfds[i].revents) ready++;
    }

    if (lucas_copy_to_client(st, fds_vaddr, pfds, bytes) != 0) {
        return -(int64_t)LX_EFAULT;
    }
    return (int64_t)ready;
}

/* Task 5 · poll-park eligibility.  Returns 1 iff this poll set is a pure
 * "wait for stdin input" — i.e. at least one fd is STDIO stdin (fd 0) asking
 * for POLLIN, and NO other fd in the set requests POLLIN.  (Other fds polling
 * only for POLLOUT are fine — STDIO/VFS are always writable, so they were
 * already reported ready by the scan; if we reach the park path the scan
 * returned 0, meaning no such writable fd was requested.)  A finite/zero
 * timeout or any non-stdin readable interest disqualifies the park so we keep
 * the current immediate-scan behaviour.  Returns 0 on copy failure (caller
 * then takes the safe immediate-scan path). */
int iomux_poll_is_stdin_block(lucas_state_t *st, uintptr_t fds_vaddr,
                              unsigned int nfds) {
    if (nfds == 0 || fds_vaddr == 0) return 0;
    if (nfds > LUCAS_MAX_FDS) nfds = LUCAS_MAX_FDS;

    struct lx_pollfd pfds[LUCAS_MAX_FDS];
    size_t bytes = (size_t)nfds * sizeof(struct lx_pollfd);
    if (lucas_copy_from_client(st, fds_vaddr, pfds, bytes) != 0) return 0;

    int stdin_in = 0;
    for (unsigned int i = 0; i < nfds; ++i) {
        if (pfds[i].fd < 0) continue;
        if (!(pfds[i].events & LX_POLLIN)) continue;   /* only POLLIN interest matters */
        if (pfds[i].fd == 0 && pfds[i].fd < LUCAS_MAX_FDS &&
            st->fds[0].kind == LUCAS_FD_STDIO) {
            stdin_in = 1;
        } else {
            return 0;   /* some other fd wants to read → not a pure stdin block */
        }
    }
    return stdin_in;
}

/* Task 5 (apt arc) · poll-park eligibility for a not-ready pipe-read fd.
 * Returns 1 iff EVERY fd in the set with POLLIN interest is a LUCAS_FD_PIPE_READ
 * fd (at least one such fd present) AND no fd requests any *other* readable
 * interest (stdio/socket/etc).  Because the caller only reaches this after the
 * scan already returned 0, every requested-readable fd is currently not-ready,
 * so parking is safe: the pipe wake (data OR HUP, fired from pipe.c) is
 * guaranteed for a forked method (it always writes the handshake or closes its
 * end).  Writable-only interest on other fds is irrelevant — those would have
 * been reported ready by the scan (stdio/vfs are always writable), so if we are
 * here none were requested.  Returns 0 on copy failure (caller then takes the
 * safe immediate-scan path).  NARROW: a single non-pipe POLLIN fd disqualifies. */
int iomux_poll_has_pipe_read_block(lucas_state_t *st, uintptr_t fds_vaddr,
                                   unsigned int nfds) {
    if (nfds == 0 || fds_vaddr == 0) return 0;
    if (nfds > LUCAS_MAX_FDS) nfds = LUCAS_MAX_FDS;

    struct lx_pollfd pfds[LUCAS_MAX_FDS];
    size_t bytes = (size_t)nfds * sizeof(struct lx_pollfd);
    if (lucas_copy_from_client(st, fds_vaddr, pfds, bytes) != 0) return 0;

    int pipe_in = 0;
    for (unsigned int i = 0; i < nfds; ++i) {
        if (pfds[i].fd < 0) continue;
        if (!(pfds[i].events & LX_POLLIN)) continue;   /* only readable interest matters */
        if (pfds[i].fd < LUCAS_MAX_FDS &&
            st->fds[pfds[i].fd].kind == LUCAS_FD_PIPE_READ) {
            pipe_in = 1;
        } else {
            return 0;   /* a non-pipe fd wants to read → not a pure pipe-read block */
        }
    }
    return pipe_in;
}
