/*
 * sotOs · LUCAS · L11-α-2 · syscall stubs for Python compatibility.
 *
 * Minimal implementations that return "harmless" values:
 *   - futex: per-op dispatch with value check (L11-α-2).
 *   - epoll_create1: synthetic fd 100
 *   - epoll_ctl: 0 (success)
 *   - epoll_wait: 0 (timeout immediately · no events)
 *   - statfs / fstatfs: -ENOSYS (Python importlib degrades gracefully)
 *   - eventfd2: synthetic fd 101
 *   - getcpu: zeros out cpu+node ptrs, returns 0
 *   - madvise: 0 (PyMalloc arena trim · non-fatal)
 *   - ftruncate: 0 (tempfile module)
 *   - get_robust_list: 0 (musl thread init)
 *   - getgroups: 0 groups (Python os module)
 *
 * L11-β will replace these with real implementations.  Phase L11-δ needs
 * real futex for threading; epoll/eventfd for asyncio.
 */
#include "state.h"
#include <lucas/syscalls.h>
#include <lucas/linux_abi.h>
#include <sotfs/graph.h>
#include "sotfs/blkdev.h"
#include <stdint.h>
#include <stdio.h>

/* Declared in handlers_proc.c (same compilation unit group). */
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *host_buf, size_t len);

/* The in-RAM sotfs graph (g_sotfs in backends_sotfs.c) · same accessor
 * used by orch/main.c, simreboot.c, graph_curvature.c. */
extern sotfs_graph_t *backends_sotfs_get_graph(void);

/* PR 12 · futex op constants now live in include/lucas/syscalls.h
 * (LX_FUTEX_*).  The local FUTEX_* aliases were removed to keep the
 * values in one place; the handler switch below uses LX_FUTEX_*. */

extern int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                    void *buf, size_t size);

int64_t lucas_sys_futex(lucas_state_t *st, uint64_t addr, uint64_t op,
                         uint64_t val, uint64_t timeout, uint64_t addr2,
                         uint64_t val3) {
    (void)timeout;

    /* threading.c helpers (file-scope forward-decls would normally live at
     * the top of this TU, but U2 may only modify the body of this function ·
     * extern declarations inside a function body are valid C11).
     *
     * PR 12 · enqueue gained a bitset parameter, and we now call into
     * three new helpers (wake_bitset / requeue / wake_op). */
    extern int lucas_futex_enqueue(lucas_state_t *, uint64_t, seL4_CPtr, int,
                                    uint32_t, seL4_CPtr);
    extern int lucas_futex_wake_bitset(lucas_state_t *, uint64_t, int,
                                        uint32_t);
    extern int lucas_futex_requeue(lucas_state_t *, uint64_t, int,
                                    uint64_t, int, int, uint32_t);
    extern int lucas_futex_wake_op(lucas_state_t *, uint64_t, int,
                                    uint64_t, int, uint32_t);

    /* Strip the PRIVATE + CLOCK flags · keep the bare op. */
    uint64_t bare_op = op & (uint64_t)LX_FUTEX_CMD_MASK;

    switch (bare_op) {
        case LX_FUTEX_WAIT:
        case LX_FUTEX_WAIT_BITSET: {
            /* WAIT_BITSET callers supply val3 as the bitset (default
             * ~0u for legacy WAIT to match every WAKE).  A zero bitset
             * is invalid per the kernel contract → -EINVAL. */
            uint32_t wait_bitset = (bare_op == LX_FUTEX_WAIT_BITSET)
                                    ? (uint32_t)val3 : ~(uint32_t)0;
            if (wait_bitset == 0) {
                printf("[futex] WAIT_BITSET pid=%d addr=0x%lx bitset=0 · -EINVAL\n",
                       st->synthetic_pid, (unsigned long)addr);
                return -(int64_t)22;  /* -EINVAL */
            }
            /* Read the userspace value at addr.  If it doesn't equal val,
             * return -EAGAIN (=-11) per futex(2) semantics (the value
             * changed before we could wait · spin again). */
            uint32_t current = 0;
            if (lucas_copy_from_client(st, (uintptr_t)addr,
                                         &current, sizeof(current)) != 0) {
                return -(int64_t)14;  /* -EFAULT */
            }
            if (current != (uint32_t)val) {
                /* L6 · throttle EAGAIN spam.  Same musl-pthread storm as
                 * the WAKE-vacant case · log first 5 then every 4096th. */
                static unsigned long wait_eagain_throttle = 0;
                ++wait_eagain_throttle;
                if (wait_eagain_throttle <= 5 ||
                    (wait_eagain_throttle & 0xFFFUL) == 0) {
                    printf("[futex] WAIT pid=%d addr=0x%lx expected=%u got=%u · -EAGAIN (#%lu)\n",
                           st->synthetic_pid, (unsigned long)addr,
                           (unsigned)val, (unsigned)current,
                           wait_eagain_throttle);
                }
                return -(int64_t)11;  /* -EAGAIN/-EWOULDBLOCK */
            }
            /* Block · SaveCaller + enqueue on the futex waiter queue.
             * A later FUTEX_WAKE on this addr will seL4_Send to the saved
             * cap; the orch fault loop honours LUCAS_WAIT4_DEFERRED to
             * suppress its own reply. */
            seL4_CPtr cslot;
            int err = vka_cspace_alloc(st->vka, &cslot);
            if (err) {
                printf("[futex] vka_cspace_alloc failed err=%d · -EAGAIN\n", err);
                return -(int64_t)11;
            }
            cspacepath_t cpath;
            vka_cspace_make_path(st->vka, cslot, &cpath);
            err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
            if (err) {
                printf("[futex] SaveCaller failed err=%d · -EAGAIN\n", err);
                vka_cspace_free(st->vka, cslot);
                return -(int64_t)11;
            }
            /* Record the THREAD that's parking (cur_fault_tcb, set by the fault
             * loop to the SP-matched faulting TCB) so the wake restores ITS
             * registers — in a multi-thread box this is not always client_tcb. */
            seL4_CPtr parking_tcb = st->cur_fault_tcb ? st->cur_fault_tcb
                                                      : st->client_tcb;
            if (lucas_futex_enqueue(st, addr, cslot, st->slot_index,
                                     wait_bitset, parking_tcb) != 0) {
                printf("[futex] waiter queue full · -EAGAIN\n");
                vka_cspace_free(st->vka, cslot);
                return -(int64_t)11;
            }
            st->state             = SOTBOX_STATE_WAITING_FOR_FUTEX;
            st->waiting_reply_cap = cslot;
            printf("[futex] WAIT pid=%d addr=0x%lx val=%u bitset=0x%x · PARKED (cslot=%lu)\n",
                   st->synthetic_pid, (unsigned long)addr, (unsigned)val,
                   (unsigned)wait_bitset,
                   (unsigned long)cslot);
            return LUCAS_WAIT4_DEFERRED;
        }

        case LX_FUTEX_WAKE:
        case LX_FUTEX_WAKE_BITSET: {
            /* Walk the futex waiter queue · wake up to `val` matchers.
             * For legacy WAKE the bitset is ~0u (match all); WAKE_BITSET
             * uses val3 verbatim, with 0 mapped to ~0u so a misordered
             * caller still wakes something. */
            uint32_t wake_bitset = (bare_op == LX_FUTEX_WAKE_BITSET)
                                    ? (uint32_t)val3 : ~(uint32_t)0;
            if (wake_bitset == 0) wake_bitset = ~(uint32_t)0;
            int n = lucas_futex_wake_bitset(st, addr, (int)val, wake_bitset);
            /* L6 · throttle FUTEX_WAKE log spam.
             * After L5 fixed args-from-MR, musl-pthread's unlock-vacant
             * loop pours ~272k WAKE printf lines onto serial during Python
             * import init (one per newly-initialised lock × every stdlib
             * module).  Each line is ~150 us on QEMU serial which busts
             * the 90 s smoke budget.
             *
             * Strategy: ALWAYS log when waiters were actually woken
             * (n > 0 · the interesting case).  For the unlock-vacant
             * case (n == 0) log first 5 occurrences then every 4096th.
             * This keeps debug visibility while keeping serial quiet. */
            if (n > 0) {
                printf("[futex] WAKE pid=%d addr=0x%lx n_req=%u woken=%d\n",
                       st->synthetic_pid, (unsigned long)addr,
                       (unsigned)val, n);
            } else {
                static unsigned long wake_vacant_throttle = 0;
                ++wake_vacant_throttle;
                if (wake_vacant_throttle <= 5 ||
                    (wake_vacant_throttle & 0xFFFUL) == 0) {
                    printf("[futex] WAKE pid=%d addr=0x%lx n_req=%u woken=0 (vacant #%lu)\n",
                           st->synthetic_pid, (unsigned long)addr,
                           (unsigned)val, wake_vacant_throttle);
                }

                /* L6 · circuit-breaker for the musl-pthread infinite
                 * WAKE-vacant loop on Python init.
                 *
                 * Now that we dispatch futex(202) correctly, Python's
                 * musl-pthread unlock-vacant loop on the global lock
                 * (typically 0x402030 in the static binary) keeps spinning
                 * forever — there's no waiter to wake, no other thread to
                 * make progress, and the loop has no time-bound termination.
                 *
                 * In baseline this same code path crashed loudly because
                 * dispatch was misclassified as UNKNOWN(op=garbage) and
                 * Python died via UserException → exit 139 → next spawn
                 * (busybox UBUNTU) ran.
                 *
                 * To preserve that "Python falls down then the next spawn
                 * runs" smoke contract, count consecutive WAKE-vacant on
                 * the SAME (slot, addr) and when the streak exceeds
                 * MUSL_VACANT_LIMIT (8192 attempts ≈ "musl has retried more
                 * than the entire static stdlib should ever need"), suspend
                 * the client so the orch reaps the slot. */
                #define MUSL_VACANT_LIMIT 8192
                #define MUSL_VACANT_SLOTS 8
                static struct {
                    uint64_t addr;
                    unsigned long streak;
                    int       owner_pid;   /* L7 · reset when slot recycles */
                } vacant_streak[MUSL_VACANT_SLOTS];
                int slot = (st->slot_index >= 0 &&
                            st->slot_index < MUSL_VACANT_SLOTS)
                           ? st->slot_index : 0;
                /* L7 · if the slot has been recycled (different synthetic_pid),
                 * reset the streak so we don't inherit pthread_test's
                 * residual count when Python lands on the same slot. */
                if (vacant_streak[slot].owner_pid != st->synthetic_pid) {
                    vacant_streak[slot].owner_pid = st->synthetic_pid;
                    vacant_streak[slot].addr      = 0;
                    vacant_streak[slot].streak    = 0;
                }
                if (vacant_streak[slot].addr == addr) {
                    ++vacant_streak[slot].streak;
                } else {
                    vacant_streak[slot].addr   = addr;
                    vacant_streak[slot].streak = 1;
                }
                if (vacant_streak[slot].streak >= MUSL_VACANT_LIMIT) {
                    printf("[futex] WAKE-vacant streak limit (%d) on slot=%d addr=0x%lx · suspending client (Python pthread stuck)\n",
                           MUSL_VACANT_LIMIT, slot,
                           (unsigned long)addr);
                    seL4_TCB_Suspend(st->client_tcb);
                    st->exited    = 1;
                    st->exit_code = 139;   /* SIGSEGV-ish · matches baseline */
                    /* L7 · also stop any leftover pthread children whose
                     * runaway WAKE calls are contaminating this sotBox via
                     * the shared badged fault EP.  Without this they keep
                     * spamming the next sotBox that takes this slot. */
                    {
                        extern void lucas_threads_suspend_all(lucas_state_t *);
                        lucas_threads_suspend_all(st);
                    }
                    /* Reset streak so a future fork/spawn on this slot
                     * starts fresh. */
                    vacant_streak[slot].streak = 0;
                    vacant_streak[slot].addr   = 0;
                }
            }
            return (int64_t)n;
        }

        case LX_FUTEX_REQUEUE:
        case LX_FUTEX_CMP_REQUEUE: {
            /* PR 12 · REQUEUE wakes `val` waiters on `addr`, then moves
             * up to `timeout` (signed-cast) remaining waiters from
             * `addr` to `addr2`.  CMP_REQUEUE additionally checks
             * *addr == val3 and returns -EAGAIN on mismatch.
             *
             * Yes, Linux really overloads the `timeout` arg as nr_requeue
             * for this op (see kernel/futex.c:do_futex). */
            int nr_wake    = (int)(int32_t)val;
            int nr_requeue = (int)(int32_t)timeout;
            int check_cmp  = (bare_op == LX_FUTEX_CMP_REQUEUE);
            int rc = lucas_futex_requeue(st, addr, nr_wake,
                                          addr2, nr_requeue,
                                          check_cmp, (uint32_t)val3);
            printf("[futex] REQUEUE pid=%d addr=0x%lx addr2=0x%lx wake=%d requeue=%d cmp=%d rc=%d\n",
                   st->synthetic_pid, (unsigned long)addr,
                   (unsigned long)addr2, nr_wake, nr_requeue,
                   check_cmp, rc);
            return (int64_t)rc;
        }

        case LX_FUTEX_WAKE_OP: {
            /* PR 12 · WAKE_OP atomically updates *addr2 per val3.opcode,
             * wakes `val` on addr; if val3.cmp(old_*addr2, cmparg) holds,
             * wakes another `timeout` (signed-cast as nr_wake2) on addr2.
             * Same overloading-of-timeout as REQUEUE. */
            int nr_wake  = (int)(int32_t)val;
            int nr_wake2 = (int)(int32_t)timeout;
            int rc = lucas_futex_wake_op(st, addr, nr_wake,
                                          addr2, nr_wake2,
                                          (uint32_t)val3);
            printf("[futex] WAKE_OP pid=%d addr=0x%lx addr2=0x%lx wake=%d wake2=%d val3=0x%x rc=%d\n",
                   st->synthetic_pid, (unsigned long)addr,
                   (unsigned long)addr2, nr_wake, nr_wake2,
                   (unsigned)val3, rc);
            return (int64_t)rc;
        }

        default:
            printf("[futex] UNKNOWN op=0x%lx (bare=0x%lx) addr=0x%lx · -ENOSYS\n",
                   (unsigned long)op, (unsigned long)bare_op,
                   (unsigned long)addr);
            return -(int64_t)38;  /* -ENOSYS */
    }
}

/* U3 · forward declarations · real implementations live in iomux.c. */
extern int64_t iomux_epoll_create(lucas_state_t *st, uint32_t flags);
extern int64_t iomux_epoll_ctl   (lucas_state_t *st, int epfd, int op, int fd,
                                   uintptr_t event_vaddr);
extern int64_t iomux_epoll_wait  (lucas_state_t *st, int epfd,
                                   uintptr_t events_vaddr,
                                   int maxevents, int timeout);

/* epoll_create1(flags) → real LUCAS fd from iomux.c. */
int64_t lucas_sys_epoll_create1(lucas_state_t *st,
                                  uint64_t flags,
                                  uint64_t _1, uint64_t _2, uint64_t _3,
                                  uint64_t _4, uint64_t _5)
{
    (void)_1; (void)_2; (void)_3; (void)_4; (void)_5;
    return iomux_epoll_create(st, (uint32_t)flags);
}

/* epoll_ctl(epfd, op, fd, event) · real ADD / MOD / DEL via iomux.c. */
int64_t lucas_sys_epoll_ctl(lucas_state_t *st,
                              uint64_t epfd, uint64_t op, uint64_t fd,
                              uint64_t event_vaddr,
                              uint64_t _4, uint64_t _5)
{
    (void)_4; (void)_5;
    return iomux_epoll_ctl(st, (int)epfd, (int)op, (int)fd,
                            (uintptr_t)event_vaddr);
}

/* epoll_wait(epfd, events, maxevents, timeout) · real readiness scan via iomux.c. */
int64_t lucas_sys_epoll_wait(lucas_state_t *st,
                               uint64_t epfd, uint64_t events_vaddr,
                               uint64_t maxevents, uint64_t timeout,
                               uint64_t _4, uint64_t _5)
{
    (void)_4; (void)_5;
    return iomux_epoll_wait(st, (int)epfd, (uintptr_t)events_vaddr,
                             (int)maxevents, (int)(int64_t)timeout);
}

/* Linux statfs layout (x86_64).  We define it locally to avoid editing
 * linux_abi.h or adding new top-of-file includes (per worker constraints).
 *
 * MUST be exactly 120 bytes to match the kernel/musl `struct statfs` the caller
 * allocates (on its STACK for fstatfs).  f_fsid is a __kernel_fsid_t = two int32
 * (8 bytes), NOT two uint64 — using uint64[2] made this struct 128 bytes, so
 * lucas_copy_to_client wrote 8 bytes PAST the caller's 120-byte buffer, smashing
 * whatever followed (the stack canary in fontconfig → __stack_chk_fail #GP; the
 * 8-byte overrun was latent for callers without a canary right after, e.g.
 * Python). */
struct lx_statfs64 {
    uint64_t f_type;
    uint64_t f_bsize;
    uint64_t f_blocks;
    uint64_t f_bfree;
    uint64_t f_bavail;
    uint64_t f_files;
    uint64_t f_ffree;
    uint32_t f_fsid[2];   /* __kernel_fsid_t · two int32 = 8 bytes (NOT 16) */
    uint64_t f_namelen;
    uint64_t f_frsize;
    uint64_t f_flags;
    uint64_t f_spare[4];
};
_Static_assert(sizeof(struct lx_statfs64) == 120,
               "struct statfs must be 120 bytes to match kernel/musl x86_64 ABI");

/* statfs(path, buf) → REAL tmpfs-shaped stats derived from the in-RAM sotfs
 * graph (g_sotfs).  Previously these were hardcoded constants — an anti-honeypot
 * tell, since `df` showed the same fixed free/used numbers regardless of actual
 * filesystem state.  We now count live blocks/inodes from the graph so `df` is
 * believable and coherent with what's actually on the (tmpfs-style) mount.
 * Python importlib (and many module-load paths) call statfs("/") to size caches. */
int64_t lucas_sys_statfs(lucas_state_t *st,
                          uint64_t path_vaddr, uint64_t buf_vaddr,
                          uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)path_vaddr; (void)_2; (void)_3; (void)_4; (void)_5;
    if (!buf_vaddr) return -(int64_t)LX_EFAULT;
    struct lx_statfs64 out;
    /* Zero everything (including f_fsid / f_spare) to keep semantics stable. */
    for (size_t i = 0; i < sizeof(out); ++i) ((uint8_t *)&out)[i] = 0;

    /* Count live blocks/inodes from the graph (id != 0 == slot in use; a free
     * slot is id == 0 per sotfs_graph_init / sotfs_free_*).  Defensive on NULL
     * (graph is a BSS global so this is belt-and-suspenders). */
    const sotfs_graph_t *g = backends_sotfs_get_graph();
    uint64_t used_blk = 0, used_ino = 0;
    if (g) {
        for (int i = 0; i < SOTFS_MAX_BLOCKS; ++i)
            if (g->blocks[i].id != 0) used_blk++;
        for (int i = 0; i < SOTFS_MAX_INODES; ++i)
            if (g->inodes[i].id != 0) used_ino++;
    }

    out.f_type    = 0x01021994ULL;       /* TMPFS_MAGIC */
    out.f_bsize   = SOTFS_BLKDEV_BLOCK_SIZE;             /* 4096 */
    out.f_blocks  = sotfs_blk_total();                   /* ~65533 for the 256 MiB region */
    out.f_bfree   = sotfs_blk_total() - sotfs_blk_used();
    out.f_bavail  = out.f_bfree;
    out.f_files   = SOTFS_MAX_INODES;
    out.f_ffree   = SOTFS_MAX_INODES - used_ino;
    out.f_namelen = SOTFS_MAX_NAME - 1;  /* longest leaf name we accept */
    out.f_frsize  = SOTFS_BLOCK_SIZE;
    if (lucas_copy_to_client(st, (uintptr_t)buf_vaddr, &out, sizeof(out)) != 0)
        return -(int64_t)LX_EFAULT;
    return 0;
}

/* fstatfs(fd, buf) → delegate to statfs("/") · the fd's mount-point lookup
 * is not yet wired through, but tmpfs-shaped numbers are still valid. */
int64_t lucas_sys_fstatfs(lucas_state_t *st,
                           uint64_t fd, uint64_t buf_vaddr,
                           uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)fd;
    return lucas_sys_statfs(st, 0, buf_vaddr, _2, _3, _4, _5);
}

/* eventfd2(initval, flags) → allocate a real LUCAS fd slot and store the
 * 64-bit counter in state.eventfd_counters[].  Read/write hookup into the
 * fs handlers is deferred (those live outside this worker's scope); for
 * now the fd lives in the table so close()/poll() see it as valid. */
int64_t lucas_sys_eventfd2(lucas_state_t *st,
                             uint64_t initval, uint64_t flags,
                             uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)flags; (void)_2; (void)_3; (void)_4; (void)_5;
    /* Find the lowest free fd slot >= 3 (0/1/2 are stdio). */
    int fd = -1;
    for (int i = 3; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID && !st->fds[i].is_std) {
            fd = i;
            break;
        }
    }
    if (fd < 0) return -(int64_t)24;  /* -EMFILE */

    /* Cap n_eventfds to the counter array size (LUCAS_MAX_FDS / 2 = 8).
     * If we ran out of counter slots, fall back to a "best-effort" fd
     * with no persistent counter (matches the old behaviour). */
    int slot = st->n_eventfds;
    if (slot >= (int)(sizeof(st->eventfd_counters) /
                       sizeof(st->eventfd_counters[0]))) {
        printf("[l11-eventfd2] no counter slot · returning fd=%d w/o counter\n", fd);
    } else {
        st->eventfd_counters[slot] = initval;
        st->n_eventfds = slot + 1;
    }

    /* Park the fd in the table as a VFS-kind with NULL mount: the close()
     * path treats NULL-mount VFS fds as a no-op release.  This keeps the
     * fd visible to close() without requiring a new LUCAS_FD_* enum. */
    st->fds[fd].kind   = LUCAS_FD_VFS;
    st->fds[fd].mount  = NULL;
    st->fds[fd].handle = NULL;
    st->fds[fd].cursor = 0;
    st->fds[fd].flags  = (int)flags;
    st->fds[fd].is_std = false;
    st->fds[fd].pipe   = NULL;
    printf("[l11-eventfd2] initval=%lu flags=0x%lx · fd=%d counter_slot=%d\n",
           (unsigned long)initval, (unsigned long)flags, fd, slot);
    return (int64_t)fd;
}

/* getcpu(cpu_ptr, node_ptr, tcache) → write 0 to both ptrs · return 0. */
int64_t lucas_sys_getcpu(lucas_state_t *st,
                          uint64_t cpu_vaddr, uint64_t node_vaddr,
                          uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)_2; (void)_3; (void)_4; (void)_5;
    uint32_t zero = 0;
    if (cpu_vaddr)
        lucas_copy_to_client(st, (uintptr_t)cpu_vaddr, &zero, sizeof(zero));
    if (node_vaddr)
        lucas_copy_to_client(st, (uintptr_t)node_vaddr, &zero, sizeof(zero));
    return 0;
}

/* madvise(addr, len, advice) → 0.  We log the advice token so that any
 * unexpected hint shows up in serial during smoke; the kernel-side LRU
 * is a no-op for us. */
int64_t lucas_sys_madvise(lucas_state_t *st,
                           uint64_t addr, uint64_t len, uint64_t advice,
                           uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)st; (void)_3; (void)_4; (void)_5;
    const char *name;
    switch (advice) {
        case 0:  name = "NORMAL";     break;
        case 1:  name = "RANDOM";     break;
        case 2:  name = "SEQUENTIAL"; break;
        case 3:  name = "WILLNEED";   break;
        case 4:  name = "DONTNEED";   break;
        case 8:  name = "FREE";       break;
        case 9:  name = "REMOVE";     break;
        default: name = "OTHER";      break;
    }
    printf("[l11-madvise] addr=0x%lx len=%lu advice=%lu(%s) · 0 (no-op)\n",
           (unsigned long)addr, (unsigned long)len,
           (unsigned long)advice, name);
    return 0;
}

/* ftruncate(fd, length) → look up fd's vfs entry; if backend supports a
 * truncate op, call it.  Otherwise return 0 silently (Python tempfile
 * relies on success here · ENOSPC/EINVAL would break it). */
int64_t lucas_sys_ftruncate(lucas_state_t *st,
                              uint64_t fd, uint64_t length,
                              uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)length; (void)_2; (void)_3; (void)_4; (void)_5;
    /* L13 · a memfd_create'd fd: ftruncate sizes + allocates the wl_shm pool
     * via the orch shm-pool module (A2).  mmap (Task B2) maps it to the guest. */
    extern int orch_shm_pool_alloc(size_t, uint32_t);
    extern int orch_shm_pool_grow(int, size_t);
    if (fd < LUCAS_MAX_FDS && st->fds[fd].is_memfd) {
        /* A second ftruncate on the same memfd RESIZES the pool — grow it in place
         * (the old code re-alloc'd a fresh pool, orphaning the first + its mapping). */
        if (st->fds[fd].shm_pool_id >= 0) {
            if (orch_shm_pool_grow(st->fds[fd].shm_pool_id, (size_t)length) < 0) return -12;
            if ((uint64_t)length > st->fds[fd].shm_pool_size) st->fds[fd].shm_pool_size = (uint64_t)length;
            return 0;
        }
        /* M4 · owner = this sotbox, for refcounted free + teardown sweep. The
         * pool starts at refcount 1 (the pending wl_shm_pool object, released by
         * wl_shm_pool.destroy); the memfd close is NOT a ref — see shm_pool.c. */
        int pid = orch_shm_pool_alloc((size_t)length, (uint32_t)st->synthetic_pid);
        if (pid < 0) return -12;            /* -ENOMEM */
        st->fds[fd].shm_pool_id   = pid;
        st->fds[fd].shm_pool_size = (uint64_t)length;
        printf("[l13-ftruncate] memfd fd=%lu size=%lu pool=%d\n",
               (unsigned long)fd, (unsigned long)length, pid);
        return 0;
    }
    if (fd >= LUCAS_MAX_FDS) {
        /* Out-of-range fd · still return 0 to keep Python tempfile happy;
         * a hard EBADF here breaks shutil/tempfile cleanup paths. */
        printf("[l11-ftruncate] fd=%lu (out-of-range) · 0 (silent)\n",
               (unsigned long)fd);
        return 0;
    }
    lucas_fd_t *e = &st->fds[fd];
    /* F3 · COW shrink-on-resave · a VFS fd backed by a truncate-capable backend
     * (static / sotfs canary surfaces) routes through it so a Tier-2 session's
     * SHORTER :w shrinks its overlay entry (no stale tail).  Non-truncate backends
     * and non-session callers fall through to success-silently. */
    if (e->kind == LUCAS_FD_VFS && e->mount && e->mount->ops->truncate) {
        lucas_set_current_caller(st);
        int rc = e->mount->ops->truncate(e->mount->backend_state, e->handle,
                                         (int64_t)length);
        lucas_set_current_caller(NULL);
        if (rc == 0 && (int64_t)length >= 0) e->cursor = 0;  /* O_TRUNC resets cursor */
        printf("[l11-ftruncate] fd=%lu length=%lu · backend truncate rc=%d\n",
               (unsigned long)fd, (unsigned long)length, rc);
        return (rc < 0) ? (int64_t)rc : 0;
    }
    printf("[l11-ftruncate] fd=%lu length=%lu · 0 (silent · no backend op)\n",
           (unsigned long)fd, (unsigned long)length);
    return 0;
}

/* fallocate(fd, mode, offset, len).  posix_fallocate(fd, offset, len) lowers to
 * this with mode=0.  libwayland's os_create_anonymous_file sizes a wl_shm pool fd
 * with posix_fallocate (memfd_create THEN posix_fallocate · no ftruncate) — so for
 * a memfd this must do exactly what ftruncate does: allocate the orch shm pool to
 * offset+len.  Without it, libwayland-cursor's cursor-theme pool fails →
 * wl_cursor_theme_load returns NULL → GTK CSD aborts (no cursor theme).  Mode bits
 * (PUNCH_HOLE / KEEP_SIZE / ...) are ignored: a size-extend is the only real use
 * here, and a non-memfd fd succeeds-silently (matches ftruncate's contract). */
int64_t lucas_sys_fallocate(lucas_state_t *st,
                              uint64_t fd, uint64_t mode, uint64_t offset,
                              uint64_t len, uint64_t _4, uint64_t _5)
{
    (void)mode; (void)_4; (void)_5;
    uint64_t size = offset + len;
    if (fd < LUCAS_MAX_FDS && st->fds[fd].is_memfd) {
        extern int orch_shm_pool_grow(int, size_t);
        if (st->fds[fd].shm_pool_id >= 0) {           /* grow an already-sized pool */
            if (orch_shm_pool_grow(st->fds[fd].shm_pool_id, (size_t)size) < 0) return -12;
            if (size > st->fds[fd].shm_pool_size) st->fds[fd].shm_pool_size = size;
            return 0;
        }
        extern int orch_shm_pool_alloc(size_t, uint32_t);
        int pid = orch_shm_pool_alloc((size_t)size, (uint32_t)st->synthetic_pid);
        if (pid < 0) return -12;                       /* -ENOMEM */
        st->fds[fd].shm_pool_id   = pid;
        st->fds[fd].shm_pool_size = size;
        printf("[l13-fallocate] memfd fd=%lu size=%lu pool=%d\n",
               (unsigned long)fd, (unsigned long)size, pid);
        return 0;
    }
    return 0;   /* non-memfd · success-silently */
}

/* get_robust_list(pid, head_ptr, len_ptr) → write the stored head/len back
 * to the caller's pointers.  Matches the kernel contract; pid is ignored
 * because we are single-task per sotbox. */
int64_t lucas_sys_get_robust_list(lucas_state_t *st,
                                   uint64_t pid, uint64_t head_ptr,
                                   uint64_t len_ptr,
                                   uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)pid; (void)_3; (void)_4; (void)_5;
    if (head_ptr) {
        uint64_t h = st->robust_list_head;
        if (lucas_copy_to_client(st, (uintptr_t)head_ptr, &h, sizeof(h)) != 0)
            return -(int64_t)LX_EFAULT;
    }
    if (len_ptr) {
        size_t l = st->robust_list_len;
        if (lucas_copy_to_client(st, (uintptr_t)len_ptr, &l, sizeof(l)) != 0)
            return -(int64_t)LX_EFAULT;
    }
    return 0;
}

/* getgroups(size, list) → 0 groups (process is in no supplementary groups). */
int64_t lucas_sys_getgroups(lucas_state_t *st,
                              uint64_t size, uint64_t list_vaddr,
                              uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)st; (void)size; (void)list_vaddr;
    (void)_2; (void)_3; (void)_4; (void)_5;
    return 0;
}

/* SYSCALL-FIVE · post-L9 stub-audit top 5 (docs/lucas-stub-audit.md).
 *
 * Five small handlers bundled here as defense-in-depth for the next Python
 * 3.12 boot pass.  Each one targets a dispatch-level gap that today routes
 * to sys_enosys; pattern + reasoning is recorded in the audit doc. */

/* mremap flag bits (Linux include/uapi/linux/mman.h). */
#define LX_MREMAP_MAYMOVE   1
#define LX_MREMAP_FIXED     2
#define LX_MREMAP_DONTUNMAP 4

/* Forward decls · in-tree handlers we reuse for mremap. */
extern int64_t lucas_sys_mmap  (lucas_state_t *, uint64_t, uint64_t, uint64_t,
                                  uint64_t, uint64_t, uint64_t);
extern int64_t lucas_sys_munmap(lucas_state_t *, uint64_t, uint64_t, uint64_t,
                                  uint64_t, uint64_t, uint64_t);

/* mremap(old_addr, old_size, new_size, flags, new_addr) · always-move impl.
 *
 * Strategy (matches docs/lucas-stub-audit.md §1 sketch):
 *   1. Require MREMAP_MAYMOVE; reject MREMAP_FIXED / MREMAP_DONTUNMAP for now
 *      (no in-place resize · we always relocate to a fresh region).
 *   2. Allocate new region via lucas_sys_mmap(NULL, new_size, anon|priv).
 *   3. Copy min(old_size, new_size) bytes through host bounce buffer using
 *      lucas_copy_from_client + lucas_copy_to_client (4 KiB chunks).
 *   4. munmap the old region.
 *   5. Return the new vaddr.
 */
int64_t lucas_sys_mremap(lucas_state_t *st,
                          uint64_t old_addr, uint64_t old_size,
                          uint64_t new_size, uint64_t flags,
                          uint64_t new_addr, uint64_t _5)
{
    (void)new_addr; (void)_5;
    if (!(flags & LX_MREMAP_MAYMOVE)) {
        printf("[mremap] flags=0x%lx missing MAYMOVE · -EINVAL\n",
               (unsigned long)flags);
        return -(int64_t)LX_EINVAL;
    }
    if (flags & (LX_MREMAP_FIXED | LX_MREMAP_DONTUNMAP)) {
        printf("[mremap] flags=0x%lx FIXED/DONTUNMAP unsupported · -EINVAL\n",
               (unsigned long)flags);
        return -(int64_t)LX_EINVAL;
    }
    if (old_size == 0 || new_size == 0) return -(int64_t)LX_EINVAL;

    /* IN-PLACE EXTEND fast path · grow at the current address when the trailing
     * span is free (map only the delta · no move/copy).  Makes apt's pkgCache
     * build survive: the always-move fallback advances the arena watermark every
     * grow → OOM at ~22 MiB.  In-place is monotonic. */
    if (new_size > old_size) {
        extern int lucas_mmap_extend_inplace(lucas_state_t *st, uint64_t addr,
                                             uint64_t old_size, uint64_t new_size);
        if (lucas_mmap_extend_inplace(st, old_addr, old_size, new_size) == 0)
            return (int64_t)old_addr;
    }

    /* Allocate fresh anonymous-private region. */
    int64_t new_vaddr = lucas_sys_mmap(st, 0, new_size,
                                        LX_PROT_READ | LX_PROT_WRITE,
                                        LX_MAP_ANONYMOUS | LX_MAP_PRIVATE,
                                        (uint64_t)-1, 0);
    if (new_vaddr < 0) {
        printf("[mremap] mmap(new_size=%lu) failed · %ld\n",
               (unsigned long)new_size, (long)new_vaddr);
        return new_vaddr;
    }

    /* Copy min(old, new) bytes through a small host bounce buffer. */
    uint64_t copy_bytes = (old_size < new_size) ? old_size : new_size;
    uint8_t  bounce[4096];
    uint64_t off = 0;
    while (off < copy_bytes) {
        size_t chunk = (copy_bytes - off > sizeof(bounce))
                        ? sizeof(bounce) : (size_t)(copy_bytes - off);
        if (lucas_copy_from_client(st, (uintptr_t)old_addr + off,
                                     bounce, chunk) != 0) {
            printf("[mremap] copy_from(0x%lx+%lu) failed · -EFAULT\n",
                   (unsigned long)old_addr, (unsigned long)off);
            return -(int64_t)LX_EFAULT;
        }
        if (lucas_copy_to_client(st, (uintptr_t)new_vaddr + off,
                                   bounce, chunk) != 0) {
            printf("[mremap] copy_to(0x%lx+%lu) failed · -EFAULT\n",
                   (unsigned long)new_vaddr, (unsigned long)off);
            return -(int64_t)LX_EFAULT;
        }
        off += chunk;
    }

    /* Free the old region (best-effort · lucas_sys_munmap is a no-op stub today). */
    (void)lucas_sys_munmap(st, old_addr, old_size, 0, 0, 0, 0);

    printf("[mremap] old=0x%lx (%lu) → new=0x%lx (%lu) copied=%lu\n",
           (unsigned long)old_addr, (unsigned long)old_size,
           (unsigned long)new_vaddr, (unsigned long)new_size,
           (unsigned long)copy_bytes);
    return new_vaddr;
}

/* clock_getres(clk_id, res) · any clock → {tv_sec=0, tv_nsec=1}, return 0. */
int64_t lucas_sys_clock_getres(lucas_state_t *st,
                                uint64_t clk_id, uint64_t res_vaddr,
                                uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)clk_id; (void)_2; (void)_3; (void)_4; (void)_5;
    if (!res_vaddr) return 0;
    struct { int64_t tv_sec; int64_t tv_nsec; } ts = { 0, 1 };
    if (lucas_copy_to_client(st, (uintptr_t)res_vaddr, &ts, sizeof(ts)) != 0)
        return -(int64_t)LX_EFAULT;
    return 0;
}

/* umask(mask) · stash + return prior value.  sotFS has no on-disk perms so
 * the value is cosmetic, but cpython's posixmodule.c does a r-m-w probe at
 * init (umask(022) → umask(orig)) that needs the previous value preserved. */
int64_t lucas_sys_umask(lucas_state_t *st,
                         uint64_t mask,
                         uint64_t _1, uint64_t _2, uint64_t _3,
                         uint64_t _4, uint64_t _5)
{
    (void)st; (void)_1; (void)_2; (void)_3; (void)_4; (void)_5;
    static unsigned int saved_umask = 022;
    unsigned int prev = saved_umask;
    saved_umask = (unsigned int)mask & 0777u;
    return (int64_t)prev;
}

/* setrlimit(resource, rlim) · log + accept (mirror of prlimit64 setter side).
 * sotOs has no real resource accounting today; Python's setrlimit(RLIMIT_STACK)
 * on some pyconfig builds just needs success. */
int64_t lucas_sys_setrlimit(lucas_state_t *st,
                             uint64_t resource, uint64_t rlim_vaddr,
                             uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)st; (void)rlim_vaddr; (void)_2; (void)_3; (void)_4; (void)_5;
    printf("[setrlimit] resource=%lu · 0 (accept)\n", (unsigned long)resource);
    return 0;
}

/* getrusage(who, usage) · zero-fill a 144-byte rusage struct.  Python doesn't
 * actually read the values on the success path (_PyImport_BootstrapImp and
 * the resource module both treat 0 as "no usage yet"). */
int64_t lucas_sys_getrusage(lucas_state_t *st,
                             uint64_t who, uint64_t usage_vaddr,
                             uint64_t _2, uint64_t _3, uint64_t _4, uint64_t _5)
{
    (void)who; (void)_2; (void)_3; (void)_4; (void)_5;
    if (!usage_vaddr) return -(int64_t)LX_EFAULT;
    uint8_t zero[144];
    for (size_t i = 0; i < sizeof(zero); ++i) zero[i] = 0;
    if (lucas_copy_to_client(st, (uintptr_t)usage_vaddr,
                              zero, sizeof(zero)) != 0)
        return -(int64_t)LX_EFAULT;
    return 0;
}

/* N-MISC-SYS · sendfile(2) moved to src/lucas/handlers_fs.c · it now performs a
 * REAL file→fd copy (busybox `cat` streams files to stdout via sendfile, not
 * read/write).  CPython's importlib still works: a correct byte-transferring
 * sendfile satisfies its fast path too. */

/* N-MISC-SYS · epoll_pwait(epfd, *events, maxevents, timeout, *sigmask, sigsetsize)
 *
 * Python 3.12's selectors module may use epoll_pwait(281) instead of
 * epoll_wait(232) so that the signal mask is applied atomically around the
 * wait.  We ignore the sigmask (LUCAS has no real signal-blocking surface
 * yet · sigaltstack/rt_sigprocmask are largely cosmetic) and route through
 * the same iomux backend as epoll_wait. */
int64_t lucas_sys_epoll_pwait(lucas_state_t *st,
                                uint64_t epfd, uint64_t events_vaddr,
                                uint64_t maxevents, uint64_t timeout,
                                uint64_t sigmask_vaddr, uint64_t sigsetsize)
{
    (void)sigmask_vaddr; (void)sigsetsize;
    return iomux_epoll_wait(st, (int)epfd, (uintptr_t)events_vaddr,
                             (int)maxevents, (int)(int64_t)timeout);
}
