/*
 * sotOs · LUCAS L3b · pipe object + ring buffer + waiter management.
 *
 * A pipe holds a fixed 4 KiB ring buffer.  Multiple sotBoxes can have fd
 * table entries pointing at it (read or write ends).  Readers/writers track
 * open counts so we can signal EOF/EPIPE on close.
 *
 * Blocking: a reader on an empty pipe parks via SaveCaller; the next writer
 * that puts bytes in walks the orchestrator's slot table looking for
 * sotBoxes with state=WAITING_FOR_PIPE_READ whose waiting_pipe matches.
 * Same pattern in reverse for blocked writers.
 */

#include <orch/sotbox.h>
#include <orch/pipe.h>
#include <lucas/syscalls.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/capops.h>
#include <vspace/vspace.h>
#include <sel4utils/mapping.h>

/* ---- Pool ---------------------------------------------------------------- */

#define LUCAS_PIPE_BUF_SIZE 4096
#define LUCAS_PIPE_POOL     64   /* 16 -> 64 · `apt install` fans out many concurrent
                                  * pipes (the apt↔method worker protocol for http/store +
                                  * the apt↔dpkg IPC pipe + dpkg's --status-fd) → 16 ran out
                                  * ("Failed to create IPC pipe to dpkg · pipe (24: Too many
                                  * open files)") before apt could --unpack the downloaded
                                  * .deb.  Each pipe is ~4 KiB (256 KiB BSS at 64). */

struct lucas_pipe {
    uint8_t buf[LUCAS_PIPE_BUF_SIZE];
    size_t  head;           /* next write position */
    size_t  tail;           /* next read position */
    size_t  count;          /* bytes available to read */
    int     readers_open;
    int     writers_open;
    bool    in_use;
};

static struct lucas_pipe g_pipe_pool[LUCAS_PIPE_POOL];

struct lucas_pipe *lucas_pipe_alloc(void) {
    for (int i = 0; i < LUCAS_PIPE_POOL; ++i) {
        if (!g_pipe_pool[i].in_use) {
            memset(&g_pipe_pool[i], 0, sizeof(g_pipe_pool[i]));
            g_pipe_pool[i].in_use       = true;
            g_pipe_pool[i].readers_open = 1;
            g_pipe_pool[i].writers_open = 1;
            printf("[pipe] alloc idx=%d\n", i);
            return &g_pipe_pool[i];
        }
    }
    printf("[pipe] alloc: pool exhausted\n");
    return NULL;
}

/* ---- External helpers (implemented in lucas static lib / handlers_fs.c) -- */

/* Copy bytes from orchestrator-local buffer into client vspace. */
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                  const void *src_buf, size_t size);

/* Copy raw bytes from client vspace into orchestrator-local buffer.
 * Implemented below — same dup_and_map pattern, but for input. */
static int pipe_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                  void *buf, size_t size);

/* ---- Slot table access --------------------------------------------------- */

/* g_slots is declared static in sotbox_table.c but we need a way to iterate
 * all live sotBoxes.  We expose it via a public getter rather than an extern
 * on the static array. */
extern lucas_state_t *sotbox_get_slot(int i);

/* U3 · iomux epoll wake-up · check sotBoxes parked in epoll_wait when a pipe
 * becomes readable/writable.  Defined in src/lucas/iomux.c. */
extern void iomux_check_epoll_waiters(struct lucas_pipe *p);
/* apt arc · wake sotBoxes parked in a blocking poll() on a pipe-read fd when a
 * pipe becomes readable / HUPs.  Defined in src/lucas/iomux.c. */
extern void iomux_check_poll_waiters(struct lucas_pipe *p);
/* apt arc · the same for a blocking (p)select() on a pipe-read fd. */
extern void iomux_check_select_waiters(struct lucas_pipe *p);

/* ---- Ring-buffer helpers -------------------------------------------------- */

/* Drain up to `count` bytes from ring buffer into local staging, then copy
 * to client.  Returns bytes actually copied. */
static size_t pipe_read_drain(lucas_state_t *st, struct lucas_pipe *p,
                               uintptr_t client_vaddr, size_t count) {
    static uint8_t stage[LUCAS_PIPE_BUF_SIZE];
    size_t available = p->count;
    if (available == 0) return 0;
    size_t to_read = (count < available) ? count : available;
    for (size_t i = 0; i < to_read; ++i) {
        stage[i] = p->buf[p->tail];
        p->tail   = (p->tail + 1) % LUCAS_PIPE_BUF_SIZE;
    }
    p->count -= to_read;
    if (lucas_copy_to_client(st, client_vaddr, stage, to_read) != 0) {
        /* Partial copy failure: data already consumed from ring.  Return
         * what we attempted so the caller at least advances. */
        return to_read;
    }
    return to_read;
}

/* Fill the ring buffer from client vspace.  Returns bytes written into ring. */
static size_t pipe_write_fill(lucas_state_t *st, struct lucas_pipe *p,
                               uintptr_t client_vaddr, size_t count) {
    static uint8_t stage[LUCAS_PIPE_BUF_SIZE];
    size_t free_space = LUCAS_PIPE_BUF_SIZE - p->count;
    if (free_space == 0) return 0;
    size_t to_write = (count < free_space) ? count : free_space;
    if (pipe_copy_from_client(st, client_vaddr, stage, to_write) != 0) {
        return 0;
    }
    for (size_t i = 0; i < to_write; ++i) {
        p->buf[p->head] = stage[i];
        p->head          = (p->head + 1) % LUCAS_PIPE_BUF_SIZE;
    }
    p->count += to_write;
    return to_write;
}

/* ---- Raw client-vspace reader -------------------------------------------- */

static int pipe_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                  void *buf, size_t size) {
    uint8_t *dst    = (uint8_t *)buf;
    size_t   copied = 0;
    while (copied < size) {
        uintptr_t addr      = client_vaddr + copied;
        uintptr_t page_base = addr & ~0xFFFUL;
        size_t    off       = (size_t)(addr - page_base);
        size_t    in_page   = 4096 - off;
        if (in_page > size - copied) in_page = size - copied;

        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
        if (!frame) {
            printf("[pipe] copy_from_client: no frame at 0x%lx\n",
                   (unsigned long)page_base);
            return -1;
        }
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                             frame, seL4_PageBits);
        if (!local) {
            printf("[pipe] copy_from_client: dup_and_map failed\n");
            return -1;
        }
        memcpy(dst + copied, (const uint8_t *)local + off, in_page);
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
        copied += in_page;
    }
    return 0;
}

/* ---- Waiter wake-ups ------------------------------------------------------ */

/* Unblock register write + Send pattern: shared by wake_readers/writers. */
static void pipe_resume_sotbox(lucas_state_t *st, int64_t retval) {
    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)retval;
        regs.rip += 2;          /* advance past syscall instruction */
        regs.rcx  = regs.rip;  /* sysret restores RIP from RCX */
        regs.r11  = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
        printf("[l:wr-orch_pipe:166] tcb=%lu rax=0x%lx rip=0x%lx (pipe_resume)\n",
               (unsigned long)st->client_tcb,
               (unsigned long)regs.rax,
               (unsigned long)regs.rip);
#endif
        seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
    }
    /* Resume via the DEDICATED pipe cap — NOT st->waiting_reply_cap, which a
     * sibling thread's futex wake may have zeroed (see state.h pipe_reply_cap). */
    seL4_Send(st->pipe_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    vka_cspace_free(st->vka, st->pipe_reply_cap);
    st->pipe_reply_cap     = 0;
    st->waiting_pipe       = NULL;
    st->pipe_wait_kind     = 0;
    /* Only clear `state` if it still reflects OUR pipe wait — a sibling thread
     * may have since overwritten it (e.g. to WAITING_FOR_FUTEX); don't clobber. */
    if (st->state == SOTBOX_STATE_WAITING_FOR_PIPE_READ ||
        st->state == SOTBOX_STATE_WAITING_FOR_PIPE_WRITE)
        st->state          = SOTBOX_STATE_RUNNING;
}

void lucas_pipe_wake_readers(struct lucas_pipe *p) {
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->pipe_wait_kind != 1) continue;   /* 1 = read · independent of st->state */
        if (st->waiting_pipe != p) continue;

        /* Try to drain bytes into the waiting reader. */
        size_t  got   = 0;
        int64_t retval = 0;
        if (p->count > 0) {
            got    = pipe_read_drain(st, p, st->waiting_pipe_buf,
                                     st->waiting_pipe_count);
            retval = (int64_t)got;
        } else if (p->writers_open == 0) {
            retval = 0;  /* EOF */
        } else {
            /* Pipe still empty and writers still open: leave parked. */
            continue;
        }

        printf("[pipe] WAKE reader pid=%d · %lld bytes\n",
               st->synthetic_pid, (long long)retval);
        pipe_resume_sotbox(st, retval);
        break;  /* L3b assumption: one blocked reader per pipe */
    }
}

void lucas_pipe_wake_writers(struct lucas_pipe *p) {
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = sotbox_get_slot(i);
        if (!st) continue;
        if (st->pipe_wait_kind != 2) continue;   /* 2 = write · independent of st->state */
        if (st->waiting_pipe != p) continue;

        int64_t retval;
        if (p->readers_open == 0) {
            retval = -(int64_t)32;  /* -EPIPE */
        } else {
            size_t put = pipe_write_fill(st, p, st->waiting_pipe_buf,
                                          st->waiting_pipe_count);
            retval = (int64_t)put;
        }

        printf("[pipe] WAKE writer pid=%d · %lld bytes\n",
               st->synthetic_pid, (long long)retval);
        pipe_resume_sotbox(st, retval);

        /* If we successfully filled space, wake any blocked reader too. */
        if (retval > 0) lucas_pipe_wake_readers(p);
        break;
    }
}

/* ---- Public read / write -------------------------------------------------- */

int64_t lucas_pipe_read(lucas_state_t *st, struct lucas_pipe *p,
                         uintptr_t client_vaddr, size_t count) {
    if (count == 0) return 0;

    if (p->count > 0) {
        size_t got = pipe_read_drain(st, p, client_vaddr, count);
        /* Draining freed space: wake any blocked writer. */
        lucas_pipe_wake_writers(p);
        return (int64_t)got;
    }
    if (p->writers_open == 0) {
        return 0;  /* EOF */
    }

    /* Block: park this sotBox until a writer puts data in. */
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)11; /* -ENOMEM */
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        return -(int64_t)11;
    }
    st->pipe_reply_cap     = cslot;   /* dedicated · futex/wait4 won't clobber it */
    st->waiting_pipe       = p;
    st->waiting_pipe_buf   = client_vaddr;
    st->waiting_pipe_count = count;
    st->pipe_wait_kind     = 1;       /* read */
    st->state              = SOTBOX_STATE_WAITING_FOR_PIPE_READ;
    printf("[pipe] PARK reader pid=%d count=%zu cslot=%lu\n",
           st->synthetic_pid, count, (unsigned long)cslot);
    return LUCAS_WAIT4_DEFERRED;
}

/* Kernel-buffer pipe write · used by sendfile(2) when the sink fd is the write
 * end of a pipe (busybox `cat FILE | grep X` does sendfile(pipe_wr, file)).
 * Copies from a kernel pointer (no client vspace) into the ring + wakes readers.
 * Returns bytes written (0 if the ring is full · the sendfile loop then stops;
 * canary pipe payloads are < the 4 KiB ring so this is non-truncating in
 * practice). Does NOT park — a single sendfile call drains what fits. */
int64_t lucas_pipe_write_kbuf(struct lucas_pipe *p, const void *buf, size_t count) {
    if (count == 0) return 0;
    if (p->readers_open == 0) return -(int64_t)32;  /* -EPIPE */
    size_t free_space = LUCAS_PIPE_BUF_SIZE - p->count;
    if (free_space == 0) return 0;
    size_t to_write = (count < free_space) ? count : free_space;
    const uint8_t *src = (const uint8_t *)buf;
    for (size_t i = 0; i < to_write; ++i) {
        p->buf[p->head] = src[i];
        p->head = (p->head + 1) % LUCAS_PIPE_BUF_SIZE;
    }
    p->count += to_write;
    lucas_pipe_wake_readers(p);
    iomux_check_epoll_waiters(p);
    iomux_check_poll_waiters(p);
    iomux_check_select_waiters(p);
    return (int64_t)to_write;
}

int64_t lucas_pipe_write(lucas_state_t *st, struct lucas_pipe *p,
                          uintptr_t client_vaddr, size_t count) {
    if (count == 0) return 0;
    if (p->readers_open == 0) return -(int64_t)32;  /* -EPIPE */

    size_t free_space = LUCAS_PIPE_BUF_SIZE - p->count;
    if (free_space > 0) {
        size_t put = pipe_write_fill(st, p, client_vaddr, count);
        /* Data in the pipe: wake any blocked reader. */
        lucas_pipe_wake_readers(p);
        /* U3 · wake any sotBox parked in epoll_wait on this pipe's read end. */
        iomux_check_epoll_waiters(p);
        iomux_check_poll_waiters(p);
        iomux_check_select_waiters(p);
        return (int64_t)put;
    }

    /* Buffer full: park this sotBox. */
    seL4_CPtr cslot;
    if (vka_cspace_alloc(st->vka, &cslot) != 0) return -(int64_t)11;
    cspacepath_t cpath;
    vka_cspace_make_path(st->vka, cslot, &cpath);
    int err = seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth);
    if (err) {
        vka_cspace_free(st->vka, cslot);
        return -(int64_t)11;
    }
    st->pipe_reply_cap     = cslot;   /* dedicated · futex/wait4 won't clobber it */
    st->waiting_pipe       = p;
    st->waiting_pipe_buf   = client_vaddr;
    st->waiting_pipe_count = count;
    st->pipe_wait_kind     = 2;       /* write */
    st->state              = SOTBOX_STATE_WAITING_FOR_PIPE_WRITE;
    printf("[pipe] PARK writer pid=%d count=%zu\n", st->synthetic_pid, count);
    return LUCAS_WAIT4_DEFERRED;
}

/* ---- Close helpers -------------------------------------------------------- */

void lucas_pipe_close_reader(struct lucas_pipe *p) {
    if (p->readers_open <= 0) return;
    p->readers_open--;
    printf("[pipe] close_reader: readers_open=%d writers_open=%d\n",
           p->readers_open, p->writers_open);
    if (p->readers_open == 0) {
        lucas_pipe_wake_writers(p);  /* wake blocked writers with -EPIPE */
        /* U3 · readers gone · writers waiting in epoll_wait now see EPOLLHUP. */
        iomux_check_epoll_waiters(p);
        iomux_check_poll_waiters(p);
        iomux_check_select_waiters(p);
        if (p->writers_open == 0) {
            p->in_use = false;
            printf("[pipe] freed\n");
        }
    }
}

void lucas_pipe_add_reader(struct lucas_pipe *p) { p->readers_open++; }
void lucas_pipe_add_writer(struct lucas_pipe *p) { p->writers_open++; }

/* ---- U3 · readiness predicates ------------------------------------------- */

int lucas_pipe_read_ready(const struct lucas_pipe *p) {
    if (!p) return 0;
    /* Bytes to drain · OR EOF (writers gone) · both are "readable". */
    return (p->count > 0) || (p->writers_open == 0);
}

int lucas_pipe_write_ready(const struct lucas_pipe *p) {
    if (!p) return 0;
    if (p->readers_open == 0) return 1;   /* writing would EPIPE · still wakeable */
    return (LUCAS_PIPE_BUF_SIZE - p->count) > 0;
}

int lucas_pipe_hup(const struct lucas_pipe *p) {
    if (!p) return 0;
    return (p->writers_open == 0) && (p->count == 0);
}

/* apt arc · would a read() block right now?  True iff the pipe is empty AND a
 * writer is still open (a blocking read would park; a non-blocking read must
 * instead return -EAGAIN).  Empty + writers-gone is EOF (read returns 0, never
 * blocks), so it is NOT a would-block. */
int lucas_pipe_would_block_read(const struct lucas_pipe *p) {
    if (!p) return 0;
    return (p->count == 0) && (p->writers_open != 0);
}

void lucas_pipe_close_writer(struct lucas_pipe *p) {
    if (p->writers_open <= 0) return;
    p->writers_open--;
    printf("[pipe] close_writer: readers_open=%d writers_open=%d\n",
           p->readers_open, p->writers_open);
    if (p->writers_open == 0) {
        lucas_pipe_wake_readers(p);  /* wake blocked readers with EOF=0 */
        /* U3 · writers gone · readers in epoll_wait observe EOF/EPOLLHUP. */
        iomux_check_epoll_waiters(p);
        iomux_check_poll_waiters(p);
        iomux_check_select_waiters(p);
        if (p->readers_open == 0) {
            p->in_use = false;
            printf("[pipe] freed\n");
        }
    }
}
