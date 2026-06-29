/*
 * sotOs · LUCAS · U2 · threading helpers.
 *
 * Two responsibilities:
 *
 *   1. Futex waiter queue · enqueue / dequeue by userspace address.
 *      Bounded array (state.futex_waiters[32]).  enqueue saves a reply
 *      cap so a later FUTEX_WAKE can seL4_Send to it.
 *
 *      PR 12 widened the queue to 32 slots (was 16 · too tight for
 *      pthread_cond_broadcast with 3+ waiters), added a per-waiter
 *      bitset filter for FUTEX_WAIT_BITSET/WAKE_BITSET, and grew
 *      helpers for FUTEX_REQUEUE / CMP_REQUEUE / WAKE_OP so glibc/musl
 *      pthread_cond_* + pthread_rwlock fast paths terminate.
 *
 *   2. TCB allocation for clone(CLONE_VM | CLONE_THREAD) · alloc a fresh
 *      TCB that shares the caller's vspace and cnode, set IP/SP/TLS,
 *      Resume.  Bookkeeping (cap stored in state.thread_list[]) lets the
 *      sotbox tear them down later.  Each thread also gets a unique
 *      synthetic_tid from state.next_tid.
 *
 * NOTE: per coordinator convention these helpers are top-of-file in this
 * NEW file · the handlers (handlers_python.c / handlers_proc.c) must
 * stay free of file-scope additions, so we expose entry points here.
 */

#include "state.h"
#include <lucas/syscalls.h>
#include <sel4/sel4.h>
#include <sel4utils/api.h>
#include <sel4utils/mapping.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <simple/simple.h>
#include <stdio.h>
#include <string.h>

/* M2-bug-1 · Per-thread IPC buffer.
 *
 * The primary TCB's IPC buffer lives at 0x7ffff1000000 (see
 * lucas_client_setup).  Each additional thread cloned via
 * CLONE_VM|CLONE_THREAD gets its own page at
 *   THREAD_IPC_BASE + n_threads * THREAD_IPC_STRIDE
 * mapped into the same (shared) client vspace, so parent + children
 * can ride the seL4 IPC fastpath concurrently without trashing each
 * other's message registers / extra caps.
 *
 * 8 slots reserved (matching state.thread_list[8]) · final mapped
 * range is 0x7ffff1001000..0x7ffff1009000, comfortably below the
 * stack region. */
#define THREAD_IPC_BASE   0x7ffff1001000UL
#define THREAD_IPC_STRIDE 0x1000UL

/* OBSD-ε OMALLOC · bounded-array alignment asserts (defense-in-depth).
 * Verify the threading tables are sized so memset on release is well-
 * defined, and that the bounds in this file (literal 8 / 16) match the
 * actual array sizes declared in state.h.
 *
 * PR 13 · thread_list[] is now a struct array (was bare seL4_CPtr[8]) so
 * each slot also carries procd_tid / robust_list_head / clear_tid_ptr.
 * The 8-slot bound stays the same so the IPC-buffer stride below (and
 * the n_threads <= 8 fast path) continues to apply.  The "aligned to 8
 * bytes" assert remains valid because every field in the struct is at
 * least 4-byte aligned and the largest field is 8-byte. */
_Static_assert((sizeof(((lucas_state_t *)0)->thread_list) % 8) == 0,
               "OBSD-ε: thread_list must be 8-byte aligned");
_Static_assert((sizeof(((lucas_state_t *)0)->thread_list) /
                 sizeof(((lucas_state_t *)0)->thread_list[0])) == 16,
               "OBSD-ε: thread_list must have 16 slots");
/* PR 12 · pthread_cond_broadcast with N threads enqueues N waiters
 * simultaneously on the cond.  glibc/musl cap unique cond waiters at
 * runtime via thread count, but a single fixture can stack 8+ waiters
 * across mutex + cond + rwlock fast paths.  Bumping from 16 → 32 keeps
 * the bounded-no-malloc invariant while giving headroom for the
 * pthread_cond_broadcast smoke + future rwlock fixtures.  Whenever
 * this constant is changed, update both the array literal in state.h
 * AND the literal `32` in the loop bounds below. */
_Static_assert((sizeof(((lucas_state_t *)0)->futex_waiters) /
                 sizeof(((lucas_state_t *)0)->futex_waiters[0])) == 32,
               "OBSD-ε: futex_waiters must have 32 slots");
#define LUCAS_FUTEX_WAITERS_MAX 32

/* --- futex waiter queue ------------------------------------------------- */

/* PR 12 · internal helper · wake the i-th waiter (already known matching
 * uaddr + bitset by caller).  Sends the 0-reply on the saved cap, bumps
 * the waiter's RIP past syscall + sets rax=0, restores state machine,
 * frees the cslot, and zeroes the queue entry.  No-op if the slot is
 * already free.  Extracted from the body of the original lucas_futex_wake
 * so it can be reused by REQUEUE (which wakes some waiters then moves
 * others to a different uaddr).  Returns 1 if a waiter was woken, 0
 * otherwise (slot already free). */
static int futex_wake_slot(lucas_state_t *st, int i) {
    if (!st->futex_waiters[i].in_use) return 0;

    seL4_CPtr cap = st->futex_waiters[i].reply_cap;

    /* Look up the waiter's logical sotbox state via slot table.
     *
     * PR 12 · the TCB register fixup below (rax=0, rip+=2) is only
     * applied when the waiter is a SINGLE-THREADED sotbox (n_threads
     * == 0).  In single-thread mode `waiter->client_tcb` IS the
     * waiter's TCB and the fixup matches the seL4_Send unblock path.
     *
     * In multi-thread mode (n_threads > 0, e.g. procd-cond-test or any
     * pthread_cond_broadcast) ALL threads share the same lucas_state ·
     * `waiter->client_tcb` is the PARENT's TCB, NOT the worker's TCB
     * that's actually parked.  The worker's reply cap (saved at
     * FUTEX_WAIT enqueue time) targets the correct TCB, so the
     * subsequent seL4_Send already handles rip/rax for the receiver.
     * Doing the register fixup on the parent's TCB at this moment
     * corrupts the parent's running state (the main thread that just
     * called WAKE) and prevents post-wake forward progress.
     *
     * The state-machine reset (WAITING_FOR_FUTEX → RUNNING + clear
     * waiting_reply_cap) is benign in both modes because it operates
     * on the shared sotbox state and only affects the wait4 deferred
     * reply path · we still skip it when state != WAITING_FOR_FUTEX. */
    extern lucas_state_t *sotbox_get_slot(int idx);
    lucas_state_t *waiter = sotbox_get_slot(st->futex_waiters[i].owner_slot);
    if (waiter) {
        /* Restore the WOKEN THREAD's registers so its FUTEX_WAIT returns 0
         * (woken) and resumes on its OWN preserved stack.  Use the per-waiter
         * parked TCB — in a multi-thread box the parked thread may be a worker,
         * NOT client_tcb (the main thread).
         *
         * This MUST run in multi-thread mode too: the old code skipped it for
         * n_threads>0 and relied on the bare seL4_Send below to resume the
         * thread "unchanged" so it re-executes the syscall — but a bare fault
         * reply does NOT restore the GP registers, so the woken thread came
         * back with rsp=0 and faulted on its next `call` (the GTK3 pthread
         * wall: a worker WAKEs the main thread → main resumed rsp=0 → VMFault).
         * Writing the full register set here (as the single-thread path always
         * did) is what makes the resume correct. */
        seL4_CPtr ptcb = st->futex_waiters[i].parked_tcb;
        if (!ptcb) ptcb = waiter->client_tcb;   /* legacy entries / single-thread */
        seL4_UserContext regs;
        int rerr = seL4_TCB_ReadRegisters(ptcb, false, 0, 18, &regs);
        if (rerr == 0) {
            regs.rax = 0;
            regs.rip += 2;
            regs.rcx = regs.rip;
            regs.r11 = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
            printf("[l:wr-threading:91] tcb=%lu rax=0x%lx rip=0x%lx (futex_wake)\n",
                   (unsigned long)ptcb,
                   (unsigned long)regs.rax,
                   (unsigned long)regs.rip);
#endif
            seL4_TCB_WriteRegisters(ptcb, false, 0, 18, &regs);
        }
        /* Restore state machine. */
        if (waiter->state == SOTBOX_STATE_WAITING_FOR_FUTEX) {
            waiter->state             = SOTBOX_STATE_RUNNING;
            waiter->waiting_reply_cap = 0;
        }
    }

    /* Reply to unblock the waiter. */
    seL4_Send(cap, seL4_MessageInfo_new(0, 0, 0, 0));

    /* Free the cslot we minted for SaveCaller. */
    vka_cspace_free(st->vka, cap);

    st->futex_waiters[i].in_use     = 0;
    st->futex_waiters[i].addr       = 0;
    st->futex_waiters[i].reply_cap  = 0;
    st->futex_waiters[i].owner_slot = -1;
    st->futex_waiters[i].bitset     = 0;
    if (st->n_futex_waiters > 0) --st->n_futex_waiters;
    /* OBSD-ε OMALLOC · junk on free · zero the whole waiter slot AFTER
     * the queue bookkeeping above so a future UAF cannot misuse a stale
     * reply_cap or owner_slot index.  Defense-in-depth. */
    memset(&st->futex_waiters[i], 0, sizeof(st->futex_waiters[i]));
    return 1;
}

/* Enqueue (uaddr, reply_cap, owner_slot, bitset) on the futex waiter
 * queue.  Returns 0 on success, -1 if the queue is full.
 *
 * PR 12 · bitset defaults to ~0u when callers pass 0 (legacy FUTEX_WAIT
 * path · "match every WAKE/WAKE_BITSET").  WAIT_BITSET callers pass the
 * uapi val3 verbatim. */
int lucas_futex_enqueue(lucas_state_t *st, uint64_t uaddr,
                        seL4_CPtr reply_cap, int owner_slot,
                        uint32_t bitset, seL4_CPtr parked_tcb) {
    if (bitset == 0) bitset = ~(uint32_t)0;
    for (int i = 0; i < LUCAS_FUTEX_WAITERS_MAX; ++i) {
        if (!st->futex_waiters[i].in_use) {
            st->futex_waiters[i].addr       = uaddr;
            st->futex_waiters[i].reply_cap  = reply_cap;
            st->futex_waiters[i].owner_slot = owner_slot;
            st->futex_waiters[i].in_use     = 1;
            st->futex_waiters[i].bitset     = bitset;
            st->futex_waiters[i].parked_tcb = parked_tcb;  /* the waiting THREAD */
            if (st->n_futex_waiters < LUCAS_FUTEX_WAITERS_MAX)
                ++st->n_futex_waiters;
            return 0;
        }
    }
    return -1;
}

/* PR 12 · WAKE_BITSET path · wake up to `max_wake` waiters on `uaddr`
 * whose stored bitset has any bit in common with `bitset`.  The legacy
 * lucas_futex_wake() is a thin wrapper that passes ~0u so every waiter
 * matches.  Returns the number of waiters actually woken. */
int lucas_futex_wake_bitset(lucas_state_t *st, uint64_t uaddr,
                              int max_wake, uint32_t bitset) {
    if (bitset == 0) return 0;
    int woken = 0;
    for (int i = 0; i < LUCAS_FUTEX_WAITERS_MAX && woken < max_wake; ++i) {
        if (!st->futex_waiters[i].in_use) continue;
        if (st->futex_waiters[i].addr != uaddr) continue;
        if ((st->futex_waiters[i].bitset & bitset) == 0) continue;
        if (futex_wake_slot(st, i)) ++woken;
    }
    return woken;
}

/* Legacy FUTEX_WAKE wrapper · matches every waiter regardless of bitset.
 * Kept for binary compatibility with the original signature; new call
 * sites should use lucas_futex_wake_bitset directly. */
int lucas_futex_wake(lucas_state_t *st, uint64_t uaddr, int max_wake) {
    return lucas_futex_wake_bitset(st, uaddr, max_wake, ~(uint32_t)0);
}

/* PR 12 · FUTEX_REQUEUE / FUTEX_CMP_REQUEUE.
 *
 * Wake `nr_wake` waiters on `uaddr` (full bitset match), then move up
 * to `nr_requeue` remaining waiters from `uaddr` to `uaddr2` (no wake,
 * just rewrite their `addr` field).  CMP_REQUEUE additionally requires
 * that the current value at `uaddr` equals `cmpval` · returns -EAGAIN
 * otherwise to match the kernel's drop-on-race semantics.
 *
 * Linux returns the SUM (woken + requeued).  Glibc/musl pthread_cond
 * uses this to splice the cond's wait queue onto the mutex's wait queue
 * on signal/broadcast so woken waiters contend on the mutex rather than
 * thundering. */
int lucas_futex_requeue(lucas_state_t *st, uint64_t uaddr, int nr_wake,
                          uint64_t uaddr2, int nr_requeue,
                          int check_cmp, uint32_t cmpval) {
    if (check_cmp) {
        /* Read the userspace value at uaddr · if it doesn't equal
         * cmpval, the cond may have been signaled before us, return
         * -EAGAIN so the caller spins.  We read via the client's
         * copy_from helper which validates the address. */
        extern int lucas_copy_from_client(lucas_state_t *st,
                                            uintptr_t client_vaddr,
                                            void *buf, size_t size);
        uint32_t cur = 0;
        if (lucas_copy_from_client(st, (uintptr_t)uaddr,
                                    &cur, sizeof(cur)) != 0) {
            return -14;  /* -EFAULT */
        }
        if (cur != cmpval) return -11;  /* -EAGAIN */
    }

    int woken = 0, requeued = 0;
    for (int i = 0; i < LUCAS_FUTEX_WAITERS_MAX; ++i) {
        if (!st->futex_waiters[i].in_use) continue;
        if (st->futex_waiters[i].addr != uaddr) continue;
        if (woken < nr_wake) {
            if (futex_wake_slot(st, i)) ++woken;
        } else if (requeued < nr_requeue) {
            /* Move this waiter to uaddr2 · do NOT wake.  A later WAKE
             * on uaddr2 will fire futex_wake_slot on this entry. */
            st->futex_waiters[i].addr = uaddr2;
            ++requeued;
        } else {
            break;
        }
    }
    return woken + requeued;
}

/* PR 12 · FUTEX_WAKE_OP.
 *
 * Atomic op on `uaddr2` then wake `nr_wake` on `uaddr1`; if a predicate
 * on the pre-op value at `uaddr2` holds, additionally wake `nr_wake2`
 * on `uaddr2`.  val3 encodes (opcode, oparg, cmp, cmparg) per
 * include/uapi/linux/futex.h:
 *
 *   bits 28-31 : opcode  (SET / ADD / OR / ANDN / XOR; high bit = shift)
 *   bits 24-27 : cmp     (EQ / NE / LT / LE / GT / GE)
 *   bits 12-23 : oparg   (12-bit)
 *   bits  0-11 : cmparg  (12-bit)
 *
 * If the top bit of the opcode field is set, oparg is interpreted as a
 * shift amount (op = 1 << oparg).
 *
 * Returns total wakeups (sum of both addrs) on success, -EINVAL on bad
 * opcode/cmp.  Used by glibc pthread_cond_signal/broadcast plus a few
 * rwlock variants. */
int lucas_futex_wake_op(lucas_state_t *st, uint64_t uaddr, int nr_wake,
                         uint64_t uaddr2, int nr_wake2, uint32_t val3) {
    extern int lucas_copy_from_client(lucas_state_t *st,
                                        uintptr_t client_vaddr,
                                        void *buf, size_t size);
    extern int lucas_copy_to_client(lucas_state_t *st,
                                      uintptr_t client_vaddr,
                                      const void *host_buf, size_t len);

    uint32_t old = 0;
    if (lucas_copy_from_client(st, (uintptr_t)uaddr2,
                                &old, sizeof(old)) != 0) {
        return -14;  /* -EFAULT */
    }

    int opcode = (int)((val3 >> 28) & 0xf);
    int oparg  = (int)((val3 >> 12) & 0xfff);
    int cmp    = (int)((val3 >> 24) & 0xf);
    int cmparg = (int)(val3 & 0xfff);

    /* High bit of opcode (bit 31 of val3, bit 3 of the 4-bit opcode
     * field) means "interpret oparg as a shift amount". */
    int shift = (opcode & 0x8);
    opcode &= 0x7;
    if (shift) oparg = 1 << oparg;

    /* PR 12 code review · validate BOTH opcode AND cmp upfront, BEFORE
     * mutating uaddr2.  Previously a cmp out of range (>5) caused us to
     * write newv to uaddr2 and then return -EINVAL, leaving torn state
     * visible to userspace.  Catch the invalid case while uaddr2 is
     * still untouched. */
    if (opcode > 4) return -22;  /* -EINVAL */
    if (cmp > 5)    return -22;  /* -EINVAL */

    uint32_t newv = old;
    switch (opcode) {
        case 0: newv = (uint32_t)oparg;          break;  /* FUTEX_OP_SET */
        case 1: newv = old + (uint32_t)oparg;    break;  /* FUTEX_OP_ADD */
        case 2: newv = old | (uint32_t)oparg;    break;  /* FUTEX_OP_OR  */
        case 3: newv = old & ~(uint32_t)oparg;   break;  /* FUTEX_OP_ANDN */
        case 4: newv = old ^ (uint32_t)oparg;    break;  /* FUTEX_OP_XOR */
    }
    if (lucas_copy_to_client(st, (uintptr_t)uaddr2,
                              &newv, sizeof(newv)) != 0) {
        return -14;  /* -EFAULT */
    }

    int ret = lucas_futex_wake_bitset(st, uaddr, nr_wake, ~(uint32_t)0);

    int cond;
    switch (cmp) {
        case 0: cond = (old == (uint32_t)cmparg); break;  /* CMP_EQ */
        case 1: cond = (old != (uint32_t)cmparg); break;  /* CMP_NE */
        case 2: cond = (old <  (uint32_t)cmparg); break;  /* CMP_LT */
        case 3: cond = (old <= (uint32_t)cmparg); break;  /* CMP_LE */
        case 4: cond = (old >  (uint32_t)cmparg); break;  /* CMP_GT */
        case 5: cond = (old >= (uint32_t)cmparg); break;  /* CMP_GE */
        default: cond = 0;  /* unreachable · validated above */
    }
    if (cond) {
        ret += lucas_futex_wake_bitset(st, uaddr2, nr_wake2, ~(uint32_t)0);
    }
    return ret;
}

/* --- thread cleanup on sotBox exit --------------------------------------- */

/* PR 13 · walk the dying thread's robust_list, mark every owned futex
 * with FUTEX_OWNER_DIED (bit 30, 0x40000000), and wake one waiter on
 * each.  Linux ABI · include/uapi/linux/futex.h:
 *
 *   struct robust_list_head {
 *       struct robust_list *list;           // +0
 *       long                futex_offset;   // +8
 *       struct robust_list *list_op_pending;// +16
 *   };
 *   struct robust_list { struct robust_list *next; };
 *
 * Each entry's lock word lives at (entry_addr + futex_offset).  We bound
 * the walk by ROBUST_WALK_LIMIT to defend against a malicious circular
 * list.  All copies use lucas_copy_{from,to}_client which validate the
 * userspace mapping · a missing page just stops the walk early. */
#define ROBUST_WALK_LIMIT 2048
#define FUTEX_OWNER_DIED  0x40000000u
#define FUTEX_TID_MASK    0x3FFFFFFFu

void lucas_walk_robust_list(lucas_state_t *st, uint64_t head_ptr,
                              uint32_t dying_tid) {
    if (head_ptr == 0) return;
    extern int lucas_copy_from_client(lucas_state_t *st,
                                        uintptr_t client_vaddr,
                                        void *buf, size_t size);
    extern int lucas_copy_to_client(lucas_state_t *st,
                                      uintptr_t client_vaddr,
                                      const void *src_buf, size_t size);
    extern int lucas_futex_wake_bitset(lucas_state_t *st, uint64_t uaddr,
                                         int max_wake, uint32_t bitset);
    /* head[0] = list, head[1] = futex_offset, head[2] = list_op_pending */
    uint64_t head[3] = { 0 };
    if (lucas_copy_from_client(st, (uintptr_t)head_ptr,
                                 head, sizeof(head)) != 0) {
        printf("[lucas] robust_walk · head 0x%lx unreadable · skip\n",
               (unsigned long)head_ptr);
        return;
    }
    uint64_t cur     = head[0];
    int64_t  ofs     = (int64_t)head[1];
    uint64_t pending = head[2];
    int marked = 0;
    int safety = 0;
    while (cur != 0 && cur != head_ptr && safety < ROBUST_WALK_LIMIT) {
        uint64_t lock_addr = (uint64_t)((int64_t)cur + ofs);
        uint32_t lock_word = 0;
        if (lucas_copy_from_client(st, (uintptr_t)lock_addr,
                                     &lock_word, sizeof(lock_word)) == 0) {
            uint32_t holder = lock_word & FUTEX_TID_MASK;
            if (holder == dying_tid) {
                /* Set OWNER_DIED bit, write back, then wake one. */
                lock_word |= FUTEX_OWNER_DIED;
                if (lucas_copy_to_client(st, (uintptr_t)lock_addr,
                                           &lock_word, sizeof(lock_word)) == 0) {
                    (void)lucas_futex_wake_bitset(st, lock_addr, 1, ~0u);
                    ++marked;
                }
            }
        }
        /* Advance to the next entry · read the `next` pointer at cur+0. */
        uint64_t next = 0;
        if (lucas_copy_from_client(st, (uintptr_t)cur,
                                     &next, sizeof(next)) != 0) {
            break;
        }
        cur = next;
        ++safety;
    }
    if (marked > 0) {
        printf("[lucas] robust_walk tid=%u head=0x%lx · marked %d futexes OWNER_DIED\n",
               dying_tid, (unsigned long)head_ptr, marked);
    }
    (void)pending;
}

/* L7 · suspend all child TCBs created via CLONE_VM | CLONE_THREAD.
 *
 * Without this, child threads created by pthread fixtures (e.g. M2 pthread
 * test) outlive the parent sotBox.  Their TCBs share the parent's fault
 * endpoint cap (badge = parent's slot_index + 1).  When the parent exits
 * and the slot is reused for a new sotBox (e.g. Python), the leftover
 * child's syscalls land in the new sotBox's badged endpoint and the orch
 * processes them as if they came from the new sotBox.
 *
 * The visible symptom (PR #65 L6 boot log) is a futex(FUTEX_WAKE, 0x402030)
 * storm "from Python" that is actually pthread_test's child stuck in a
 * tight loop after parent exit_group.  Suspending child TCBs cleanly stops
 * the loop and prevents the cross-sotBox contamination.
 *
 * PR 13 · before suspending, walk each thread's robust_list to mark owned
 * mutexes FUTEX_OWNER_DIED + wake one waiter (for join-on-exit semantics
 * in glibc/musl), and shadow-announce OP_THREAD_EXIT to procd so the
 * proc_t.n_threads counter + thread_t table stay coherent.  The
 * procd-side announce is best-effort (failure is logged, not fatal).
 *
 * We only Suspend, not Delete · the TCB object capabilities are still
 * referenced from thread_list[] and full teardown would require unmapping
 * each thread's IPC buffer page and freeing both the TCB and frame caps.
 * For now suspending is enough to silence the WAKE storm. */
void lucas_threads_suspend_all(lucas_state_t *st) {
    for (int i = 0; i < 16; ++i) {
        seL4_CPtr t = st->thread_list[i].tcb;
        if (t == 0) continue;

        /* PR 13 · walk this thread's robust list BEFORE suspending so any
         * owned futex gets OWNER_DIED + a wakeup before its TCB stops
         * running.  Order matters · suspending first would leave the
         * lock_word write racing with a peer's read; walking under the
         * still-running thread is safe because lucas is single-vCPU. */
        uint32_t pd_tid = st->thread_list[i].procd_tid;
        uint64_t rhead  = st->thread_list[i].robust_list_head;
        if (rhead != 0 && pd_tid != 0) {
            lucas_walk_robust_list(st, rhead, pd_tid);
        }

        /* PR 13 · also handle clear_tid_ptr · Linux semantics: kernel
         * writes 0 at clear_tid_ptr on thread exit and wakes one futex
         * waiter on the same address.  Joiners block on this address in
         * pthread_join() · without the wake they'd hang past parent
         * exit_group. */
        uint64_t ctp = st->thread_list[i].clear_tid_ptr;
        if (ctp != 0) {
            extern int lucas_copy_to_client(lucas_state_t *st,
                                              uintptr_t client_vaddr,
                                              const void *src_buf, size_t size);
            extern int lucas_futex_wake_bitset(lucas_state_t *st, uint64_t uaddr,
                                                 int max_wake, uint32_t bitset);
            uint32_t zero = 0;
            (void)lucas_copy_to_client(st, (uintptr_t)ctp, &zero, sizeof(zero));
            (void)lucas_futex_wake_bitset(st, ctp, 1, ~0u);
        }

        int err = seL4_TCB_Suspend(t);
        if (err) {
            printf("[lucas] threads_suspend_all: TCB_Suspend(cap=%lu) failed err=%d\n",
                   (unsigned long)t, err);
        }

        /* PR 13 · announce the per-thread exit to procd so proc_t.n_threads
         * decrements + the thread_t entry frees up.  Best-effort · a
         * failure here doesn't block the parent's exit_group. */
        if (st->procd_slot != 0 && pd_tid != 0) {
            extern int orch_procd_thread_exit(uint32_t caller_slot, uint32_t tid);
            int pd_rc = orch_procd_thread_exit(st->procd_slot, pd_tid);
            if (pd_rc < 0) {
                printf("[lucas] procd OP_THREAD_EXIT announce failed rc=%d "
                       "(tid=%u slot=%u)\n", pd_rc, pd_tid, st->procd_slot);
            }
        }

        /* Clear the slot so a re-entry into the same sotBox doesn't try
         * to suspend a stale cap. */
        st->thread_list[i].tcb              = 0;
        st->thread_list[i].procd_tid        = 0;
        st->thread_list[i].robust_list_head = 0;
        st->thread_list[i].clear_tid_ptr    = 0;
    }
    if (st->n_threads > 0) {
        printf("[lucas] threads_suspend_all · suspended %d child TCBs (slot=%d pid=%d)\n",
               st->n_threads, st->slot_index, st->synthetic_pid);
    }
    st->n_threads = 0;
    /* OBSD-ε OMALLOC · junk on free · zero the entire thread_list array
     * AFTER the per-slot Suspend + bookkeeping above.  The per-element
     * zero above is enough today (thread_list[] is small), but an
     * explicit array memset guarantees a future addition to the
     * "thread cleanup" path can't accidentally leave residue and keeps
     * the OBSD-ε contract uniform across all release sites. */
    memset(st->thread_list, 0, sizeof(st->thread_list));
}

/* --- thread create via CLONE_VM | CLONE_THREAD -------------------------- */

/* Allocate + configure a new TCB sharing parent->client_vspace and
 * parent->client_cnode.  IP = entry_pc (typically child_stack address
 * holding a return helper, but Linux convention is that child_stack is
 * already-allocated stack memory · the user code at the address pointed
 * to by *child_stack normally is the thread entry).  We follow what musl
 * expects: SP = child_stack, IP comes from the caller's clone return path.
 *
 * Linux pthread create uses a wrapper: clone() returns 0 in the child,
 * and __clone's stub then jumps to the start_routine.  For our model the
 * NEW thread MUST start executing at the same RIP as the parent's clone
 * syscall + 2 (post-syscall), but with rax = 0 and rsp = child_stack ·
 * exactly the fork semantics, only with vspace shared.
 *
 * Returns the new synthetic_tid on success, or -errno on failure. */
int64_t lucas_thread_clone(lucas_state_t *st,
                           uint64_t newsp, uint64_t tls,
                           uint64_t flags, uint64_t ctid) {
    /* PR 13 · the helper now receives ctid (child_tid_ptr from
     * lucas_sys_clone) so the procd OP_CLONE announce carries the
     * authoritative kernel-side address.  thread_list[slot].clear_tid_ptr
     * stashes the same value locally so the per-thread exit path can
     * issue the futex(addr, 1) wake without re-traversing the announce
     * round-trip. */

    if (st->n_threads >= 16) {
        printf("[clone] thread_list full · -EAGAIN\n");
        return -(int64_t)11;  /* -EAGAIN */
    }

    /* Allocate a fresh TCB. */
    vka_object_t tcb_obj;
    int err = vka_alloc_tcb(st->vka, &tcb_obj);
    if (err) {
        printf("[clone] vka_alloc_tcb failed err=%d · -ENOMEM\n", err);
        return -(int64_t)12;  /* -ENOMEM */
    }
    seL4_CPtr new_tcb = tcb_obj.cptr;

    /* M2-bug-1 · allocate a DEDICATED IPC buffer frame for the new TCB
     * and map it into the shared client vspace at a distinct vaddr.
     * Mirror lucas_client_setup: 4 KiB frame (12-bit size_bits) +
     * sel4utils_map_page_leaky.
     *
     * Previously this path reused the parent's IPC buffer
     * (st->client_ipc_buffer_frame @ 0x7ffff1000000), which is unsafe as
     * soon as either thread issues an IPC (the kernel writes message
     * registers / extra caps into the buffer).  Documented in
     * docs/M2-pthread-verification.md §4·A as the prime suspect for
     * the pthread fixture's parent rax=-9 corruption. */
    vka_object_t ipc_frame_obj;
    err = vka_alloc_frame(st->vka, 12, &ipc_frame_obj);
    if (err) {
        printf("[clone] IPC frame alloc failed err=%d · -ENOMEM\n", err);
        vka_free_object(st->vka, &tcb_obj);
        return -(int64_t)12;
    }
    seL4_CPtr ipc_frame_cap = ipc_frame_obj.cptr;

    uintptr_t ipc_vaddr =
        THREAD_IPC_BASE + (uintptr_t)st->n_threads * THREAD_IPC_STRIDE;
    err = sel4utils_map_page_leaky(st->vka, st->client_vspace,
                                    ipc_frame_cap, (void *)ipc_vaddr,
                                    seL4_ReadWrite, 1);
    if (err) {
        printf("[clone] IPC buffer map at 0x%lx failed err=%d\n",
               (unsigned long)ipc_vaddr, err);
        vka_free_object(st->vka, &ipc_frame_obj);
        vka_free_object(st->vka, &tcb_obj);
        return -(int64_t)5;  /* -EIO */
    }

    /* Configure: share parent's CSpace + VSpace, but bind a PRIVATE
     * IPC buffer.  Mirror lucas_client_setup: skip (64 - 4) bits for a
     * 4-bit CNode. */
    seL4_Word cspace_root_data = api_make_guard_skip_word(seL4_WordBits - 4);

    err = seL4_TCB_Configure(new_tcb,
                              /* fault_ep slot in client CSpace */ 1,
                              st->client_cnode,
                              cspace_root_data,
                              st->client_vspace,
                              seL4_NilData,
                              ipc_vaddr,
                              ipc_frame_cap);
    if (err) {
        printf("[clone] TCB_Configure failed err=%d\n", err);
        /* Frame is leaky-mapped · we cannot cleanly unmap without a
         * reservation.  Free the frame cap regardless; the orphaned PTE
         * will be cleared at sotbox teardown. */
        vka_free_object(st->vka, &ipc_frame_obj);
        vka_free_object(st->vka, &tcb_obj);
        return -(int64_t)5;  /* -EIO */
    }

    err = seL4_TCB_SetPriority(new_tcb,
                                simple_get_init_cap(st->simple, seL4_CapInitThreadTCB),
                                seL4_MaxPrio);
    if (err) {
        printf("[clone] SetPriority failed err=%d · non-fatal\n", err);
    }

    /* Read the CALLING thread's registers to clone the post-syscall PC.
     *
     * M0 fix · this MUST be the thread that issued the clone syscall, NOT
     * st->client_tcb (the main thread).  When a WORKER thread calls clone
     * (nested pthread_create — GLib's thread pool routinely spawns threads from
     * a worker), reading client_tcb gave the MAIN thread's registers, which are
     * typically parked deep inside a futex `syscall` in libc.  The child then
     * inherited the main thread's parked rip+2 (a syscall-wrapper epilogue) +
     * the worker's stack → it `ret`'d through a NULL continuation on the fresh
     * stack and jumped to 0x0 (the GTK heavy-widget worker-thread crash).  The
     * fault loop stashes the real caller in st->cur_fault_tcb right before
     * dispatch (matched by SP); use it so the child resumes at the caller's
     * actual __clone tail (`pop rdi; call *r9`), exactly like a main-thread
     * clone.  Fall back to client_tcb for the single-thread / unset case. */
    seL4_CPtr caller_tcb = st->cur_fault_tcb ? st->cur_fault_tcb : st->client_tcb;
    seL4_UserContext p_regs;
    err = seL4_TCB_ReadRegisters(caller_tcb, false, 0,
                                  sizeof(p_regs)/sizeof(seL4_Word), &p_regs);
    if (err) {
        printf("[clone] ReadRegisters(parent) failed err=%d\n", err);
        vka_free_object(st->vka, &ipc_frame_obj);
        vka_free_object(st->vka, &tcb_obj);
        return -(int64_t)5;
    }

    /* The new thread runs the caller's post-syscall code path with
     * rax = 0 (clone returns 0 in the child) and rsp = newsp. */
    p_regs.rax = 0;
    p_regs.rip = p_regs.rip + 2;   /* skip `syscall` */
    p_regs.rcx = p_regs.rip;
    p_regs.r11 = p_regs.rflags;
    if (newsp) p_regs.rsp = (seL4_Word)newsp;

#ifdef LUCAS_TRACE_L2_WR
    printf("[l:wr-threading:233] tcb=%lu rax=0x%lx rip=0x%lx (clone child)\n",
           (unsigned long)new_tcb,
           (unsigned long)p_regs.rax,
           (unsigned long)p_regs.rip);
#endif
    err = seL4_TCB_WriteRegisters(new_tcb, false, 0,
                                   sizeof(p_regs)/sizeof(seL4_Word), &p_regs);
    if (err) {
        printf("[clone] WriteRegisters(new) failed err=%d\n", err);
        vka_free_object(st->vka, &ipc_frame_obj);
        vka_free_object(st->vka, &tcb_obj);
        return -(int64_t)5;
    }

    /* If CLONE_SETTLS, set the new TCB's FS base to `tls`. */
    if (tls) {
        int terr = seL4_TCB_SetTLSBase(new_tcb, tls);
        if (terr) {
            printf("[clone] SetTLSBase(tls=0x%lx) failed err=%d · continuing\n",
                   (unsigned long)tls, terr);
        }
    }

    /* ADR-006 · flag the child as a Linux-ABI thread too (each clone/pthread
     * child can issue a colliding syscall, e.g. poll(timeout=-1), independently)
     * so the kernel routes ALL its syscalls to UnknownSyscall. */
    {
        int ferr = seL4_TCB_SetFlags(new_tcb, 0, seL4_TCBFlag_linuxABI).error;
        if (ferr) printf("[clone] SetFlags(linuxABI) failed err=%d on child tcb\n", ferr);
    }

    /* Resume the new TCB. */
    int rerr = seL4_TCB_Resume(new_tcb);
    if (rerr) {
        printf("[clone] TCB_Resume failed err=%d\n", rerr);
        vka_free_object(st->vka, &ipc_frame_obj);
        vka_free_object(st->vka, &tcb_obj);
        return -(int64_t)5;
    }

    /* Bookkeeping: record cap + allocate synthetic_tid.
     *
     * PR 13 · thread_list[] is now a struct array; capture the slot
     * index so subsequent fields (procd_tid, robust_list_head,
     * clear_tid_ptr) can be filled in below after the procd announce
     * returns. */
    int tid = ++st->next_tid;
    if (tid == 0) tid = ++st->next_tid;   /* avoid 0 */
    int slot_idx = st->n_threads++;
    st->thread_list[slot_idx].tcb              = new_tcb;
    st->thread_list[slot_idx].procd_tid        = 0;
    st->thread_list[slot_idx].robust_list_head = 0;
    st->thread_list[slot_idx].clear_tid_ptr    = 0;

    printf("[clone] thread create tid=%d shared_vspace=cap_%lu newsp=0x%lx tls=0x%lx ipc_buf=0x%lx\n",
           tid, (unsigned long)st->client_vspace,
           (unsigned long)newsp, (unsigned long)tls,
           (unsigned long)ipc_vaddr);

    /* PR 8 · shadow-announce the new thread to procd so it can allocate
     * the thread_t entry, bump owner.n_threads under the seqlock, and
     * publish PROCD_EV_THREAD_BORN.  The seL4 mechanics above are the
     * source of truth for the thread's actual execution · the announce
     * is informational for procd accounting + audit subscribers.
     *
     * PR 13 · capture the procd-assigned synthetic_tid into thread_list[slot]
     * so subsequent OP_SET_ROBUST / OP_THREAD_EXIT announces from this
     * same thread address the same thread_t entry.  PR 13 also threads
     * child_tid_ptr through this helper · the caller (lucas_sys_clone)
     * now passes ctid so the kernel-side robust + clear_tid bookkeeping
     * has a per-thread record. */
    if (st->procd_slot != 0) {
        extern int orch_procd_clone_thread(uint32_t caller_slot, uint64_t flags,
                                            uint64_t tls_, uint64_t child_tid_ptr,
                                            uint32_t *out_tid);
        uint32_t pd_tid = 0;
        int pd_rc = orch_procd_clone_thread(st->procd_slot, flags,
                                             tls, /* child_tid_ptr */ ctid,
                                             &pd_tid);
        if (pd_rc < 0) {
            printf("[lucas] procd OP_CLONE announce failed rc=%d · thread continues\n",
                   pd_rc);
        } else {
            st->thread_list[slot_idx].procd_tid     = pd_tid;
            st->thread_list[slot_idx].clear_tid_ptr = ctid;
            printf("[lucas] procd thread announced pd_tid=%u (owner_slot=%u local_tid=%d)\n",
                   pd_tid, st->procd_slot, tid);
        }
    }

    return (int64_t)tid;
}
