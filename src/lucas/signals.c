/*
 * sotOs · LUCAS · U1 signals · helpers for rt_sigaction + delivery loop.
 *
 * Owns the signal-frame builder, alt-stack accessor, and the in-fault-loop
 * delivery dispatcher.  The four handler bodies live in handlers_proc.c as
 * required by the batch coordinator; this file holds the shared logic those
 * bodies call into AND the function the fault loop invokes after each
 * syscall return to deliver a queued signal.
 *
 * Ground rules (per worker brief):
 *  - C11, no malloc, bounded arrays only.
 *  - Logs use "[signals]" prefix.
 *  - Linux x86_64 ABI: 64 signals, 8-byte sigset_t, kernel struct sigaction
 *    layout = { handler, flags, restorer, mask } (8+8+8+8 = 32 B).
 */

#include "state.h"
#include "handlers.h"
#include <lucas/linux_abi.h>

#include <sel4/sel4.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>

extern int g_orch_quiet;   /* v2.9 · operator `watch` quiet mode (suppress per-syscall spam) */

/* Forward declarations for copy helpers (defined in handlers_fs.c). */
int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                          const void *src_buf, size_t size);
int lucas_copy_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                            void *dst_buf, size_t size);

/* OBSD-ε OMALLOC · bounded-array alignment asserts (defense-in-depth).
 * Linux x86_64 has 64 signals, indexed 1..64 → array size 64.  Pending
 * queue is a small bounded buffer.  Sizes must be multiples of 8 so the
 * memset-on-release path on these slots is well-defined. */
_Static_assert((sizeof(((lucas_state_t *)0)->signal_handlers) /
                 sizeof(((lucas_state_t *)0)->signal_handlers[0])) == 64,
               "OBSD-ε: signal_handlers must have 64 slots");
_Static_assert((sizeof(((lucas_state_t *)0)->signal_handlers) % 8) == 0,
               "OBSD-ε: signal_handlers must be 8-byte aligned");
_Static_assert((sizeof(((lucas_state_t *)0)->pending_signals) % 8) == 0,
               "OBSD-ε: pending_signals must be 8-byte aligned");

/* Linux x86_64 sigprocmask "how" codes. */
#define LUCAS_SIG_BLOCK    0
#define LUCAS_SIG_UNBLOCK  1
#define LUCAS_SIG_SETMASK  2

/* Linux SA_* flag bits (subset). */
#define LUCAS_SA_NOCLDSTOP 0x00000001
#define LUCAS_SA_NODEFER   0x40000000
#define LUCAS_SA_RESTART   0x10000000
#define LUCAS_SA_SIGINFO   0x00000004
#define LUCAS_SA_ONSTACK   0x08000000
#define LUCAS_SA_RESTORER  0x04000000

/* Kernel ABI of struct sigaction (x86_64).  Matches what musl + glibc
 * marshal into the rt_sigaction syscall. */
struct lucas_k_sigaction {
    uint64_t handler;    /* sa_handler / sa_sigaction */
    uint64_t flags;      /* sa_flags · includes SA_RESTORER */
    uint64_t restorer;   /* sa_restorer · trampoline that issues rt_sigreturn */
    uint64_t mask;       /* sa_mask · 64-bit sigset */
};

/* Linux SIG_DFL / SIG_IGN anomalys (pointer-sized). */
#define LUCAS_SIG_DFL  0UL
#define LUCAS_SIG_IGN  1UL

/* Default action lookup · matches Linux for the signals user code installs.
 * Only signals listed here have a non-terminate default; everything else
 * terminates.  Return 1 = "ignore by default", 0 = "terminate by default". */
static int default_is_ignore(int sig) {
    switch (sig) {
        case 17:  /* SIGCHLD */
        case 18:  /* SIGCONT */
        case 23:  /* SIGURG */
        case 28:  /* SIGWINCH */
            return 1;
        default:
            return 0;
    }
}

/* Bit math helpers for the 64-bit sigset.  Signals are numbered 1..64; bit
 * (sig - 1) tracks them in our uint64_t.  Signal 0 is invalid input. */
static inline uint64_t sigmask_bit(int sig) {
    if (sig < 1 || sig > 64) return 0;
    return (uint64_t)1ULL << (sig - 1);
}

/* === rt_sigaction core ================================================ */

int64_t lucas_signals_rt_sigaction(lucas_state_t *st, int sig,
                                    uint64_t act_uptr, uint64_t oact_uptr,
                                    size_t sigsetsize) {
    if (sig < 1 || sig > 64) return -(int64_t)LX_EINVAL;
    /* SIGKILL (9) and SIGSTOP (19) cannot be caught/blocked. */
    if (sig == 9 || sig == 19) return -(int64_t)LX_EINVAL;
    if (sigsetsize != 8) return -(int64_t)LX_EINVAL;

    if (oact_uptr) {
        struct lucas_k_sigaction old = {
            .handler  = st->signal_handlers[sig - 1],
            .flags    = st->signal_flags[sig - 1],
            .restorer = st->signal_restorers[sig - 1],
            .mask     = st->signal_sa_mask[sig - 1],
        };
        if (lucas_copy_to_client(st, (uintptr_t)oact_uptr, &old, sizeof(old)) != 0)
            return -(int64_t)LX_EFAULT;
    }

    if (act_uptr) {
        struct lucas_k_sigaction newact;
        if (lucas_copy_from_client(st, (uintptr_t)act_uptr, &newact, sizeof(newact)) != 0)
            return -(int64_t)LX_EFAULT;
        st->signal_handlers[sig - 1]  = newact.handler;
        st->signal_flags[sig - 1]     = newact.flags;
        st->signal_restorers[sig - 1] = newact.restorer;
        st->signal_sa_mask[sig - 1]   = newact.mask;
        if (!g_orch_quiet)
        printf("[signals] rt_sigaction pid=%d sig=%d handler=0x%lx flags=0x%lx\n",
               st->synthetic_pid, sig,
               (unsigned long)newact.handler,
               (unsigned long)newact.flags);
        /* OBSD-ε OMALLOC · junk on free · when the client resets a signal
         * to the default disposition (SIG_DFL == 0), the handler slot is
         * effectively released.  Force the auxiliary fields to zero AFTER
         * the assignments above so future reads of this signal's slot
         * cannot observe stale flags, restorer ptr, or sa_mask bits left
         * over from a prior handler registration.  Defense-in-depth: the
         * client SHOULD pass zeros alongside SIG_DFL, but a buggy or
         * hostile caller could pass stale values · we drop them. */
        if (newact.handler == LUCAS_SIG_DFL) {
            st->signal_flags[sig - 1]     = 0;
            st->signal_restorers[sig - 1] = 0;
            st->signal_sa_mask[sig - 1]   = 0;
        }
    }
    return 0;
}

/* === rt_sigprocmask core ============================================== */

int64_t lucas_signals_rt_sigprocmask(lucas_state_t *st, int how,
                                      uint64_t set_uptr, uint64_t oset_uptr,
                                      size_t sigsetsize) {
    if (sigsetsize != 8) return -(int64_t)LX_EINVAL;

    if (oset_uptr) {
        uint64_t old = st->signal_mask;
        if (lucas_copy_to_client(st, (uintptr_t)oset_uptr, &old, sizeof(old)) != 0)
            return -(int64_t)LX_EFAULT;
    }
    if (set_uptr) {
        uint64_t in;
        if (lucas_copy_from_client(st, (uintptr_t)set_uptr, &in, sizeof(in)) != 0)
            return -(int64_t)LX_EFAULT;
        /* SIGKILL/SIGSTOP cannot be masked · strip them from any incoming mask. */
        in &= ~(sigmask_bit(9) | sigmask_bit(19));
        switch (how) {
            case LUCAS_SIG_BLOCK:    st->signal_mask |=  in; break;
            case LUCAS_SIG_UNBLOCK:  st->signal_mask &= ~in; break;
            case LUCAS_SIG_SETMASK:  st->signal_mask  =  in; break;
            default: return -(int64_t)LX_EINVAL;
        }
        if (!g_orch_quiet)
        printf("[signals] rt_sigprocmask pid=%d how=%d mask=0x%lx\n",
               st->synthetic_pid, how, (unsigned long)st->signal_mask);
    }
    return 0;
}

/* === sigaltstack core ================================================ */

/* Linux struct stack_t layout.  size_t is 8 bytes on x86_64. */
struct lucas_stack_t {
    uint64_t ss_sp;      /* base of the alt stack */
    int32_t  ss_flags;
    uint8_t  pad[4];
    uint64_t ss_size;
};

#define LUCAS_SS_DISABLE 2
#define LUCAS_MINSIGSTKSZ 2048

int64_t lucas_signals_sigaltstack(lucas_state_t *st,
                                   uint64_t ss_uptr, uint64_t oss_uptr) {
    if (oss_uptr) {
        struct lucas_stack_t old = {
            .ss_sp    = st->sigaltstack_sp,
            .ss_flags = st->sigaltstack_sp ? 0 : LUCAS_SS_DISABLE,
            .ss_size  = (uint64_t)st->sigaltstack_size,
        };
        if (lucas_copy_to_client(st, (uintptr_t)oss_uptr, &old, sizeof(old)) != 0)
            return -(int64_t)LX_EFAULT;
    }
    if (ss_uptr) {
        struct lucas_stack_t in;
        if (lucas_copy_from_client(st, (uintptr_t)ss_uptr, &in, sizeof(in)) != 0)
            return -(int64_t)LX_EFAULT;
        if (in.ss_flags & LUCAS_SS_DISABLE) {
            st->sigaltstack_sp   = 0;
            st->sigaltstack_size = 0;
        } else {
            if (in.ss_size < LUCAS_MINSIGSTKSZ) return -(int64_t)LX_EINVAL;
            st->sigaltstack_sp   = in.ss_sp;
            st->sigaltstack_size = (size_t)in.ss_size;
        }
        printf("[signals] sigaltstack pid=%d sp=0x%lx size=%lu\n",
               st->synthetic_pid,
               (unsigned long)st->sigaltstack_sp,
               (unsigned long)st->sigaltstack_size);
    }
    return 0;
}

/* === Signal frame layout =============================================
 *
 * Minimal rt-signal frame we build on the user stack when delivering.
 * NOT bit-compatible with the kernel struct rt_sigframe (which carries
 * full siginfo_t + ucontext_t).  We only need enough state to round-trip
 * RIP, RSP, RFLAGS, and the general-purpose register file so rt_sigreturn
 * can restore the pre-signal context.
 *
 * Layout (16-byte aligned · grows toward lower addresses):
 *
 *   [SP_after_push - 8]:   "magic"   (anomaly for validation)
 *   ...
 *   [SP_after_push +  0]:  saved_rip   (caller IP at delivery time)
 *   [SP_after_push +  8]:  saved_rsp
 *   [SP_after_push + 16]:  saved_rflags
 *   [SP_after_push + 24]:  saved_rax
 *   [SP_after_push + 32]:  saved_rbx
 *   [SP_after_push + 40]:  saved_rcx
 *   [SP_after_push + 48]:  saved_rdx
 *   [SP_after_push + 56]:  saved_rdi
 *   [SP_after_push + 64]:  saved_rsi
 *   [SP_after_push + 72]:  saved_rbp
 *   [SP_after_push + 80]:  saved_r8
 *   [SP_after_push + 88]:  saved_r9
 *   [SP_after_push + 96]:  saved_r10
 *   [SP_after_push + 104]: saved_r11
 *   [SP_after_push + 112]: saved_r12
 *   [SP_after_push + 120]: saved_r13
 *   [SP_after_push + 128]: saved_r14
 *   [SP_after_push + 136]: saved_r15
 *   [SP_after_push + 144]: saved_signal_mask
 *   [SP_after_push + 152]: magic
 *   [SP_after_push + 160]: return-address slot · trampoline / restorer
 *
 * Total = 168 B (already 8-aligned).  We pad to a multiple of 16 by
 * leaving the bottom slot as the trampoline return address so that when
 * the handler issues `ret`, the CPU pops the restorer and jumps to it.
 */
#define LUCAS_SIGFRAME_MAGIC 0x5347464D454D4F73ULL  /* "sotOMEMFGS" */

struct lucas_sigframe {
    uint64_t saved_rip;
    uint64_t saved_rsp;
    uint64_t saved_rflags;
    uint64_t saved_rax;
    uint64_t saved_rbx;
    uint64_t saved_rcx;
    uint64_t saved_rdx;
    uint64_t saved_rdi;
    uint64_t saved_rsi;
    uint64_t saved_rbp;
    uint64_t saved_r8;
    uint64_t saved_r9;
    uint64_t saved_r10;
    uint64_t saved_r11;
    uint64_t saved_r12;
    uint64_t saved_r13;
    uint64_t saved_r14;
    uint64_t saved_r15;
    uint64_t saved_signal_mask;
    uint64_t magic;
};

/* === Delivery dispatcher ==============================================
 *
 * Pick a deliverable pending signal, build the frame on the user stack,
 * rewrite `regs` so the post-syscall WriteRegisters lands us at the
 * handler.  Returns 1 if a signal was delivered (caller should NOT
 * advance RIP / set RAX; we already did), 0 otherwise.
 */
int lucas_signals_try_deliver(lucas_state_t *st, seL4_UserContext *regs) {
    if (st->in_signal_handler) return 0;     /* nested delivery suppressed */
    if (st->n_pending <= 0)    return 0;

    /* Scan in FIFO order; deliver the first signal whose handler is
     * installed AND not currently masked. */
    int picked_idx = -1;
    int picked_sig = 0;
    for (int i = 0; i < st->n_pending; ++i) {
        int sig = st->pending_signals[i];
        if (sig < 1 || sig > 64) continue;
        uint64_t bit = sigmask_bit(sig);
        if (st->signal_mask & bit) continue;
        uint64_t h = st->signal_handlers[sig - 1];
        if (h == LUCAS_SIG_DFL) {
            /* No handler installed.  If default is "ignore", drop;
             * otherwise the signal should terminate.  For δ-1 we drop
             * and log · termination is L11+. */
            (void)default_is_ignore(sig);
            continue;
        }
        if (h == LUCAS_SIG_IGN) continue;
        picked_idx = i;
        picked_sig = sig;
        break;
    }
    if (picked_sig == 0) return 0;

    /* Compact the queue · remove picked entry. */
    for (int i = picked_idx; i < st->n_pending - 1; ++i)
        st->pending_signals[i] = st->pending_signals[i + 1];
    st->n_pending -= 1;
    /* OBSD-ε OMALLOC · junk on free · the slot now past n_pending is a
     * released queue entry.  Zero it AFTER the compaction so a future
     * over-read of pending_signals[n_pending] cannot observe a stale
     * signal number from the previous queue state. */
    if (st->n_pending >= 0 &&
        (size_t)st->n_pending < sizeof(st->pending_signals) /
                                sizeof(st->pending_signals[0])) {
        st->pending_signals[st->n_pending] = 0;
    }

    /* Decide whether to use the alt stack. */
    uint64_t flags = st->signal_flags[picked_sig - 1];
    uint64_t base_sp;
    if ((flags & LUCAS_SA_ONSTACK) && st->sigaltstack_sp != 0 &&
        st->sigaltstack_size >= LUCAS_MINSIGSTKSZ) {
        base_sp = st->sigaltstack_sp + st->sigaltstack_size;
    } else {
        base_sp = regs->rsp;
    }

    /* Build the frame.  We reserve 16 B "red-zone scratch" below the
     * existing stack to be safe, then place the frame, then leave the
     * restorer address as the lowest slot so the handler's `ret` jumps
     * into the trampoline.  Final SP (handler's RSP on entry) must be
     * 16-aligned per the x86_64 SysV ABI, with the return address at
     * (SP).  Our frame size is 160 B (8-aligned); we offset by 8 to get
     * the trampoline-return slot 16-aligned at handler entry. */
    const size_t frame_bytes = sizeof(struct lucas_sigframe);  /* 160 */
    /* Pass the user-provided restorer through verbatim.  Linux x86_64
     * requires SA_RESTORER + a real trampoline (musl + glibc always set
     * both); we trust the stored pointer.  If a binary installs a handler
     * with sa_restorer = 0, the handler's terminating `ret` will fault on
     * RIP=0 (faithful to what Linux would do), and the fault is observable
     * via the standard VM-fault path. */
    uint64_t restorer = st->signal_restorers[picked_sig - 1];

    /* Reserve red zone (128 B) per System V ABI. */
    uint64_t sp = base_sp - 128;
    /* Push trampoline-return slot (8 B) then the frame above it. */
    sp -= 8;
    uint64_t restorer_slot_addr = sp;
    sp -= frame_bytes;
    /* Force 16-byte alignment of the handler's RSP entry point.  The
     * ret-address slot lives at (sp - 0), so we want (sp) % 16 == 0
     * after we account for the implicit `call` mismatch · easiest: align
     * sp downward to 16 B. */
    sp &= ~(uint64_t)0xF;
    /* After alignment, the restorer slot may have moved relative to the
     * frame; recompute by stacking frame ABOVE the restorer slot
     * deterministically. */
    uint64_t frame_addr   = sp;
    restorer_slot_addr    = frame_addr - 8;
    uint64_t handler_rsp  = restorer_slot_addr;   /* handler sees ret-addr at (rsp) */

    struct lucas_sigframe frame;
    memset(&frame, 0, sizeof(frame));
    frame.saved_rip        = regs->rip;
    frame.saved_rsp        = regs->rsp;
    frame.saved_rflags     = regs->rflags;
    frame.saved_rax        = regs->rax;
    frame.saved_rbx        = regs->rbx;
    frame.saved_rcx        = regs->rcx;
    frame.saved_rdx        = regs->rdx;
    frame.saved_rdi        = regs->rdi;
    frame.saved_rsi        = regs->rsi;
    frame.saved_rbp        = regs->rbp;
    frame.saved_r8         = regs->r8;
    frame.saved_r9         = regs->r9;
    frame.saved_r10        = regs->r10;
    frame.saved_r11        = regs->r11;
    frame.saved_r12        = regs->r12;
    frame.saved_r13        = regs->r13;
    frame.saved_r14        = regs->r14;
    frame.saved_r15        = regs->r15;
    frame.saved_signal_mask = st->signal_mask;
    frame.magic            = LUCAS_SIGFRAME_MAGIC;

    if (lucas_copy_to_client(st, (uintptr_t)frame_addr, &frame, sizeof(frame)) != 0) {
        printf("[signals] deliver pid=%d sig=%d · frame copy_to_client FAILED · skip\n",
               st->synthetic_pid, picked_sig);
        return 0;
    }
    if (lucas_copy_to_client(st, (uintptr_t)restorer_slot_addr,
                              &restorer, sizeof(restorer)) != 0) {
        printf("[signals] deliver pid=%d sig=%d · restorer copy_to_client FAILED · skip\n",
               st->synthetic_pid, picked_sig);
        return 0;
    }

    /* Apply the handler's sa_mask (and the signal itself unless SA_NODEFER).
     * We restore the saved mask in rt_sigreturn. */
    uint64_t new_mask = st->signal_mask | st->signal_sa_mask[picked_sig - 1];
    if (!(flags & LUCAS_SA_NODEFER)) new_mask |= sigmask_bit(picked_sig);
    /* SIGKILL/SIGSTOP can never be in the mask. */
    new_mask &= ~(sigmask_bit(9) | sigmask_bit(19));
    st->signal_mask = new_mask;

    /* Redirect execution: handler entry, with frame on stack. */
    regs->rip = st->signal_handlers[picked_sig - 1];
    regs->rsp = handler_rsp;
    regs->rdi = (uint64_t)picked_sig;   /* arg 1 · signum */
    regs->rsi = 0;                       /* arg 2 · siginfo (NULL · SA_SIGINFO TBD) */
    regs->rdx = 0;                       /* arg 3 · ucontext (NULL · SA_SIGINFO TBD) */
    /* Mirror RIP into RCX in case seL4 returns via sysret. */
    regs->rcx = regs->rip;
    regs->r11 = regs->rflags;

    st->in_signal_handler = 1;

    printf("[signals] deliver pid=%d sig=%d handler=0x%lx rsp=0x%lx frame=0x%lx\n",
           st->synthetic_pid, picked_sig,
           (unsigned long)regs->rip,
           (unsigned long)regs->rsp,
           (unsigned long)frame_addr);

    return 1;
}

/* === rt_sigreturn core ===============================================
 *
 * Restore registers from the frame at the current RSP.  We are called
 * from the syscall path: the user's RSP at handler entry was
 * `restorer_slot_addr`; after the handler ran and the trampoline pushed
 * us into rt_sigreturn, RSP is somewhere past that.  We locate the
 * frame by scanning forward looking for our magic anomaly.
 *
 * Linux's rt_sigreturn is invoked with a precisely-known RSP layout.
 * Since we built the frame, the easiest robust approach is: search a
 * bounded window (256 B) above the current RSP for our magic, then
 * restore registers from there.  This tolerates small ABI variations
 * (e.g. whether the trampoline does an extra `add` before syscall).
 */
int64_t lucas_signals_rt_sigreturn(lucas_state_t *st, seL4_UserContext *regs) {
    /* Search for the frame within a small window of current RSP. */
    uint64_t scan_base = regs->rsp;
    struct lucas_sigframe frame;
    int found = 0;
    /* The trampoline at most decrements RSP slightly; in our default
     * "no restorer" case the handler issues rt_sigreturn directly and
     * RSP equals (restorer_slot_addr + 8) = frame_addr. */
    for (int delta = -16; delta <= 256 && !found; delta += 8) {
        uint64_t probe = scan_base + (int64_t)delta;
        if (lucas_copy_from_client(st, (uintptr_t)probe,
                                    &frame, sizeof(frame)) != 0) {
            continue;
        }
        if (frame.magic == LUCAS_SIGFRAME_MAGIC) {
            found = 1;
            break;
        }
    }
    if (!found) {
        printf("[signals] rt_sigreturn pid=%d · frame not found near rsp=0x%lx · keep regs\n",
               st->synthetic_pid, (unsigned long)regs->rsp);
        st->in_signal_handler = 0;
        return 0;
    }

    regs->rip    = frame.saved_rip;
    regs->rsp    = frame.saved_rsp;
    regs->rflags = frame.saved_rflags;
    regs->rax    = frame.saved_rax;
    regs->rbx    = frame.saved_rbx;
    regs->rcx    = frame.saved_rcx;
    regs->rdx    = frame.saved_rdx;
    regs->rdi    = frame.saved_rdi;
    regs->rsi    = frame.saved_rsi;
    regs->rbp    = frame.saved_rbp;
    regs->r8     = frame.saved_r8;
    regs->r9     = frame.saved_r9;
    regs->r10    = frame.saved_r10;
    regs->r11    = frame.saved_r11;
    regs->r12    = frame.saved_r12;
    regs->r13    = frame.saved_r13;
    regs->r14    = frame.saved_r14;
    regs->r15    = frame.saved_r15;
    st->signal_mask = frame.saved_signal_mask;
    st->in_signal_handler = 0;

    printf("[signals] rt_sigreturn pid=%d · restored rip=0x%lx rsp=0x%lx\n",
           st->synthetic_pid,
           (unsigned long)regs->rip,
           (unsigned long)regs->rsp);
    return 0;
}

/* === Test/utility hook ================================================
 *
 * Queue a pending signal for `st`.  Called from kill() / tkill() in
 * future L11+ work.  Dropped silently if the queue is full.
 */
void lucas_signals_queue_pending(lucas_state_t *st, int sig) {
    if (sig < 1 || sig > 64) return;
    /* Standard (non-RT) signals coalesce: at most ONE pending instance.  Without
     * this, a default-ignore signal (e.g. repeated SIGWINCH on terminal resize at
     * a no-handler prompt) is never consumed by try_deliver and floods the 8-slot
     * queue until it drops real signals. */
    for (int i = 0; i < st->n_pending; ++i)
        if (st->pending_signals[i] == (uint8_t)sig) return;
    if (st->n_pending >= (int)(sizeof(st->pending_signals) /
                                sizeof(st->pending_signals[0]))) {
        printf("[signals] queue pid=%d sig=%d · DROPPED (queue full)\n",
               st->synthetic_pid, sig);
        return;
    }
    st->pending_signals[st->n_pending++] = (uint8_t)sig;
    printf("[signals] queue pid=%d sig=%d · n_pending=%d\n",
           st->synthetic_pid, sig, st->n_pending);
}
