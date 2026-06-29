#include "fault_loop.h"
#include "state.h"
#include "dispatch.h"
#include <lucas/syscalls.h>
#include <orch/proto.h>
#include <sotguard/event.h>
#include <sottrace/trace.h>

#include <sel4/sel4.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <vspace/vspace.h>
#include <vka/vka.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <limits.h>

/* L1-rax-readback: opt-in diagnostic.  Define LUCAS_TRACE_RAX_READBACK at
 * build time (e.g. via -DLUCAS_TRACE_RAX_READBACK=1) to enable a post-write
 * ReadRegisters trace that verifies whether LUCAS's WriteRegisters actually
 * landed rax in the client TCB.  Findings (RAX_LANDED_OK): see
 * docs/l1-rax-readback.md. */

/* Peek 8 bytes at client_vaddr · uses dup_and_map of the backing frame.
 * Returns 0 and *out=value on success, -1 on EFAULT.  Same pattern as
 * the handlers' lucas_copy_*. */
static int peek_client_qword(lucas_state_t *st, uintptr_t client_vaddr,
                              uint64_t *out) {
    uintptr_t page_base = client_vaddr & ~0xFFFUL;
    size_t off = (size_t)(client_vaddr - page_base);
    seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page_base);
    if (!frame) return -1;
    void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                         frame, seL4_PageBits);
    if (!local) return -1;
    *out = *(uint64_t *)((uint8_t *)local + off);
    sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
    return 0;
}

/* Track last syscall number for ENOSYS diagnostics. */
unsigned int lucas_last_enosys_sysno = 0;

/* PY2 · manual `ret` simulation for arch_prctl (sysno 158).
 * Declared extern so we don't need to pull handlers.h here. */
extern int lucas_copy_from_client(struct lucas_state *st, uintptr_t client_vaddr,
                                   void *out_buf, size_t len);

/* seL4 fault label values (per sel4/fault.h on x86_64). */
#define LUCAS_FAULT_NULL              0
#define LUCAS_FAULT_CAP               1
#define LUCAS_FAULT_UNKNOWN_SYSCALL   2
#define LUCAS_FAULT_USER_EXCEPTION    3
#define LUCAS_FAULT_TIMEOUT           4
#define LUCAS_FAULT_VM                5

/* For VMFault on x86_64 the IPC MRs are:
 *   MR(0) = faulting program counter (FaultIP)
 *   MR(1) = fault address
 *   MR(2) = instruction-fetch flag (1 if instr fetch, 0 if data)
 *   MR(3) = fault status register (page-fault error code)
 *   (rest are register dump on some configurations) */

static const char *fault_name(seL4_Word label) {
    switch (label) {
        case LUCAS_FAULT_NULL:            return "NullFault";
        case LUCAS_FAULT_CAP:             return "CapFault";
        case LUCAS_FAULT_UNKNOWN_SYSCALL: return "UnknownSyscall";
        case LUCAS_FAULT_USER_EXCEPTION:  return "UserException";
        case LUCAS_FAULT_TIMEOUT:         return "Timeout";
        case LUCAS_FAULT_VM:              return "VMFault";
        default:                          return "?";
    }
}

/* Wine M1 bring-up diagnostic gate (docs/wine-spike.md · the ld-musl re-launch
 * #GP).  Returns 1 iff this sotBox is the Wine loader chain (exe_path contains
 * "wine": /usr/bin/wine or /usr/bin/wine-preloader).  ALL [wine-trace] output is
 * gated on this so it is strictly inert for every other guest (busybox, python,
 * gtk3-demo, doom, …) and cannot perturb the existing gates.  Substring scan
 * (no strstr dependency); exe_path is a fixed 128-byte NUL-terminated buffer. */
static int lucas_exe_is_wine(const lucas_state_t *st) {
    const char *p = st->exe_path;
    for (; *p; ++p)
        if (p[0] == 'w' && p[1] == 'i' && p[2] == 'n' && p[3] == 'e') return 1;
    return 0;
}

/* Track per-sotBox non-syscall fault count (keyed by slot_index).
 * Avoids adding a field to lucas_state_t for now.
 *
 * v0.10-fix: the cap MUST be reset per spawn — across multi-binary demos
 * (Python + busybox + udp_send + ...) the cumulative non-syscall faults from
 * earlier sotBoxes would otherwise drain the counter and the next spawn
 * would die on its first harmless UserException at entry+2. */
#define MAX_VM_FAULT_SLOTS 8
#define VM_FAULT_CAP_INITIAL 64
static int g_vm_fault_cap[MAX_VM_FAULT_SLOTS];
static int g_vm_fault_cap_inited = 0;

static void ensure_vm_fault_inited(void) {
    if (!g_vm_fault_cap_inited) {
        for (int i = 0; i < MAX_VM_FAULT_SLOTS; ++i)
            g_vm_fault_cap[i] = VM_FAULT_CAP_INITIAL;
        g_vm_fault_cap_inited = 1;
    }
}

/* Timing · per-slot cache of the post-syscall instruction byte at rip+2 that the c3-pop
 * heuristic reads via lucas_copy_from_client — a page dup_and_map+unmap that dominates the
 * per-syscall cost (T5).  .text is immutable within a process image, so a syscall site's
 * post-byte is constant; we cache it direct-mapped by rip and clear the slot's rows per-spawn
 * (reset_slot) and on execve (image replacement).  A collision or cold entry just re-peeks,
 * so the cache is never wrong — only sometimes cold.  rip==0 marks an empty entry (a real
 * syscall site's rip+2 is always ≥ the ELF base, never 0). */
#define C3_CACHE_N 16
static struct { uintptr_t rip; uint8_t byte; } g_c3_cache[MAX_VM_FAULT_SLOTS][C3_CACHE_N];
static inline void c3_cache_clear(int slot) {
    if (slot < 0 || slot >= MAX_VM_FAULT_SLOTS) return;
    for (int i = 0; i < C3_CACHE_N; ++i) g_c3_cache[slot][i].rip = 0;
}

void lucas_fault_loop_reset_slot(int slot) {
    if (slot >= 0 && slot < MAX_VM_FAULT_SLOTS) {
        g_vm_fault_cap[slot] = VM_FAULT_CAP_INITIAL;
    }
    c3_cache_clear(slot);   /* fresh image · drop stale post-syscall byte cache */
    sottrace_reset_slot(slot);
}

/*
 * L3b-T1: lucas_handle_one_fault — process ONE fault IPC.
 *
 * Called by orch_fault_loop AFTER seL4_Recv (badge already consumed to
 * look up st).  Reads syscall args, dispatches to the appropriate handler,
 * writes back registers, and calls seL4_Reply.
 *
 * Returns 1 if the client has exited (st->exited set), 0 otherwise.
 *
 * NOTE: does NOT call seL4_Recv — that is the caller's responsibility.
 */
/* Trivial constant-return syscalls (no args, no side effects, no errno) eligible for the
 * timing fast-path in lucas_handle_one_fault (skips ReadRegisters/WriteRegisters). */
static inline int lucas_is_trivial_syscall(unsigned int sysno) {
    switch (sysno) {
    case 39:    /* getpid  */
    case 110:   /* getppid */
    case 102:   /* getuid  */
    case 104:   /* getgid  */
    case 107:   /* geteuid */
    case 108:   /* getegid */
    case 186:   /* gettid  */
    case 24:    /* sched_yield — no-op on single-thread sotbox; returns 0 always.
                 * The handler skips seL4_Yield() when n_threads==0 (see
                 * lucas_sys_sched_yield in handlers_proc.c), so there is no
                 * kernel IPC in the fast-path and cycles stay in the hundreds.
                 * set_tid_address (218) is NOT in this set: it stores
                 * clear_child_tid (a meaningful side effect) and the static
                 * set_tid_calls diagnostic counter; called only at init so
                 * performance gain is minimal. */
        return 1;
    default:
        return 0;
    }
}

int lucas_handle_one_fault(lucas_state_t *st, seL4_MessageInfo_t info) {
    ensure_vm_fault_inited();
    seL4_Word label = seL4_MessageInfo_get_label(info);
    int slot = (st->slot_index >= 0 && st->slot_index < MAX_VM_FAULT_SLOTS)
               ? st->slot_index : 0;

    if (label == LUCAS_FAULT_UNKNOWN_SYSCALL) {
        /* L6 · snapshot all UnknownSyscall MRs BEFORE ReadRegisters.
         *
         * K6 (PR #63) showed that seL4_TCB_ReadRegisters clobbers MR[4..17]
         * of the orchestrator's IPC buffer — the very slots that hold the
         * Linux syscall args (rdi/rsi/rdx/r10/r8/r9 etc.).  Read them now
         * while they are still the faulting-thread snapshot. */
        seL4_Word mr_rax     = seL4_GetMR(seL4_UnknownSyscall_RAX);
        seL4_Word mr_rdi     = seL4_GetMR(seL4_UnknownSyscall_RDI);
        seL4_Word mr_rsi     = seL4_GetMR(seL4_UnknownSyscall_RSI);
        seL4_Word mr_rdx     = seL4_GetMR(seL4_UnknownSyscall_RDX);
        seL4_Word mr_r10     = seL4_GetMR(seL4_UnknownSyscall_R10);
        seL4_Word mr_r8      = seL4_GetMR(seL4_UnknownSyscall_R8);
        seL4_Word mr_r9      = seL4_GetMR(seL4_UnknownSyscall_R9);
        seL4_Word mr_faultip = seL4_GetMR(seL4_UnknownSyscall_FaultIP);
        seL4_Word mr_sp      = seL4_GetMR(seL4_UnknownSyscall_SP);
        /* Timing fast-path · the rest of the GP frame, snapshotted NOW (before
         * trace_emit_enter, which does FS IPC that clobbers the IPC MRs) so both the
         * trivial fast-path AND the single-thread normal path can reconstruct a CLEAN
         * 18-register frame WITHOUT seL4_TCB_ReadRegisters. */
        seL4_Word mr_rbx     = seL4_GetMR(seL4_UnknownSyscall_RBX);
        seL4_Word mr_rcx     = seL4_GetMR(seL4_UnknownSyscall_RCX);
        seL4_Word mr_rbp     = seL4_GetMR(seL4_UnknownSyscall_RBP);
        seL4_Word mr_r11     = seL4_GetMR(seL4_UnknownSyscall_R11);
        seL4_Word mr_r12     = seL4_GetMR(seL4_UnknownSyscall_R12);
        seL4_Word mr_r13     = seL4_GetMR(seL4_UnknownSyscall_R13);
        seL4_Word mr_r14     = seL4_GetMR(seL4_UnknownSyscall_R14);
        seL4_Word mr_r15     = seL4_GetMR(seL4_UnknownSyscall_R15);
        seL4_Word mr_flags   = seL4_GetMR(seL4_UnknownSyscall_FLAGS);

        /* L3-fix · stale-re-delivery guard (zero-FaultIP class).
         * After LUCAS replies to an UnknownSyscall fault the kernel may
         * (under conditions documented in docs/l2-spurious-rax-source.md)
         * re-deliver the SAME fault back to us, but with FaultIP == 0 in
         * the IPC MRs (no valid user RIP).  Skip dispatch entirely on these
         * zero-FaultIP re-deliveries — just Reply to unblock the kernel. */
        if (mr_faultip == 0) {
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            return 0;
        }

        /* L6 · stale-re-delivery guard (bogus-sysno class).
         * L5 found a second stale-redelivery shape: MR[FaultIP] is
         * non-zero but MR[0]=RAX carries the receiver TCB's leftover
         * -EBADF (=-9) or similar large unsigned negative value from a
         * prior in-orch syscall return.  Linux x86_64 has < 500 real
         * syscalls today — anything above 1024 is necessarily a stale
         * IPC re-delivery (or a userspace bug we can't service).  Skip
         * dispatch quietly to keep the kernel from flooding our log. */
        unsigned int sysno = (unsigned int)mr_rax;
        if (sysno > 1024U) {
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            return 0;
        }

        /* sottrace · syscall ENTER. Read args from the MR snapshot locals
         * (mr_rdi..mr_r9 captured @126-133), NEVER regs.* — ReadRegisters
         * (next line) clobbers MR[4..17] (the K6 bug). Sits AFTER both
         * stale-redelivery guards so it never logs a synth syscall. */
        {
            uint64_t _tr_args[6] = { mr_rdi, mr_rsi, mr_rdx, mr_r10, mr_r8, mr_r9 };
            trace_emit_enter(st->slot_index, (uint32_t)st->synthetic_pid,
                             sysno, _tr_args, (uint64_t)mr_faultip);
        }

        /* ── TIMING FAST-PATH ──────────────────────────────────────────────────────
         * Trivial constant-return syscalls (getpid/uid/gid/tid) from a single-thread,
         * in-text box with no pending signal: serviced WITHOUT the two per-syscall kernel
         * calls (seL4_TCB_ReadRegisters + WriteRegisters).  The UnknownSyscall fault already
         * delivered the FULL 18-register GP frame in the IPC MRs (seL4_UnknownSyscall_Msg),
         * so we dispatch and REPLY with that frame echoed — patching rax (result), rip (+2),
         * and rcx/r11 (the sysret RIP/FLAGS mirror).  seL4 restores the 18 regs from the
         * reply and resumes.  This removes the dominant cost of the fault→IPC→lucAs→return
         * path for the cheapest syscalls (T5 microbench).  Anything outside this exact shape
         * — multi-thread, wine, a pending signal, an out-of-text site — falls through to the
         * full path below (TCB-by-RSP identification, msyscall detector, signal delivery). */
        if (st->n_threads == 0 && st->n_pending == 0 &&
            lucas_is_trivial_syscall(sysno) && !lucas_exe_is_wine(st)) {
            int fp_in_text = (mr_faultip >= 0x00400000UL && mr_faultip < 0x01300000UL);
            if (!fp_in_text && st->is_dynamic &&
                mr_faultip >= LUCAS_DYN_BIN_BASE && mr_faultip < LUCAS_DYN_BRK_BASE)
                fp_in_text = 1;
            if (fp_in_text) {
#ifdef T5_ELIDE_DISPATCH
                /* ── T5 MEASUREMENT TOGGLE · DEFAULT OFF ────────────────────────────────────
                 * Skip lucas_dispatch_call; stub the return value so the frame is still
                 * written back and the guest advances normally.  Bench output is garbage
                 * (getpid returns 1 instead of the synthetic pid); we only read the cycle
                 * delta (baseline − this) to isolate the lucas_dispatch_call cost. */
                int64_t fp_ret = 1;
#else
                int64_t fp_ret = lucas_dispatch_call(st, sysno,
                                                     mr_rdi, mr_rsi, mr_rdx,
                                                     mr_r10, mr_r8, mr_r9);
#endif
                seL4_Word fp_nrip = (seL4_Word)mr_faultip + 2;
                lucas_last_enosys_sysno = sysno;
                /* Reconstruct the GP frame from the clean fault-MR snapshot (so we DON'T
                 * pay seL4_TCB_ReadRegisters), patch rax=result, rip=+2, rcx/r11 = the
                 * sysret RIP/FLAGS mirror, and write it back through the SAME proven
                 * WriteRegisters + empty-Reply path the full handler uses below.  (Replying
                 * with the registers in the IPC MRs does NOT work here — the kernel's fault
                 * reply restores the frame in a different order than the UnknownSyscall fault
                 * message, scrambling the callee-saved regs.)  Net: one kernel round-trip
                 * (the ReadRegisters) removed per trivial syscall. count=18 = rip..r15, so
                 * fs_base/gs_base are left untouched (TLS owned by arch_prctl). */
                seL4_UserContext fpr;
                fpr.rip = fp_nrip;           fpr.rsp = mr_sp;       fpr.rflags = mr_flags;
                fpr.rax = (seL4_Word)fp_ret; fpr.rbx = mr_rbx;      fpr.rcx = fp_nrip;
                fpr.rdx = mr_rdx;            fpr.rsi = mr_rsi;      fpr.rdi = mr_rdi;
                fpr.rbp = mr_rbp;            fpr.r8  = mr_r8;       fpr.r9  = mr_r9;
                fpr.r10 = mr_r10;            fpr.r11 = mr_flags;    fpr.r12 = mr_r12;
                fpr.r13 = mr_r13;            fpr.r14 = mr_r14;      fpr.r15 = mr_r15;
#ifdef T5_ELIDE_WRITEREGS
                /* ── T5 MEASUREMENT TOGGLE · DEFAULT OFF ────────────────────────────────────
                 * Skip the full seL4_TCB_WriteRegisters(count=18).  Instead write only
                 * FaultIP with WriteRegisters(count=1).  This is the minimum needed because:
                 *   (a) count=1 writes frameRegisters[0]=FaultIP → advances the guest's RIP
                 *       past the syscall instruction (fp_nrip).
                 *   (b) invokeTCB_WriteRegisters always calls Mode_postModifyRegisters which
                 *       sets registers[Error]=0 for non-current threads.  Error=0 forces the
                 *       kernel to use the IRETQ return path (which correctly restores RSP
                 *       from registers[RSP] via the IRQ stack) instead of SYSRETQ (which
                 *       explicitly zeroes RSP before the sysretq instruction).
                 *   (c) registers[RSP] already holds the correct user RSP from
                 *       handleUnknownSyscall (ADR-005 / x64KS_user_rsp_save) — no need to
                 *       re-set it.
                 * RAX stays as the raw syscall number (garbage return value for getpid) but
                 * the bench discards sys1()'s return, so only the cycle delta counts.
                 * Delta (baseline(18) − this(1)) ≈ cost of the 17 extra WriteRegisters
                 * fields; the kernel IPC round-trip remains in both variants.
                 * trace_emit_exit omitted; trace correctness is irrelevant under elision. */
                int fperr1 = seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 1, &fpr);
                if (fperr1) printf("[lucas] T5-elide-wr: WriteRegisters(1) failed (%d)\n", fperr1);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
#else
                int fperr = seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &fpr);
                if (fperr) printf("[lucas] fast-path WriteRegisters failed (err=%d)\n", fperr);
                trace_emit_exit(st->slot_index, (uint32_t)st->synthetic_pid,
                                sysno, fp_ret, (uint64_t)fp_nrip);
                seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
#endif
                if (st->exited) return 1;
                return 0;
            }
        }

        /* WINE-M1 · per-syscall trace for the wine chain · pin the launcher's
         * exact wineserver-connection mechanism (socket/connect vs inherited
         * socketpair fd).  Gated to wine boxes → inert for every other guest. */
        if (lucas_exe_is_wine(st)) {
            char _wp[80]; _wp[0] = '\0';
            /* path-bearing syscalls: open(2)/stat(4)/lstat(6)/access(21) take the
             * path at a0; openat(257)/newfstatat(262) at a1.  Snapshot it so the
             * trace shows WHAT wine polls for (the wineserver socket file?). */
            uint64_t _pa = 0;
            if (sysno==2||sysno==4||sysno==6||sysno==21||sysno==59||sysno==83||sysno==88) _pa = mr_rdi;
            else if (sysno==257||sysno==262||sysno==268) _pa = mr_rsi;
            if (_pa) { extern int lucas_copy_from_client(lucas_state_t*, uintptr_t, void*, size_t);
                       if (lucas_copy_from_client(st, (uintptr_t)_pa, _wp, sizeof(_wp)-1) == 0) _wp[sizeof(_wp)-1]='\0'; else _wp[0]='\0'; }
            printf("[wine-sys] pid=%d sysno=%u a0=0x%lx a1=0x%lx a2=0x%lx a3=0x%lx ip=0x%lx%s%s\n",
                   st->synthetic_pid, sysno,
                   (unsigned long)mr_rdi, (unsigned long)mr_rsi, (unsigned long)mr_rdx,
                   (unsigned long)mr_r10, (unsigned long)mr_faultip,
                   _wp[0] ? " path=" : "", _wp);
        }

        /* Linux syscall · the path we already know works.
         *
         * MULTI-THREAD · all pthread children share this sotbox's badged
         * fault EP (clone configures fault_ep slot 1 in the shared CSpace),
         * so a child's syscall arrives here keyed by the PARENT's badge.
         * The register read/modify/write-back below MUST target the THREAD
         * that actually faulted — else a child's return value + RIP advance
         * land on the parent's TCB while the child resumes UNCHANGED and
         * re-faults the identical syscall forever (observed as an SDL2
         * thread spinning ~733k× on rt_sigprocmask under Chocolate Doom).
         * seL4_Reply uses the implicit reply cap so the RIGHT thread resumes;
         * we only have to pick the right TCB to ReadRegisters/WriteRegisters.
         *
         * Identify by RSP: the fault message's SP (mr_sp, MR[16], captured
         * pre-clobber) equals the faulting thread's saved rsp, and threads
         * have distinct stacks. The common case (single-thread box, or the
         * main thread faulting) matches client_tcb on the first read → no
         * extra ReadRegisters. */
        seL4_CPtr fault_tcb = st->client_tcb;
        /* NULL-TCB guard · a stale fault that resolves to a reaped/half-rebuilt box
         * (client_tcb==0) must NOT be invoked — seL4_TCB_ReadRegisters on cptr 0
         * makes the kernel spam "Attempted to invoke a null cap #0" + returns
         * InvalidCapability.  Drop it cleanly as a fatal (reap, no kernel noise). */
        if (fault_tcb == 0) {
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            st->exited = 1; st->exit_code = 1;
            return 1;
        }
        seL4_UserContext regs;
        int err = 0;
        if (st->n_threads == 0) {
            /* Single-thread box (the overwhelming majority): reconstruct the GP frame from
             * the fault-MR snapshot instead of paying seL4_TCB_ReadRegisters.  The thread is
             * blocked at the fault, so the snapshot IS its live register state — and per the
             * K6 note above it is the AUTHORITATIVE arg payload (ReadRegisters can hand back
             * clobbered args).  This removes the ReadRegisters round-trip from EVERY
             * single-thread syscall, not just the trivial fast-path.  rcx/r11 get overwritten
             * for sysret below; fs_base/gs_base are owned by arch_prctl and never written back
             * (count=18 = rip..r15), so leaving them 0 here is inert. */
            regs.rip = mr_faultip; regs.rsp = mr_sp;  regs.rflags = mr_flags;
            regs.rax = mr_rax;     regs.rbx = mr_rbx; regs.rcx = mr_rcx;  regs.rdx = mr_rdx;
            regs.rsi = mr_rsi;     regs.rdi = mr_rdi; regs.rbp = mr_rbp;
            regs.r8  = mr_r8;      regs.r9  = mr_r9;  regs.r10 = mr_r10;   regs.r11 = mr_r11;
            regs.r12 = mr_r12;     regs.r13 = mr_r13; regs.r14 = mr_r14;   regs.r15 = mr_r15;
            regs.fs_base = 0;      regs.gs_base = 0;
        } else {
            /* Multi-thread box · a child's syscall arrives keyed by the parent's badge, so we
             * must ReadRegisters and pick the TCB whose RSP matches the fault's SP (distinct
             * per-thread stacks) before operating on its context. */
            err = seL4_TCB_ReadRegisters(fault_tcb, false, 0,
                                          sizeof(regs)/sizeof(seL4_Word), &regs);
            if (!err && (seL4_Word)regs.rsp != mr_sp) {
                for (int ti = 0; ti < 16; ++ti) {
                    seL4_CPtr tcb = st->thread_list[ti].tcb;
                    if (!tcb) continue;
                    seL4_UserContext tr;
                    int terr = seL4_TCB_ReadRegisters(tcb, false, 0,
                                                      sizeof(tr)/sizeof(seL4_Word), &tr);
                    if (terr == 0 && (seL4_Word)tr.rsp == mr_sp) {
                        fault_tcb = tcb;
                        regs      = tr;   /* operate on the faulting thread's context */
                        break;
                    }
                }
            }
        }
        if (err) {
            printf("[lucas] ReadRegisters failed (err=%d)\n", err);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            /* Treat as fatal: stop servicing this client.
             * (sottrace: ENTER was already emitted; no EXIT follows — same benign
             *  ENTER-only asymmetry as the deferred/execve paths; slot reuse resets the ring.) */
            st->exited    = 1;
            st->exit_code = 1;
            return 1;
        }
        lucas_last_enosys_sysno = sysno;

        /* OBSD-ε MSYSCALL · verify the syscall site is within the legitimate
         * ELF text range.  Shellcode running from heap/stack/anon-mmap will
         * have RIP outside this range · first hit triggers STAR Tier-2
         * deception.  OpenBSD's msyscall would kill the process; sotOs
         * traps it into the synth layer instead.
         *
         * regs.rip on UnknownSyscall points AT the `syscall` opcode (same
         * convention used by the c3-peek heuristic at line 253 which reads
         * regs.rip+2 for the post-syscall instruction).
         *
         * Single-fire gate: only one seL4_Call to anomaly per sotbox
         * even if the shellcode issues a tight syscall loop.  Counter
         * keeps incrementing unconditionally for operator forensics. */
        #define LUCAS_TEXT_LOW   0x00400000UL
        #define LUCAS_TEXT_HIGH  0x01300000UL
        uintptr_t syscall_site = (uintptr_t)regs.rip;
        /* N3/D1 · a dynamic sotbox legitimately executes from the PIE +
         * ld-musl load window [BIN_BASE, BRK_BASE).  Treat that whole region
         * as legitimate text so ld-musl's startup syscalls (arch_prctl, mmap,
         * mprotect, …) don't trip the OUTSIDE-TEXT detector — which for an
         * untrusted box would do a blocking mid-fault seL4_Call and park it. */
        bool site_in_text = (syscall_site >= LUCAS_TEXT_LOW &&
                             syscall_site < LUCAS_TEXT_HIGH);
        if (st->is_dynamic &&
            syscall_site >= LUCAS_DYN_BIN_BASE &&
            syscall_site < LUCAS_DYN_BRK_BASE) {
            site_in_text = true;
        }
        if (!site_in_text) {
            uint32_t prev = st->msyscall_violations;
            st->msyscall_violations++;
            if (st->trusted || st->is_dynamic) {
                /* SP1 PR 5 · tier-pin with observability.  A trusted sotbox
                 * (the in-OS C compiler) legitimately executes JIT-generated
                 * code from a writable-mapped page — so EVERY syscall it
                 * issues (the compiled program's write/exit) has RIP outside
                 * .text and trips this detector.  We must NOT do the blocking
                 * seL4_Call forward/promote here: that mid-fault Call would
                 * HANG the sotbox (PR 4 investigation).  Log the detection
                 * audit-only on the first hit and CONTINUE so the JIT syscall
                 * is dispatched normally below.  Untrusted boxes fall through
                 * to the forward/promote branch unchanged. */
                if (prev == 0) {
                    printf("[msyscall] %s pid=%d rip=0x%lx sysno=%u "
                           "audit-only · not promoted\n",
                           st->trusted ? "trusted" : "dynamic",
                           st->synthetic_pid, (unsigned long)syscall_site,
                           (unsigned int)sysno);
                    /* N3/D2 · a dynamic box runs real lib code from the mmap
                     * region (outside the PIE text window) · record the
                     * deception signal in sotGuard, but NEVER the blocking
                     * mid-fault seL4_Call (it would hang the box · cf. D1). */
                    if (st->is_dynamic && !st->trusted) {
                        static uint64_t sg_dyn_seq;
                        sotguard_event_t ev;
                        memset(&ev, 0, sizeof(ev));
                        ev.pid = (uint32_t)st->synthetic_pid;
                        ev.type = SG_EV_FAULT_SYSCALL;
                        ev.timestamp = ++sg_dyn_seq;
                        ev.detail.fault.syscall_nr = (uint32_t)sysno;
                        ev.detail.fault.rip = (uint64_t)syscall_site;
                        (void)sotguard_emit(&ev);
                    }
                }
            } else if (prev == 0) {
                printf("[msyscall] pid=%d rip=0x%lx sysno=%u OUTSIDE-TEXT\n",
                       st->synthetic_pid, (unsigned long)syscall_site,
                       (unsigned int)sysno);
                extern seL4_CPtr orch_get_anomaly_ep(void);
                seL4_CPtr sep = orch_get_anomaly_ep();
                if (sep != 0) {
                    seL4_SetMR(0, (seL4_Word)st->synthetic_pid);
                    seL4_SetMR(1, (seL4_Word)ANOMALY_EV_MSYSCALL);
                    seL4_SetMR(2, (seL4_Word)syscall_site);
                    seL4_SetMR(3, (seL4_Word)sysno);
                    /* REPLY-DRIVEN promote · anomaly returns the tier in MR(0)
                     * (no re-entrant seL4_Call(orch_ep) · that deadlocks). */
                    seL4_MessageInfo_t mr = seL4_Call(sep, seL4_MessageInfo_new(
                              ORCH_OP_ANOMALY_EVENT, 0, 0, 4));
                    int pt = (seL4_MessageInfo_get_length(mr) > 0)
                           ? (int)seL4_GetMR(0) : 0;
                    if (pt > 0) {
                        extern void orch_anomaly_apply_promote(uint32_t pid, int tier);
                        orch_anomaly_apply_promote((uint32_t)st->synthetic_pid, pt);
                    }
                }
                /* SG-FAULT Phase 2 · also emit into the sotGuard event bus.
                 * Gated by `prev == 0` so we honour the single-fire policy
                 * (one event per sotbox per RIP-out-of-text observation). */
                {
                    static uint64_t sg_msyscall_seq;
                    sotguard_event_t ev;
                    memset(&ev, 0, sizeof(ev));
                    ev.pid = (uint32_t)st->synthetic_pid;
                    ev.type = SG_EV_FAULT_SYSCALL;
                    ev.timestamp = ++sg_msyscall_seq;
                    ev.detail.fault.syscall_nr = (uint32_t)sysno;
                    ev.detail.fault.rip = (uint64_t)syscall_site;
                    (void)sotguard_emit(&ev);
                }
            }
            /* Continue dispatching the syscall normally · let the malware
             * "succeed" so it commits to its exploit path; anomaly rule
             * already promoted to Tier-2 on the first hit. */
        }

        /* L6 · use the MR snapshot for all args (rdi/rsi/rdx/r10/r8/r9).
         * regs.* came from ReadRegisters which clobbers our IPC MRs but
         * also returns stale-or-corrupt arg registers under the same K6
         * conditions.  The MR snapshot taken at fault entry is the
         * authoritative arg payload. */
        /* Record the faulting thread's TCB so a parking syscall (FUTEX_WAIT)
         * can stash WHICH thread to restore at wake — in a multi-thread box the
         * parked thread may be a worker, not client_tcb (the GTK pthread wall). */
        st->cur_fault_tcb = fault_tcb;
        int64_t ret = lucas_dispatch_call(st,
                                           sysno,
                                           mr_rdi, mr_rsi, mr_rdx,
                                           mr_r10, mr_r8,  mr_r9);

        /* execve/execveat replaced the process image in place · the new .text occupies the
         * same vaddrs, so drop this slot's post-syscall byte cache to force a re-peek. */
        if (sysno == 59 || sysno == 322) c3_cache_clear(st->slot_index);

        /* DOOM-DBG · bracket the text-frame corruption to a single syscall.
         * Probe the victim page 0x54b000 after EVERY syscall; the first trip
         * names the syscall (and PID) that flipped it to the mtio.h header. */
        {
            extern void lucas_doom_probe_sys(unsigned long sysno, int pid);
            lucas_doom_probe_sys((unsigned long)sysno, st ? st->synthetic_pid : -1);
        }

        /* L3b-T2: wait4 SaveCaller deferred path.
         * The handler saved the reply cap and parked the sotBox.
         * Do NOT call seL4_Reply (the wakeup path will Send to the
         * saved reply cap when the child exits).  Return -2 to signal
         * orch_fault_loop that we deferred — NOT exited. */
        if (ret == LUCAS_WAIT4_DEFERRED) {
            return -2;
        }

        /* L3b-T3: execve path.
         * The handler already called TCB_WriteRegisters with the new
         * image's entry point and stack.  Just Reply to unblock the
         * client (it will start at the fresh RIP); do NOT overwrite
         * rax/rip with the return value.  Return -3 to signal
         * orch_fault_loop: reply was sent, not exited. */
        if (ret == LUCAS_EXEC_REPLY_RAW) {
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            return -3;
        }

        regs.rax = (uint64_t)ret;
        /* sottrace · syscall EXIT. The deferred/execve magic paths early-returned
         * above (@299 WAIT4_DEFERRED, @309 EXEC_REPLY_RAW), so ret here is a real
         * code. A deferred (wait4/recv) syscall therefore shows ENTER with no
         * EXIT — which is exactly the hung-syscall signature we want. */
        trace_emit_exit(st->slot_index, (uint32_t)st->synthetic_pid,
                        sysno, ret, (uint64_t)regs.rip);
        /* PY6 · generalize PY2 manual-ret simulation.
         * Some CPU/seL4 combos botch the post-syscall `ret`: instead of
         * popping RSP into RIP, the thread resumes with RIP just +2 above
         * the syscall (rax also corrupted).  PY2 worked around this for
         * sysno 158 (arch_prctl).  Investigation in
         * docs/python-entry2-mystery.md shows the same +2 magic pattern
         * appears downstream in Python at 0x120f018 · so the bug is not
         * arch_prctl-specific, it's tied to the `syscall;ret` byte
         * sequence itself.
         *
         * Heuristic: peek the instruction byte at rip_post (= regs.rip+2
         * in the standard model · that's where the `ret` would live).  If
         * it's `c3`, do the manual pop here and skip the user-mode `ret`.
         * If it's anything else (mov/lea/jmp/...), fall back to the
         * standard +2 advance · the next instruction is benign and runs
         * normally.
         *
         * This generalization keeps busybox happy (its libc wrappers also
         * use `syscall;ret`, but they apparently weren't hitting the +2
         * bug for unrelated reasons · TBD; if smoke regresses, this
         * heuristic is too coarse and we narrow further). */
        uint8_t post_byte = 0;
        uintptr_t rip_post = regs.rip + 2;
        int read_rc;
        /* Timing · serve the post-syscall byte from the per-slot cache when this exact
         * syscall site was already peeked (the common case in any loop), avoiding the
         * copy_from_client page map/unmap.  Cold/colliding entry falls back to the peek. */
        int _cs = st->slot_index;
        int _ci = (int)((rip_post >> 1) & (C3_CACHE_N - 1));
        if (_cs >= 0 && _cs < MAX_VM_FAULT_SLOTS &&
            rip_post != 0 && g_c3_cache[_cs][_ci].rip == rip_post) {
            post_byte = g_c3_cache[_cs][_ci].byte;
            read_rc   = 0;
        } else {
            read_rc = lucas_copy_from_client(st, rip_post, &post_byte, 1);
            if (read_rc == 0 && _cs >= 0 && _cs < MAX_VM_FAULT_SLOTS) {
                g_c3_cache[_cs][_ci].rip  = rip_post;
                g_c3_cache[_cs][_ci].byte = post_byte;
            }
        }

        if (read_rc == 0 && post_byte == 0xc3) {
            /* syscall;ret pattern · pop the return addr from user stack
             * and jump there directly, bypassing the broken user `ret`.
             *
             * L10-RET-GUARDS · plausibility-check the popped value before
             * installing as RIP.  Without this, a `syscall;ret` at the
             * top-level (no preceding `call`) leaves argc / fd / loop
             * counter on [rsp]; we would otherwise install that small
             * integer as RIP and the CPU faults at faultIP=<small int>.
             * Diagnosed in docs/sysret-align-audit.md and observed in
             * Python's init (VMFault faultIP=0x4 at v0.11.4 / PR #82).
             * Userspace text starts above 1 MiB (typical ELF base is
             * 0x400000); x86_64 canonical user vspace ceiling is
             * 0x7fff_ffff_ffff. */
            /* WINE-TRACE · rank-2 probe (docs/wine-spike.md).  The manual c3-pop
             * guard is purely numeric [0x100000,0x800000000000) — no exec/align
             * check — so a stale stack qword in the ld-musl rodata window
             * (>= exec end 0x4006713e) would install as RIP and #GP.  Log every
             * pop on the wine chain; flag pops that land in ld-musl rodata. */
            if (lucas_exe_is_wine(st)) {
                uint64_t pk = 0;
                lucas_copy_from_client(st, (uintptr_t)regs.rsp, &pk, sizeof(pk));
                printf("[wine-trace] c3-pop sysno=%u site=0x%lx rsp=0x%lx rsp&7=%lu popped=0x%lx%s\n",
                       sysno, (unsigned long)regs.rip, (unsigned long)regs.rsp,
                       (unsigned long)(regs.rsp & 7u), (unsigned long)pk,
                       (pk >= 0x40067000UL && pk < 0x40120000UL)
                           ? "  <-- into ld-musl RODATA (rank-2 confirmed)" : "");
            }
            uint64_t popped_rip = 0;
            if (lucas_copy_from_client(st, (uintptr_t)regs.rsp,
                                        &popped_rip, sizeof(popped_rip)) == 0
                && popped_rip >= 0x100000UL
                && popped_rip <  0x800000000000UL) {
                regs.rip  = popped_rip;
                regs.rsp += 8;
            } else {
                /* Couldn't read the return slot, OR popped value is
                 * implausible · fall back to +2 so the fault loop stays
                 * healthy and the user-mode `ret` instruction at rip+2
                 * runs normally (where it will either succeed against a
                 * real return frame, or fault visibly with the actual
                 * culprit address). */
                regs.rip += 2;
            }
        } else if (sysno == 56 /* SYS_clone */) {
            /* M2-bug-3: PY8 originally applied the manual-pop bypass here,
             * mirroring PY6's `c3` workaround.  Investigation in
             * docs/M2-bug-3-parent-rax-investigation.md showed that PY8 is
             * unsafe for fall-through clone callers: the pthread_test
             * fixture issues `syscall` at top-level without a preceding
             * `call`, so `[rsp]` holds `argc` (= 1), not a return address.
             * The bypass therefore set rip to 0x1 and the parent walked
             * into unmapped memory.
             *
             * Use the standard +2 advance · the next instruction
             * (`test %rax,%rax`) runs in user mode like any other
             * post-syscall fall-through.  For libc-wrapped clone where the
             * post-syscall byte IS 0xc3, the generic `c3` branch above
             * already handles the case.  Sysno=56 needs no special bypass. */
            regs.rip += 2;
        } else {
            /* Standard syscall advance · post-syscall instruction will
             * execute in user mode. */
            regs.rip += 2;
        }

        /* K2-revert-v2 · K2's `regs.rip -= 2` for rip >= 0x01000000 was
         * suspected of re-executing the same syscall instead of advancing
         * past it (PY-sample / PR #70 saw set_tid_address looping 9180×
         * over 120 s with K2 active).  Removed here with M2-bug-5 thread
         * cleanup active so prior contamination doesn't mask the result. */
        /* U1 · signals · check pending queue after each successful syscall
         * return.  If a deliverable signal is queued, the helper rewrites
         * regs in-place to enter the user-installed handler.  Forward-
         * declared inline to keep this file's includes unchanged. */
        if (st->n_pending > 0) {
            extern int lucas_signals_try_deliver(lucas_state_t *st,
                                                  seL4_UserContext *regs);
            (void)lucas_signals_try_deliver(st, &regs);
        }
        /* On x86_64 the `syscall` instruction sets RCX = next RIP and
         * R11 = RFLAGS (for sysret-based return).  If seL4 resumes the
         * thread via sysret rather than iretq, RIP comes from RCX, so
         * we must mirror our updated RIP into RCX (and refresh R11 with
         * the current RFLAGS so sysret doesn't clobber flags weirdly). */
        regs.rcx = regs.rip;
        regs.r11 = regs.rflags;
        /* Write back ONLY the general regs (count=18: rip..r15).  We
         * must NOT touch fs_base/gs_base · the arch_prctl handler
         * (or any future TLS-altering syscall) sets those directly
         * via seL4_TCB_SetTLSBase, and our stale local copy would
         * overwrite the kernel-side change. */
#ifdef LUCAS_TRACE_L2_WR
        /* L2-spurious-rax · gated diagnostic.  Logs every fault-loop
         * WriteRegisters where rax is 0/-9/-38 so the cascade described in
         * docs/l2-spurious-rax-source.md is visible at boot. */
        if (regs.rax == 0 || regs.rax == (uint64_t)-9LL ||
            regs.rax == (uint64_t)-38LL) {
            printf("[l:wr-fault_loop:256] tcb=%lu rax=0x%lx rip=0x%lx sysno=%u\n",
                   (unsigned long)st->client_tcb,
                   (unsigned long)regs.rax,
                   (unsigned long)regs.rip,
                   sysno);
        }
#endif
        err = seL4_TCB_WriteRegisters(fault_tcb, false, 0,
                                       18, &regs);
        if (err) printf("[lucas] WriteRegisters failed (err=%d)\n", err);

#ifdef LUCAS_TRACE_RAX_READBACK
        /* L1-rax-readback: after WriteRegisters, immediately Read back to
         * verify rax landed.  Gated on rip range to limit noise. */
        if (regs.rip >= 0x00400000UL && regs.rip <= 0x01300000UL) {
            seL4_UserContext rb;
            int rerr = seL4_TCB_ReadRegisters(st->client_tcb, false, 0,
                                               sizeof(rb)/sizeof(seL4_Word), &rb);
            printf("[l:rax-rb] sysno=%u rip_wrote=0x%lx rip_rb=0x%lx rax_wrote=0x%lx rax_rb=0x%lx (rerr=%d)\n",
                   sysno, (unsigned long)regs.rip, (unsigned long)rb.rip,
                   (unsigned long)regs.rax, (unsigned long)rb.rax, rerr);
        }
#endif

        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

        if (st->exited) return 1;
        return 0;
    }

    /* Non-syscall fault · log details from the IPC message AND a register
     * snapshot.  Do NOT auto-advance RIP · that loops forever. */
    seL4_Word mr0 = seL4_GetMR(0);
    seL4_Word mr1 = seL4_GetMR(1);
    seL4_Word mr2 = seL4_GetMR(2);
    seL4_Word mr3 = seL4_GetMR(3);

    /* N3/D3 · lazy file-backed mmap backing.  A dynamic box faulting inside a
     * registered lazy .so region gets the page backed on-demand here, then
     * re-executes the faulting instruction.  Resume WITHOUT touching the fault
     * cap (else libcrypto's first page-faults would suspend the box) and BEFORE
     * the noisy fault logging below (libcrypto lazily faults many pages).  Gated
     * on is_dynamic so the static/trusted hot path is untouched. */
    if (label == LUCAS_FAULT_VM && st->is_dynamic) {
        extern int lucas_lazy_back_page_ex(lucas_state_t *st, uintptr_t fault_vaddr, int is_write);
        /* x86-64 VMFault MR3 = page-fault error code; bit1 = write access. */
        int is_write = (int)((mr3 >> 1) & 1u);
        if (lucas_lazy_back_page_ex(st, (uintptr_t)mr1, is_write) == 0) {
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            return 0;
        }
    }

    /* MULTI-THREAD · pthread children share this sotbox's badged fault EP, so a
     * child's VMFault arrives keyed by the PARENT's badge (same as the syscall
     * path above).  The VMFault message has no SP, but MR0 = the faulting
     * thread's IP, so identify the thread whose saved rip == faultIP and dump
     * ITS registers — else a child fault prints the parent's (idle) registers,
     * which is exactly what made the GTK widget-thread NULL-call undiagnosable
     * (regs showed the main thread parked in futex while the child jumped to 0). */
    seL4_CPtr fault_tcb = st->client_tcb;
    seL4_UserContext regs;
    int err = seL4_TCB_ReadRegisters(fault_tcb, false, 0,
                                      sizeof(regs)/sizeof(seL4_Word), &regs);
    if (!err && (seL4_Word)regs.rip != (seL4_Word)mr0 && st->n_threads > 0) {
        for (int ti = 0; ti < 16; ++ti) {
            seL4_CPtr tcb = st->thread_list[ti].tcb;
            if (!tcb) continue;
            seL4_UserContext tr;
            if (seL4_TCB_ReadRegisters(tcb, false, 0,
                                       sizeof(tr)/sizeof(seL4_Word), &tr) == 0
                && (seL4_Word)tr.rip == (seL4_Word)mr0) {
                fault_tcb = tcb; regs = tr; break;
            }
        }
    }
    printf("[lucas] FAULT %s (slot=%d%s) · faultIP=0x%lx addr=0x%lx ifetch=%lu fsr=0x%lx\n",
           fault_name(label), st->slot_index,
           fault_tcb == st->client_tcb ? "" : " thread",
           (unsigned long)mr0, (unsigned long)mr1,
           (unsigned long)mr2, (unsigned long)mr3);
    if (err == 0) {
        printf("[lucas]   regs: rip=0x%lx rsp=0x%lx rbp=0x%lx rax=0x%lx\n",
               (unsigned long)regs.rip, (unsigned long)regs.rsp,
               (unsigned long)regs.rbp, (unsigned long)regs.rax);
        printf("[lucas]         rdi=0x%lx rsi=0x%lx rdx=0x%lx rcx=0x%lx\n",
               (unsigned long)regs.rdi, (unsigned long)regs.rsi,
               (unsigned long)regs.rdx, (unsigned long)regs.rcx);
        /* WINE-TRACE · rank-1 probe (docs/wine-spike.md).  The wine-preloader
         * hand-builds the re-launched ld-musl's initial stack/auxv in userspace
         * (LUCAS never validates it); a bad AT_BASE / argc / auxv layout derails
         * musl's _dlstart self-relocation off the end of text (0x4006713e) into
         * rodata, where 0x40068c49 (byte 0x1e) #GPs.  Dump: rsp 16-byte alignment,
         * 16 bytes @ faultIP (expect ld-musl rodata = derailment confirmed), and
         * the stack qwords (argc/argv/auxv if near the entry stack).  Wine-gated
         * → strictly inert for every other guest. */
        if (lucas_exe_is_wine(st)) {
            uint8_t fb[16] = {0};
            (void)lucas_copy_from_client(st, (uintptr_t)mr0, fb, sizeof(fb));
            printf("[wine-trace] FAULT faultIP=0x%lx rsp=0x%lx rsp&15=%lu\n",
                   (unsigned long)mr0, (unsigned long)regs.rsp,
                   (unsigned long)(regs.rsp & 15u));
            printf("[wine-trace]   bytes@faultIP:");
            for (int i = 0; i < 16; ++i) printf(" %02x", fb[i]);
            printf("\n");
            printf("[wine-trace]   fs_base=0x%lx gs_base=0x%lx (thread=%s)\n",
                   (unsigned long)regs.fs_base, (unsigned long)regs.gs_base,
                   fault_tcb == st->client_tcb ? "main" : "clone");
            if (regs.gs_base) {
                uint64_t teb_self = 0;
                if (lucas_copy_from_client(st, (uintptr_t)regs.gs_base + 0x30,
                                           &teb_self, 8) == 0)
                    printf("[wine-trace]   *(gs_base+0x30)=0x%lx (TEB->Self expect==gs_base)\n",
                           (unsigned long)teb_self);
                else
                    printf("[wine-trace]   *(gs_base+0x30) unreadable\n");
            }
            /* Scan deep enough to clear a large frame (RtlAllocateHeap's is
             * ~0xd0): flag qwords that look like a return address into ntdll.dll
             * (0x6ffffff4xxxx), the PE exe (0x1400xxxxx) or the unix ntdll.so
             * (0x400xxxxx) so the call chain is readable. */
            for (int q = 0; q < 64; ++q) {
                uint64_t v = 0;
                if (lucas_copy_from_client(st, (uintptr_t)regs.rsp + 8 * q, &v, 8) != 0) break;
                const char *tag = "";
                if ((v >= 0x6ffffff40000ULL && v < 0x700000000000ULL) ||
                    (v >= 0x140000000ULL    && v < 0x141000000ULL)    ||
                    (v >= 0x40000000ULL     && v < 0x41000000ULL))
                    tag = "  <- code (return addr?)";
                printf("[wine-trace]   [rsp+0x%02x]=0x%lx%s\n",
                       (unsigned)(q * 8), (unsigned long)v, tag);
            }
            /* WINE-M1 · NULL-process-heap diagnosis.  ntdll.dll's loader_init does
             * `if (!attach_done) { create process heap } else { thread-attach }`.
             * attach_done is a static in .bss at RVA 0x9493c (process_detaching at
             * 0x94938).  If it reads non-zero in this (first-thread of a spawned)
             * process, loader_init skipped heap creation → this NULL-heap fault.
             * base = faultIP - 0x5c2cc (the RtlEnterCriticalSection fast-path RVA). */
            if (regs.rip >= 0x6ffffff40000ULL && regs.rip < 0x700000000000ULL) {
                uintptr_t ntdll = (uintptr_t)regs.rip - 0x5c2ccULL;
                /* .bss 0x94938 = process_detaching;  0x9493c = imports_fixup_done
                 * (the loader_init first-time-block gate, loader.c:4280 — verified
                 * via disasm of loader_init@0x354c0: `mov 0x9493c(rip),r14d; test;
                 * jne skip`).  imports_fixup_done==0 means the block (heap creation
                 * + init_user_process_params) RUNS, so a NULL ProcessHeap here means
                 * RtlCreateHeap itself returned NULL — not a skipped block. */
                uint32_t detaching = 0xdeadbeef, imports_fixup = 0xdeadbeef;
                lucas_copy_from_client(st, ntdll + 0x94938, &detaching, 4);
                lucas_copy_from_client(st, ntdll + 0x9493c, &imports_fixup, 4);
                printf("[wine-trace]   ntdll.dll base=0x%lx  process_detaching=0x%x  imports_fixup_done=0x%x\n",
                       (unsigned long)ntdll, detaching, imports_fixup);
                /* the binary-search table the faulting allocator reads (RVA 0x962a0
                 * ptr + 0x962a8 count) · in .bss page 0x96000, NOT the 0x94000 page.
                 * If non-zero here while attach_done==0, this .bss page is stale
                 * (not zero-filled) → wine thinks the table is live → grows it from
                 * the not-yet-created process heap → NULL-heap fault. */
                uint64_t tbl = 0; uint32_t cnt = 0;
                lucas_copy_from_client(st, ntdll + 0x962a0, &tbl, 8);
                lucas_copy_from_client(st, ntdll + 0x962a8, &cnt, 4);
                printf("[wine-trace]   .bss table[0x962a0]=0x%lx count[0x962a8]=0x%x\n",
                       (unsigned long)tbl, cnt);
                /* THE root (per wine heap.c create_heap): RtlCreateHeap uses a STATIC
                 * cs debug-info for the FIRST heap iff the `process_heap` global is
                 * NULL; if it reads non-zero it takes the dynamic path that allocs the
                 * cs DebugInfo from peb->ProcessHeap (still NULL) → this fault.
                 * process_heap global is at .bss RVA 0x93028 (page 0x93000).  Dump it
                 * + a window of page 0x93000 to confirm stale (non-zero) .bss. */
                uint64_t proc_heap_global = 0xdead;
                lucas_copy_from_client(st, ntdll + 0x93028, &proc_heap_global, 8);
                printf("[wine-trace]   process_heap global[0x93028]=0x%lx  (NULL=first-heap static-cs path; non-0=dynamic-alloc → fault)\n",
                       (unsigned long)proc_heap_global);
                for (int k = 0; k < 6; ++k) {
                    uint64_t v = 0;
                    lucas_copy_from_client(st, ntdll + 0x93010 + 8 * k, &v, 8);
                    printf("[wine-trace]   .bss[0x%05x]=0x%lx\n",
                           (unsigned)(0x93010 + 8 * k), (unsigned long)v);
                }
                /* peb->ProcessHeap: TEB(gs_base)->Peb(@+0x60)->ProcessHeap(@+0x30) */
                uint64_t peb = 0, ph = 0;
                if (regs.gs_base) {
                    lucas_copy_from_client(st, (uintptr_t)regs.gs_base + 0x60, &peb, 8);
                    if (peb) lucas_copy_from_client(st, (uintptr_t)peb + 0x30, &ph, 8);
                    printf("[wine-trace]   TEB->Peb=0x%lx  peb->ProcessHeap=0x%lx\n",
                           (unsigned long)peb, (unsigned long)ph);
                }
                for (int k = 0; k < 4; ++k) {
                    uint64_t v = 0;
                    lucas_copy_from_client(st, ntdll + 0x96290 + 8 * k, &v, 8);
                    printf("[wine-trace]   .bss[0x%05x]=0x%lx\n",
                           (unsigned)(0x96290 + 8 * k), (unsigned long)v);
                }
            }
        }
        /* On a jump/call to a bad address (e.g. ifetch at 0x0 = a NULL function
         * pointer), find the call site.  A `call *reg` pushes the return addr at
         * [rsp]; a `jmp *GOT` (PLT tail-jump through an unresolved/NULL entry)
         * pushes nothing, so the real caller is the topmost stack qword that
         * looks like mapped code.  Dump r8-r15 (musl stashes the clone fn in r9;
         * indirect-call targets often sit in r1x) + scan the stack for a code
         * return address so we can map it to the offending library/symbol. */
        if (mr2 /* ifetch */) {
            printf("[lucas]   r8=0x%lx r9=0x%lx r10=0x%lx r11=0x%lx\n",
                   (unsigned long)regs.r8, (unsigned long)regs.r9,
                   (unsigned long)regs.r10, (unsigned long)regs.r11);
            printf("[lucas]   r12=0x%lx r13=0x%lx r14=0x%lx r15=0x%lx\n",
                   (unsigned long)regs.r12, (unsigned long)regs.r13,
                   (unsigned long)regs.r14, (unsigned long)regs.r15);
            uint64_t stk[32] = {0};
            if (lucas_copy_from_client(st, (uintptr_t)regs.rsp, stk, sizeof(stk)) == 0) {
                for (int i = 0; i < 32; ++i) {
                    uint64_t v = stk[i];
                    /* plausible mapped code: main binary or the high .so window */
                    int code = (v >= 0x401000UL && v < 0x600000UL) ||
                               (v >= 0x40000000UL && v < 0x46000000UL);
                    if (code) { printf("[lucas]   stack[+%d]=0x%lx (likely caller / code)\n",
                                       i*8, (unsigned long)v); break; }
                }
            }
        }
    }

    /* v1.0-rc1 lifetime fix · TEARDOWN-RACE CLASSIFICATION.
     *
     * If this is an instruction-fetch VMFault from a forked sharer whose
     * TEXT-owner arena has already been revoked (owner slot no longer alive),
     * the sharer's executable translation to 0x400000 is permanently gone — it
     * can NEVER make progress.  Do NOT feed it into the 64-retry cap loop (that
     * spins out an ifetch storm and reports a misleading code=139 SIGSEGV).
     * Classify it as killed-by-teardown and reap immediately.
     *
     * The ordered-teardown in sotbox_destroy normally reaps sharers BEFORE the
     * owner's revoke, so this is a belt-and-suspenders guard for any sharer that
     * faults in the window before its suspend lands (or a slot reused after a
     * stale owner). owner-gone = the owner slot is empty OR no longer owns seL4
     * objects (its arena was revoked). */
    if (label == LUCAS_FAULT_VM && mr2 /* ifetch */ &&
        st->forked && st->text_owner_slot >= 0) {
        extern lucas_state_t *sotbox_get_slot(int);
        lucas_state_t *owner = sotbox_get_slot(st->text_owner_slot);
        if (owner == NULL || owner == st || !owner->seL4_objects_owned) {
            printf("[lucas] TEARDOWN-RACE · slot=%d pid=%d ifetch-fault faultIP=0x%lx · "
                   "TEXT-owner slot=%d is gone · reaping (stale, not code=139)\n",
                   st->slot_index, st->synthetic_pid, (unsigned long)mr0,
                   st->text_owner_slot);
            seL4_TCB_Suspend(st->client_tcb);
            {
                extern void lucas_threads_suspend_all(lucas_state_t *);
                lucas_threads_suspend_all(st);
            }
            st->exited    = 1;
            st->exit_code = 137;   /* 128+SIGKILL · reaped by teardown, not a crash */
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            return 1;
        }
    }

    /* DOOM-DBG · one-shot ground-truth dump for a TRUSTED box's first VMFault.
     * Confirms whether the loaded opcode bytes at rip match the on-disk ELF
     * (corruption check) and exposes the de-interleaved musl aux[] array +
     * the stack, since the reported fault MRs are internally inconsistent. */
    if (err == 0 && label == LUCAS_FAULT_VM && st->trusted
        && slot >= 0 && slot < MAX_VM_FAULT_SLOTS
        && g_vm_fault_cap[slot] == VM_FAULT_CAP_INITIAL) {
        uint8_t ob[16] = {0};
        if (lucas_copy_from_client(st, (uintptr_t)regs.rip, ob, sizeof(ob)) == 0) {
            printf("[doom-dbg] rip-bytes:");
            for (int i = 0; i < 16; ++i) printf(" %02x", ob[i]);
            printf("\n");
        } else {
            printf("[doom-dbg] rip 0x%lx NOT readable in client\n",
                   (unsigned long)regs.rip);
        }
        uint64_t qw[8] = {0};
        if (lucas_copy_from_client(st, (uintptr_t)regs.rsp, qw, sizeof(qw)) == 0) {
            printf("[doom-dbg] [rsp+0..7]:");
            for (int i = 0; i < 8; ++i) printf(" 0x%lx", (unsigned long)qw[i]);
            printf("\n");
        }
        /* Read other known text locations to test whether the page at rip is
         * coherent: 0x54b8b6 = __init_tls entry (push rbx = 0x53...), and the
         * page base 0x54b000.  If entry reads as code but rip reads as a
         * string on the SAME 4K page, copy_from_client / the mapping is the
         * liar, not the CPU. */
        uint8_t e0[8] = {0}, pb[8] = {0}, lo[8] = {0};
        lucas_copy_from_client(st, 0x54b8b6, e0, sizeof(e0));
        lucas_copy_from_client(st, 0x54b000, pb, sizeof(pb));
        lucas_copy_from_client(st, 0x400000, lo, sizeof(lo));
        printf("[doom-dbg] @0x54b8b6:");
        for (int i=0;i<8;++i) printf(" %02x", e0[i]);
        printf("  @0x54b000:");
        for (int i=0;i<8;++i) printf(" %02x", pb[i]);
        printf("  @0x400000:");
        for (int i=0;i<8;++i) printf(" %02x", lo[i]);
        printf("\n");
        uint64_t ax[8] = {0};   /* de-interleaved aux[]: ax[3]=PHDR ax[4]=PHENT ax[5]=PHNUM */
        if (lucas_copy_from_client(st, (uintptr_t)regs.rdi, ax, sizeof(ax)) == 0) {
            printf("[doom-dbg] [rdi+0..7] aux[]: ");
            for (int i = 0; i < 8; ++i) printf(" a%d=0x%lx", i, (unsigned long)ax[i]);
            printf("\n");
        } else {
            printf("[doom-dbg] rdi 0x%lx NOT readable\n", (unsigned long)regs.rdi);
        }

        /* PHYS-ALIAS SCAN · the clobbered text page (0x54b000) was byte-correct
         * at pre-resume but holds foreign content now, and the box made NO
         * syscall before this fault → some vaddr the box WROTE shares the SAME
         * physical frame as 0x54b000.  Get the paddr of each page's frame and
         * scan text + data/bss + the early mmap window for a paddr collision. */
        uint64_t target_pa = 0;
        seL4_CPtr fc = vspace_get_cap(&st->client_vspace_abs, (void *)0x54b000UL);
        if (fc) {
            seL4_X86_Page_GetAddress_t r = seL4_X86_Page_GetAddress(fc);
            if (!r.error) target_pa = (uint64_t)r.paddr;
        }
        printf("[doom-dbg] FAULT paddr(0x54b000)=0x%lx cap=%lu · scanning for alias…\n",
               (unsigned long)target_pa, (unsigned long)fc);
        if (target_pa) {
            int hits = 0;
            /* ranges: text, data+bss, stack, the obsd mmap window */
            struct { uint64_t lo, hi; } rg[] = {
                {0x400000UL, 0x5c5000UL}, {0x7c5000UL, 0x8a1000UL},
                {0x10000000UL, 0x10101000UL}, {0x40000000UL, 0x40120000UL},
            };
            for (int g = 0; g < 4 && hits < 12; ++g) {
                for (uint64_t v = rg[g].lo; v < rg[g].hi && hits < 12; v += 0x1000) {
                    if (v == 0x54b000UL) continue;
                    seL4_CPtr c = vspace_get_cap(&st->client_vspace_abs, (void *)v);
                    if (!c) continue;
                    seL4_X86_Page_GetAddress_t pr = seL4_X86_Page_GetAddress(c);
                    if (!pr.error && (uint64_t)pr.paddr == target_pa) {
                        printf("[doom-dbg] ALIAS! vaddr=0x%lx shares paddr=0x%lx with 0x54b000\n",
                               (unsigned long)v, (unsigned long)target_pa);
                        ++hits;
                    }
                }
            }
            if (!hits) printf("[doom-dbg] no paddr alias found in scanned ranges\n");
        }
    }

    if (--g_vm_fault_cap[slot] <= 0) {
        printf("[lucas] non-syscall fault cap reached (slot=%d) · suspending client\n",
               st->slot_index);
        seL4_TCB_Suspend(st->client_tcb);
        /* M2-bug-5 · same cleanup as the orderly exit_group path: also
         * suspend any pthread child TCBs so they don't outlive the
         * parent and contaminate the next sotBox to take this slot. */
        {
            extern void lucas_threads_suspend_all(lucas_state_t *);
            lucas_threads_suspend_all(st);
        }
        st->exited    = 1;
        st->exit_code = 139;   /* SIGSEGV-ish */
        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
        return 1;
    }
    /* Reply without changes · keep state coherent for next iteration. */
    seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
    return 0;
}

/*
 * lucas_fault_loop — legacy wrapper (kept for compatibility).
 * Calls lucas_handle_one_fault in a loop until the client exits.
 * L3b no longer uses this directly; orch_fault_loop is the main loop.
 */
void lucas_fault_loop(lucas_state_t *st) {
    printf("[lucas] fault loop entering (legacy path, slot=%d)\n", st->slot_index);
    while (!st->exited) {
        seL4_Word badge;
        seL4_MessageInfo_t info = seL4_Recv(st->fault_ep, &badge);
        (void)badge;
        if (lucas_handle_one_fault(st, info)) break;
    }
    printf("[lucas] fault loop exited · client_exit_code=%d\n", st->exit_code);
}
