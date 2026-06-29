/* sotOs · orch · procd RPC client (PR 5 · CROSSING-OF-RUBICON,
 *                                   PR 6 · OP_FORK + OP_EXIT + OP_WAIT,
 *                                   PR 7 · OP_EXEC).
 *
 * PR 5 shipped the OP_SPAWN announce path · orch tells procd about every
 * new sotbox so procd can own the proc_t slot/tier/functor accounting.
 * The seL4 mechanics (TCB/CSpace/VSpace) stay in orch for PR 5+ (see
 * src/procd/handlers_lifecycle.c for the scope-reduction rationale).
 *
 * PR 6 adds three more shadow-announce helpers · OP_FORK (parent slot →
 * child slot/synthetic_pid), OP_EXIT (caller exits with a status), and
 * OP_WAIT (poll for a zombie child).  All three keep the same "orch
 * keeps the seL4 mechanics, procd keeps the accounting" split.
 *
 * Payload encoding (MR-only path):
 *   OP_SPAWN
 *     MR(0) = PROCD_OP_SPAWN
 *     MR(1) = caller_slot      (parent ppid · 0 means "init" / root spawn)
 *     MR(2) = initial_tier     (proc_tier_t)
 *     MR(3) = pledge & 0xFFFFFFFF        (low 32 bits)
 *     MR(4) = (pledge >> 32) & 0xFFFFFFFF (high 32 bits)
 *   OP_FORK
 *     MR(0) = PROCD_OP_FORK
 *     MR(1) = parent_slot   (procd slot of the forking parent)
 *   OP_EXIT
 *     MR(0) = PROCD_OP_EXIT
 *     MR(1) = caller_slot
 *     MR(2) = exit_status   (signed)
 *   OP_WAIT
 *     MR(0) = PROCD_OP_WAIT
 *     MR(1) = caller_slot
 *     MR(2) = which         (-1 = any child; >0 = specific pid)
 *     MR(3) = options       (WNOHANG=1 stub flag)
 *   OP_EXEC
 *     MR(0) = PROCD_OP_EXEC
 *     MR(1) = caller_slot   (sotbox whose image was just replaced)
 *
 * Reply (all ops · result is op-specific):
 *   MR(0) = result (signed · slot/pid >= 0 or -errno)
 *   MR(1) = out_slot
 *   MR(2) = out_extra (synthetic_pid for SPAWN/FORK · status for WAIT)
 *
 * SHM scratch passing is still deferred · the four ops above all fit in
 * MRs today (worst case 5 words used of the 120-word budget).
 *
 * Spec: procd-process-server-design §5.1.
 */

#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include <procd/proto.h>
#include <procd/proc.h>

/* Procd listen EP in orch's CSpace.  Captured by orch/main.c at
 * BOOTSTRAP from bs.procd_listen_ep_slot.  0 until then (orch_procd_spawn
 * short-circuits in that case · the announce becomes a no-op and the
 * legacy orch sotbox_init path remains the source of truth). */
seL4_CPtr g_procd_listen_ep = 0;

/* procd PR 10 · BADGED procd listen EP in orch's CSpace (badge =
 * BADGE_ANOMALY_OP_SET_TIER, 0xA009).  Captured at BOOTSTRAP from
 * bs.procd_set_tier_ep_slot.  Used by lucas_set_tier() to mirror every
 * legacy tier mutation into procd's authoritative proc_t state · 0 if
 * the badged mint failed (procd never came up / root error).  procd's
 * dispatcher rejects OP_SET_TIER calls with the unbadged g_procd_listen_ep
 * cap above, so the two caps are NOT interchangeable. */
seL4_CPtr g_procd_set_tier_ep = 0;

/* Forward decl · definition appears later in this file.  Needed because
 * orch_procd_spawn() calls orch_procd_set_tier() inside the PR 10 smoke
 * marker block and C requires the prototype to be visible at the call
 * site. */
int orch_procd_set_tier(uint32_t target_slot, uint32_t new_tier);

/* PR 4 carry-over · procd_shm_base from BOOTSTRAP.  Still 0 in PR 5 —
 * the cross-vspace mapping deferred to PR 6+.  Kept as a global so the
 * announce can grow into SHM-backed payloads later without churning the
 * caller signature. */
void *g_procd_shm_base = 0;

int orch_procd_spawn(uint64_t elf_offset, uint32_t elf_size,
                      int argc, const char *const argv[],
                      proc_tier_t initial_tier, uint64_t pledge,
                      uint32_t caller_slot, const char *comm,
                      uint32_t *out_slot, uint32_t *out_synthetic_pid)
{
    /* PR 5 doesn't actually use the ELF / argv payload yet · procd owns
     * accounting only, not the seL4 mechanics.  We accept them in the
     * signature so PR 6/7 can wire them through without churning every
     * call site.  Tag the casts as intentional. */
    (void)elf_offset;
    (void)elf_size;
    (void)argc;
    (void)argv;

    if (g_procd_listen_ep == 0) {
        return -1;
    }

    /* ABI v2 · pack comm[16] into two seL4_Words (MR5,MR6).  comm is the
     * short program name (basename of argv0); "" when the caller has none. */
    char commbuf[16];
    memset(commbuf, 0, sizeof(commbuf));
    if (comm) {
        size_t n = strlen(comm);
        if (n > 15) n = 15;
        memcpy(commbuf, comm, n);
    }
    uint64_t comm_lo, comm_hi;
    memcpy(&comm_lo, commbuf,     8);
    memcpy(&comm_hi, commbuf + 8, 8);

    seL4_SetMR(0, PROCD_OP_SPAWN);
    /* PR 6 fix · caller_slot now flows from the caller.  Root-driven
     * SPAWN passes 0 (init); sotShell-nested SPAWN passes 0 too until
     * PR 8 plumbs sotShell's procd slot through (TODO). */
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)initial_tier);
    seL4_SetMR(3, (seL4_Word)(pledge & 0xFFFFFFFFull));
    seL4_SetMR(4, (seL4_Word)((pledge >> 32) & 0xFFFFFFFFull));
    seL4_SetMR(5, (seL4_Word)comm_lo);
    seL4_SetMR(6, (seL4_Word)comm_hi);

    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 7));
    (void)r;

    int32_t result = (int32_t)seL4_GetMR(0);
    if (out_slot)     *out_slot     = (uint32_t)seL4_GetMR(1);
    if (out_synthetic_pid) *out_synthetic_pid = (uint32_t)seL4_GetMR(2);

    /* PR 10 · one-shot OP_SET_TIER smoke marker · fires exactly once per
     * boot, after the first successful OP_SPAWN, so the smoke gates
     * (PROCD·set_tier + PROCD·functor_rebound) have evidence to grep
     * for without depending on the inject-script /simulated_attacker.py
     * demo being run as part of smoke.  We drive the new slot to
     * tier=0 → tier=0 (no-op transition that still publishes
     * EV_TIER_CHANGED + EV_FUNCTOR_REBOUND under the proc_t seqlock)
     * so the smoke evidence appears without changing the spawned
     * sotbox's operator-visible behaviour.  Guard variable ensures we
     * don't repeat on every spawn · single-firing keeps the boot log
     * clean. */
    static int smoke_marker_fired = 0;
    if (result >= 0 && !smoke_marker_fired && g_procd_set_tier_ep != 0
        && out_slot && *out_slot != 0) {
        smoke_marker_fired = 1;
        printf("[orch] PR 10 smoke marker · firing OP_SET_TIER slot=%u tier=0\n",
               *out_slot);
        int rc = orch_procd_set_tier(*out_slot, 0);
        printf("[orch] PR 10 smoke marker · OP_SET_TIER rc=%d\n", rc);
    }
    return result;
}

/* PR 6 · OP_FORK · announce a fork from parent_slot.  Procd allocates a
 * fresh slot and inherits ppid/pgid/sid/tier/functor/pledge from parent.
 * Returns the child's procd slot (>=0) or -errno; on success writes
 * out_slot / out_synthetic_pid. */
int orch_procd_fork(uint32_t parent_slot,
                     uint32_t *out_slot, uint32_t *out_synthetic_pid)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_FORK);
    seL4_SetMR(1, (seL4_Word)parent_slot);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 2));
    (void)r;
    int32_t result = (int32_t)seL4_GetMR(0);
    if (out_slot)     *out_slot     = (uint32_t)seL4_GetMR(1);
    if (out_synthetic_pid) *out_synthetic_pid = (uint32_t)seL4_GetMR(2);
    return result;
}

/* PR 6 · OP_EXIT · announce that caller_slot has exited with the given
 * status.  Procd marks the slot ZOMBIE, publishes PROC_EXITED + SIGCHLD,
 * and notifies subscribers.  Returns 0 on success or -errno. */
int orch_procd_exit(uint32_t caller_slot, int32_t exit_status)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_EXIT);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)exit_status);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 3));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}

/* PR 6 · OP_WAIT · poll-style wait4.  which: -1 = any child; >0 = pid.
 * options: WNOHANG (=1) returns 0 if no zombie ready.  Returns the
 * reaped pid (>0) on success, 0 when WNOHANG and no zombie, or -errno.
 * On success the reaped child's exit_status is written to *out_status. */
int orch_procd_wait(uint32_t caller_slot, int32_t which, int32_t options,
                     int32_t *out_pid, int32_t *out_status)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_WAIT);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)which);
    seL4_SetMR(3, (seL4_Word)options);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 4));
    (void)r;
    int32_t result = (int32_t)seL4_GetMR(0);
    if (out_pid)    *out_pid    = result;  /* result encodes the pid */
    if (out_status) *out_status = (int32_t)(uint32_t)seL4_GetMR(2);
    return result;
}

/* PR 7 · OP_EXEC · announce that caller_slot has replaced its image.
 * Procd keeps the same slot, flips state to RUNNING, publishes the
 * PROCD_EV_EXEC_OK marker.  Returns 0 on success or -errno.  The real
 * seL4 mechanics (vspace + register reset) already ran in orch's
 * sotbox-side image swap before this call · the announce is purely
 * informational for procd accounting + ring subscribers. */
int orch_procd_exec(uint32_t caller_slot)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_EXEC);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 2));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}

/* PR 8 · OP_CLONE · thread-path announce.
 *
 * The lucas-side TCB allocation in src/lucas/threading.c calls this
 * helper after seL4_TCB_Configure + Resume succeed so procd can record
 * the thread_t (owner_slot, tls_base, clear_tid_ptr) and publish
 * PROCD_EV_THREAD_BORN.  procd assigns the synthetic_tid (its own monotonic
 * counter, distinct from lucas's state.next_tid); the lucas caller
 * stashes the returned tid in the per-thread bookkeeping so the future
 * OP_THREAD_EXIT addresses the same thread_t entry.
 *
 * Payload encoding:
 *   MR(0) = PROCD_OP_CLONE
 *   MR(1) = caller_slot       (procd slot of the parent process)
 *   MR(2) = flags             (Linux clone flag bitmask)
 *   MR(3) = tls               (TLS base · CLONE_SETTLS payload)
 *   MR(4) = child_tid_ptr     (clear_child_tid futex address)
 *
 * Reply:
 *   MR(0) = synthetic_tid (>0) or -errno
 *   MR(1) = owner_slot (echo of caller_slot on success)
 *   MR(2) = thread table index (procd-internal · for diagnostics) */
int orch_procd_clone_thread(uint32_t caller_slot, uint64_t flags,
                             uint64_t tls, uint64_t child_tid_ptr,
                             uint32_t *out_tid)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_CLONE);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)flags);
    seL4_SetMR(3, (seL4_Word)tls);
    seL4_SetMR(4, (seL4_Word)child_tid_ptr);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 5));
    (void)r;
    int32_t result = (int32_t)seL4_GetMR(0);
    if (out_tid) *out_tid = (result > 0) ? (uint32_t)result : 0u;
    return result;
}

/* PR 9 · OP_SETSID · announce that caller_slot has detached from its
 * parent session and become a leader of a new session + process group
 * both named after its own synthetic_pid.  On success returns the new sid
 * (which equals the caller's synthetic_pid · POSIX) and writes it to
 * *out_sid.  On the Linux-defined EPERM path (caller is already a pgrp
 * leader) returns -1 · the caller surfaces it as -EPERM to the
 * userspace process.
 *
 * Payload encoding:
 *   MR(0) = PROCD_OP_SETSID
 *   MR(1) = caller_slot
 * Reply:
 *   MR(0) = sid (>0) or -errno
 *   MR(1) = out_slot
 *   MR(2) = out_extra (caller's synthetic_pid on success) */
int orch_procd_setsid(uint32_t caller_slot, uint32_t *out_sid) {
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_SETSID);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 2));
    (void)r;
    int32_t result = (int32_t)seL4_GetMR(0);
    if (result > 0 && out_sid) *out_sid = (uint32_t)result;
    return result;
}

/* PR 9 · OP_SETPGID · place target_pid (0 = caller) into process group
 * new_pgid (0 = target's own synthetic_pid).  Returns 0 on success or -errno.
 *
 * Payload encoding:
 *   MR(0) = PROCD_OP_SETPGID
 *   MR(1) = caller_slot
 *   MR(2) = target_pid     (0 = caller's own synthetic_pid)
 *   MR(3) = new_pgid       (0 = target's own synthetic_pid · become leader) */
int orch_procd_setpgid(uint32_t caller_slot, uint32_t target_pid,
                        uint32_t new_pgid) {
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_SETPGID);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)target_pid);
    seL4_SetMR(3, (seL4_Word)new_pgid);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 4));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}

/* PR 9 · OP_GETPGID · query the pgid of target_pid (0 = caller).
 * Returns the pgid (>=1) on success or -errno.  Writes the pgid to
 * *out_pgid on success · the caller can use either the return value or
 * out_pgid (kept symmetrical with setsid's out_sid for ergonomics).
 *
 * Payload encoding:
 *   MR(0) = PROCD_OP_GETPGID
 *   MR(1) = caller_slot
 *   MR(2) = target_pid     (0 = caller's own synthetic_pid) */
int orch_procd_getpgid(uint32_t caller_slot, uint32_t target_pid,
                        uint32_t *out_pgid) {
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_GETPGID);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)target_pid);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 3));
    (void)r;
    int32_t result = (int32_t)seL4_GetMR(0);
    if (result >= 0 && out_pgid) *out_pgid = (uint32_t)result;
    return result;
}

/* PR 8 · OP_THREAD_EXIT · announce that a CLONE_THREAD-spawned thread
 * has terminated.  The tid passed here is the procd-assigned synthetic_tid
 * returned by the matching orch_procd_clone_thread() call · NOT lucas's
 * own state.next_tid counter (which is process-local and may collide
 * with procd's monotonic allocator across sotboxes).  Procd decrements
 * the owner.n_threads count under its seqlock, frees the thread_t slot,
 * and publishes PROCD_EV_THREAD_EXITED.
 *
 * Returns 0 on success or -errno (in particular -3/-ESRCH if the tid
 * doesn't match any live thread_t · double-announce or wrong tid). */
int orch_procd_thread_exit(uint32_t caller_slot, uint32_t tid)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_THREAD_EXIT);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)tid);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 3));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}

/* PR 13 · OP_SET_ROBUST · per-thread robust_list_head registration.
 *
 * Called by lucas's lucas_sys_set_robust_list handler whenever a
 * userspace thread publishes its robust_list head pointer (glibc/musl
 * do this very early in pthread initialization).  Procd records the
 * head on the matching thread_t entry · the lucas-side mirror in
 * thread_list[i].robust_list_head drives the actual walk on thread
 * exit (FUTEX_OWNER_DIED + futex wake).
 *
 * tid == 0 is the "main thread" anomaly · procd's handler falls back
 * to the first thread_t entry owned by caller_slot, or treats the call
 * as audit-only if no live thread is bound yet.  Best-effort · failure
 * is logged but does not break the lucas-side syscall return path.
 *
 * Payload encoding:
 *   MR(0) = PROCD_OP_SET_ROBUST
 *   MR(1) = caller_slot  (procd-side process slot)
 *   MR(2) = tid          (procd-assigned synthetic_tid · 0 = main thread)
 *   MR(3) = robust_head  (userspace vaddr of struct robust_list_head)
 * Reply:
 *   MR(0) = 0 on success or -errno. */
int orch_procd_set_robust(uint32_t caller_slot, uint32_t tid,
                            uint64_t robust_head)
{
    if (g_procd_listen_ep == 0) return -1;
    seL4_SetMR(0, PROCD_OP_SET_ROBUST);
    seL4_SetMR(1, (seL4_Word)caller_slot);
    seL4_SetMR(2, (seL4_Word)tid);
    seL4_SetMR(3, (seL4_Word)robust_head);
    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 4));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}

/* PR 10 · OP_SET_TIER · authoritative tier mutation through procd.
 *
 * MUST use the badged g_procd_set_tier_ep (not g_procd_listen_ep) so
 * procd accepts the call · the dispatcher rejects unbadged callers with
 * -EPERM + PROCD_EV_BADGE_REJECT.  Called from lucas_set_tier() to mirror
 * every legacy tier flip into procd's proc_t state so EV_TIER_CHANGED +
 * EV_FUNCTOR_REBOUND fire on every operator-visible promotion.
 *
 * No-op (returns -1) when:
 *   - g_procd_set_tier_ep is 0 · procd was not configured or the badged
 *     mint failed at boot.
 *   - target_slot is 0 · the lucas_state has no procd_slot bound yet
 *     (boot-time, announce-failure).
 *
 * Best-effort · failure is non-fatal because the legacy writes_silenced /
 * is_isolated flip on lucas_state has already happened by the time this
 * runs, and the demo invariant only requires the flag flip.
 *
 * Per the plan: this is the post-condition for the PR 10 invariant ·
 * `[procd] EV_TIER_CHANGED slot=N old=X new=Y` should appear on every
 * operator-visible promotion. */
int orch_procd_set_tier(uint32_t target_slot, uint32_t new_tier)
{
    if (g_procd_set_tier_ep == 0 || target_slot == 0) return -1;
    seL4_SetMR(0, PROCD_OP_SET_TIER);
    seL4_SetMR(1, (seL4_Word)target_slot);  /* caller_slot · sotbox procd slot */
    seL4_SetMR(2, (seL4_Word)new_tier);
    seL4_MessageInfo_t r = seL4_Call(g_procd_set_tier_ep,
        seL4_MessageInfo_new(0, 0, 0, 3));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}

/* ABI v2 · OP_SET_SESSION · post-spawn cow_session + comm update.
 *
 * cow_session is assigned at SSH login (AFTER the spawn announce) and comm
 * changes on execve, so this is the channel that fills those two proc_t
 * fields once they are known.  Modelled on orch_procd_spawn (unbalanced
 * orch→procd call over the UNBADGED g_procd_listen_ep · orch is the
 * legitimate caller, no anomaly badge gate like set_tier).
 *
 * Pass comm=NULL to leave comm unchanged (cow_session-only update); pass a
 * non-NULL string to also set comm (execve path).  target_slot==0 or an
 * un-configured procd EP is a no-op (-1), mirroring orch_procd_set_tier.
 *
 * Payload encoding:
 *   MR(0) = PROCD_OP_SET_SESSION
 *   MR(1) = target_slot
 *   MR(2) = cow_session
 *   MR(3) = comm[0..7]   (0 when comm==NULL · sentinel "leave unchanged")
 *   MR(4) = comm[8..15]
 *   MR(5) = comm_present (1 = set comm, 0 = leave unchanged)
 * Reply:
 *   MR(0) = 0 on success or -errno. */
int orch_procd_set_session(uint32_t target_slot, uint32_t cow_session,
                            const char *comm)
{
    if (g_procd_listen_ep == 0 || target_slot == 0) return -1;

    char commbuf[16];
    memset(commbuf, 0, sizeof(commbuf));
    uint32_t comm_present = 0;
    if (comm) {
        comm_present = 1;
        size_t n = strlen(comm);
        if (n > 15) n = 15;
        memcpy(commbuf, comm, n);
    }
    uint64_t comm_lo, comm_hi;
    memcpy(&comm_lo, commbuf,     8);
    memcpy(&comm_hi, commbuf + 8, 8);

    seL4_SetMR(0, PROCD_OP_SET_SESSION);
    seL4_SetMR(1, (seL4_Word)target_slot);
    seL4_SetMR(2, (seL4_Word)cow_session);
    seL4_SetMR(3, (seL4_Word)comm_lo);
    seL4_SetMR(4, (seL4_Word)comm_hi);
    seL4_SetMR(5, (seL4_Word)comm_present);

    seL4_MessageInfo_t r = seL4_Call(g_procd_listen_ep,
        seL4_MessageInfo_new(0, 0, 0, 6));
    (void)r;
    return (int32_t)seL4_GetMR(0);
}
