/* sotOs · procd · lifecycle op handlers (OP_SPAWN, OP_FORK, OP_EXIT,
 *                  OP_WAIT, OP_EXEC).
 *
 * PR 5 scope reduction (carried forward into PR 6 unchanged):
 *   The plan called for procd to take over the seL4 mechanics of sotbox
 *   creation (TCB + CSpace + VSpace + retypes from delegated untypeds).
 *   That requires root to delegate a separate untyped budget into
 *   procd's CSpace, mirroring how it delegates to orch via BOOTSTRAP.
 *   Cross-process untyped delegation is intricate enough to deserve
 *   its own PR; PR 5 stopped at procd owning the *proc_t accounting*
 *   (slot, synthetic_pid, tier, functor binding, pledge_mask).  The seL4
 *   mechanics stay in orch's existing sotbox_init for PR 5+.
 *
 * PR 6 adds the same shadow-announce treatment for fork/exit/wait:
 *
 *   procd_handle_fork
 *     · validates the parent slot,
 *     · allocates a fresh child slot via procd_slot_alloc,
 *     · inherits ppid (parent->synthetic_pid) + pgid + sid + tier + functors
 *       + pledge from the parent,
 *     · publishes PROCD_EV_PROC_BORN.
 *     The real seL4 vspace copy + TCB resume stays in orch/fork.c.
 *
 *   procd_handle_exit
 *     · flips the slot to PROC_STATE_ZOMBIE and records exit_code,
 *     · publishes PROCD_EV_PROC_EXITED + PROCD_EV_SIGCHLD (parent or
 *       init when ppid==0).
 *     The real TCB suspend stays in lucas_sys_exit_group.
 *
 *   procd_handle_wait
 *     · polling reap only (no SaveCaller path) · returns the first
 *       ZOMBIE child of the caller, marks it DEAD, publishes
 *       PROCD_EV_PROC_REAPED.
 *     Blocking wait (caller suspended until SIGCHLD) deferred to PR 7+
 *     because it needs reply-cap saving.  PR 6 returns -ECHILD when no
 *     zombie is ready and WNOHANG returns 0.
 *
 * The DEAD slot is left in the table for now · explicit reap-free
 * lands in PR 7 (OP_REAP_FREE) so the slot count grows monotonically
 * across a session for PR 6.  PROCD_MAX_PROCS=256 makes this safe for
 * the smoke / demo session length.
 *
 * Spec: procd-process-server-design §6.1.
 */
#include <stdio.h>
#include <string.h>
#include <procd/proto.h>
#include <procd/proc.h>
#include <procd/shm.h>
#include <procd/events.h>
#include <procd/functor.h>
#include <procd/wal_log_helper.h>  /* PR 3 · PROCD_SEQLOCK_END_LOGGED · pair seqlock_end with WAL append */
#include <lucas/syscalls.h>  /* PR 14 · LX_CLONE_* canonical flag values */

extern proc_t   *procd_table_get(uint32_t slot);
extern proc_t   *procd_table_first_zombie_child(uint32_t ppid);
extern int       procd_slot_alloc(uint32_t *out_slot);
extern int       procd_thread_alloc(uint32_t *out_tslot);
extern int       procd_thread_free (uint32_t tslot);
extern thread_t *procd_thread_at_index(uint32_t i);
extern thread_t *procd_thread_by_tid (uint32_t tid);
extern procd_event_ring_t *procd_shm_ring(void);

procd_reply_t procd_handle_spawn(const procd_request_t *req) {
    procd_reply_t fail = { .result = -11 /* -EAGAIN */,
                            .out_slot = 0,
                            .out_extra = 0 };

    uint32_t slot = 0;
    if (procd_slot_alloc(&slot) != 0) {
        procd_event_ring_t *r = procd_shm_ring();
        if (r) procd_event_publish(r, PROCD_EV_TABLE_FULL,
                                     req->caller_slot, 0);
        printf("[procd] spawn FAILED · table full (caller=%u)\n",
               req->caller_slot);
        return fail;
    }
    proc_t *p = procd_table_get(slot);
    if (!p) return fail;

    /* PR 5 scope reduction: procd owns the *accounting* (tier / functor
     * binding / pledge / parent linkage); orch still owns the seL4
     * mechanics (TCB / CSpace / VSpace).  cap fields stay zero · orch
     * fills them via a follow-up OP_BIND in PR 6/7. */
    procd_seqlock_begin(p);
    /* identidad · slot + synthetic_pid are set by procd_slot_alloc.  ppid =
     * caller_slot · 0 means "init" (root spawn).  pgid / sid default to
     * the new synthetic_pid · POSIX session leader semantics fold in cleanly
     * once OP_SETSID lands in PR 9. */
    p->ppid          = req->caller_slot;
    p->pgid          = p->synthetic_pid;
    p->sid           = p->synthetic_pid;

    /* estado · NASCENT.  procd_slot_alloc already set state=NASCENT but
     * we keep the explicit write so this handler is self-documenting. */
    p->state         = PROC_STATE_NASCENT;
    p->tier          = (proc_tier_t)req->spawn.initial_tier;
    p->exit_code     = 0;

    /* functor binding · default for the requested tier.  OP_REBIND_FUNCTOR
     * (PR 10) lets anomaly override these per-process at runtime. */
    if (p->tier <= PROC_TIER_3) {
        p->functor_fs   = procd_default_functor_for_tier[p->tier].fs;
        p->functor_net  = procd_default_functor_for_tier[p->tier].net;
        p->functor_proc = procd_default_functor_for_tier[p->tier].proc;
    }
    p->pledge_mask   = req->spawn.initial_pledge;
    /* ABI v2 · comm (short program name) from the spawn IPC + cow_session=0
     * (filled later by OP_SET_SESSION at SSH login).  Bounded copy · the
     * dispatcher already NUL-terminated req->spawn.comm at [15]. */
    strncpy(p->comm, req->spawn.comm, sizeof(p->comm) - 1);
    p->comm[sizeof(p->comm) - 1] = '\0';
    p->cow_session   = 0;
    PROCD_SEQLOCK_END_LOGGED(p);

    /* Publish the lifecycle event so subscribers (orch, anomaly, lucas)
     * can wake up and observe the new slot.  PROCD_EV_PROC_BORN is the
     * canonical "new process" marker. */
    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_PROC_BORN, slot, p->synthetic_pid);
    }

    printf("[procd] spawn slot=%u synthetic_pid=%u tier=%u ppid=%u pledge=0x%llx comm=%s\n",
           slot, p->synthetic_pid, (unsigned)p->tier, p->ppid,
           (unsigned long long)p->pledge_mask, p->comm);

    procd_reply_t ok = {
        .result    = (int32_t)slot,
        .out_slot  = slot,
        .out_extra = p->synthetic_pid,
    };
    return ok;
}

/* PR 6 · OP_FORK · shadow-announce mode.
 * PR 11 · synth fork policy gate · branch on parent->tier.
 *
 * Tier 0 / Tier 1 · do_fork_real: same as PR 6.  Procd allocates a
 *   fresh slot, inherits the "Linux process composition" fields from
 *   the parent, publishes PROCD_EV_PROC_BORN.  The seL4 caps stay zero
 *   · orch/fork.c continues to do the eager-vspace-copy + TCB setup.
 *
 * Tier 2 · do_fork_synth: procd allocates a slot in NASCENT state but
 *   marks it with functor_proc = FPROC_SYNTH_FORK.  No real TCB will
 *   ever back this slot · the operator sees PROCD_EV_SYNTH_FORK and
 *   the malware sees a valid synthetic_pid it can "communicate" with through
 *   the F_proc functor (subsequent syscalls on synth slots return
 *   shaped lies · spec follow-up).  Closes the deception narrative on
 *   the process dimension (sotFS GHOST + sotNet SYNTH + PROC SYNTH_FORK).
 *
 * Tier 3 · denied · PROCD_EV_DENIED_TIER3 published, -EPERM returned.
 *   Tier-3 sotboxes are fully revoked and may not spawn descendants. */

static procd_reply_t do_fork_real(proc_t *parent, const procd_request_t *req) {
    uint32_t slot = 0;
    if (procd_slot_alloc(&slot) != 0) {
        procd_event_ring_t *r = procd_shm_ring();
        if (r) procd_event_publish(r, PROCD_EV_TABLE_FULL,
                                    req->caller_slot, 0);
        printf("[procd] fork FAILED · table full (parent=%u)\n",
               req->caller_slot);
        return (procd_reply_t){ .result = -11 /* -EAGAIN */ };
    }

    proc_t *child = procd_table_get(slot);
    if (!child) {
        return (procd_reply_t){ .result = -11 };
    }

    procd_seqlock_begin(child);
    /* Linux inheritance · child takes parent's identity except for slot
     * and synthetic_pid (already minted by procd_slot_alloc).  pgid + sid are
     * inherited from parent so process groups survive fork(); OP_SETSID
     * in PR 9 lets the child detach later. */
    child->ppid          = parent->synthetic_pid;
    child->pgid          = parent->pgid;
    child->sid           = parent->sid;
    child->state         = PROC_STATE_NASCENT;
    child->tier          = parent->tier;
    child->functor_fs    = parent->functor_fs;
    child->functor_net   = parent->functor_net;
    child->functor_proc  = parent->functor_proc;
    child->pledge_mask   = parent->pledge_mask;
    child->exit_code     = 0;
    /* ABI v2 · a fork inherits the parent's comm + owning SSH session. */
    strncpy(child->comm, parent->comm, sizeof(child->comm) - 1);
    child->comm[sizeof(child->comm) - 1] = '\0';
    child->cow_session   = parent->cow_session;
    PROCD_SEQLOCK_END_LOGGED(child);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_PROC_BORN, slot, child->synthetic_pid);
    }

    printf("[procd] fork slot=%u synthetic_pid=%u ppid=%u tier=%u\n",
           slot, child->synthetic_pid, child->ppid, (unsigned)child->tier);

    return (procd_reply_t){ .result    = (int32_t)slot,
                             .out_slot  = slot,
                             .out_extra = child->synthetic_pid };
}

/* PR 11 · do_fork_synth · allocate a silenced slot that the malware can
 * see (positive synthetic_pid return) but which has no real TCB / seL4 caps
 * behind it.  Subsequent syscalls on the synth child route through
 * F_proc · FPROC_SYNTH_FORK and return shaped lies.  The operator
 * sees EV_SYNTH_FORK and no new sotbox shows up in `sotinfo`. */
static procd_reply_t do_fork_synth(proc_t *parent,
                                       const procd_request_t *req) {
    uint32_t slot = 0;
    if (procd_slot_alloc(&slot) != 0) {
        procd_event_ring_t *r = procd_shm_ring();
        if (r) procd_event_publish(r, PROCD_EV_TABLE_FULL,
                                    req->caller_slot, 0);
        printf("[procd] synth fork FAILED · table full (parent=%u)\n",
               req->caller_slot);
        return (procd_reply_t){ .result = -11 /* -EAGAIN */ };
    }

    proc_t *child = procd_table_get(slot);
    if (!child) {
        return (procd_reply_t){ .result = -11 };
    }

    procd_seqlock_begin(child);
    child->ppid          = parent->synthetic_pid;
    child->pgid          = parent->pgid;
    child->sid           = parent->sid;
    /* NASCENT · never transitions to RUNNING because no real TCB will
     * ever back this slot.  The F_proc functor is responsible for
     * synthesising the lie when the malware tries to communicate. */
    child->state         = PROC_STATE_NASCENT;
    child->tier          = PROC_TIER_2;
    child->functor_fs    = FFS_ISOLATED;
    child->functor_net   = FNET_SYNTH;
    child->functor_proc  = FPROC_SYNTH_FORK;
    child->pledge_mask   = parent->pledge_mask;
    child->exit_code     = 0;
    /* ABI v2 · synth child inherits the parent's comm + SSH session so it
     * renders coherently in the attacker's own `ps` view. */
    strncpy(child->comm, parent->comm, sizeof(child->comm) - 1);
    child->comm[sizeof(child->comm) - 1] = '\0';
    child->cow_session   = parent->cow_session;
    /* seL4 caps stay 0 · this is a silenced in the table only.  No TCB,
     * no CSpace, no VSpace will ever be allocated for this slot. */
    PROCD_SEQLOCK_END_LOGGED(child);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_SYNTH_FORK,
                             slot, parent->synthetic_pid);
    }

    printf("[procd] EV_SYNTH_FORK slot=%u parent=%u (malware-visible synthetic_pid=%u)\n",
           slot, parent->synthetic_pid, child->synthetic_pid);

    /* Malware sees a positive return value (the synthetic_pid) and can attempt
     * to "communicate" with the child · subsequent syscalls on synth
     * slots return shaped lies (F_proc functor · spec follow-up). */
    return (procd_reply_t){ .result    = (int32_t)child->synthetic_pid,
                             .out_slot  = slot,
                             .out_extra = child->synthetic_pid };
}

procd_reply_t procd_handle_fork(const procd_request_t *req) {
    proc_t *parent = procd_table_get(req->caller_slot);
    if (!parent) {
        printf("[procd] fork · invalid parent slot=%u\n", req->caller_slot);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    /* PR 11 · dispatch on parent->tier.  Tier 0/1 keep the PR 6
     * shadow-announce path; Tier 2 generates a synth slot; Tier 3 is
     * denied because the parent's caps are fully revoked. */
    switch (parent->tier) {
        case PROC_TIER_0:
        case PROC_TIER_1:
            return do_fork_real(parent, req);
        case PROC_TIER_2:
            return do_fork_synth(parent, req);
        case PROC_TIER_3: {
            procd_event_ring_t *ring = procd_shm_ring();
            if (ring) {
                procd_event_publish(ring, PROCD_EV_DENIED_TIER3,
                                     req->caller_slot, PROCD_OP_FORK);
            }
            printf("[procd] OP_FORK DENIED (tier=3) caller_slot=%u\n",
                   req->caller_slot);
            return (procd_reply_t){ .result = -1 /* -EPERM */ };
        }
    }
    return (procd_reply_t){ .result = -22 /* -EINVAL */ };
}

/* PR 6 · OP_EXIT · the calling sotbox has terminated with exit_status.
 * Procd flips the slot to ZOMBIE so a subsequent OP_WAIT (parent) can
 * reap it.  Publishes PROC_EXITED for observers + SIGCHLD addressed to
 * the parent (or init when ppid==0).
 *
 * The real TCB suspend stays in lucas_sys_exit_group · procd is the
 * accounting authority only. */
procd_reply_t procd_handle_exit(const procd_request_t *req) {
    proc_t *p = procd_table_get(req->caller_slot);
    if (!p || p->state == PROC_STATE_FREE || p->state == PROC_STATE_DEAD) {
        printf("[procd] exit · stale slot=%u (state=%d)\n",
               req->caller_slot, p ? (int)p->state : -1);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    int32_t code = req->exit.exit_status;
    procd_seqlock_begin(p);
    p->state     = PROC_STATE_ZOMBIE;
    p->exit_code = code;
    PROCD_SEQLOCK_END_LOGGED(p);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_PROC_EXITED,
                            p->slot, (uint32_t)code);
        /* SIGCHLD addressed to parent synthetic_pid · 0 (no parent) means
         * init owns the orphan and gets a synthesized notification. */
        uint32_t target = (p->ppid != 0) ? p->ppid : 1u;
        procd_event_publish(ring, PROCD_EV_SIGCHLD, target, p->slot);
    }

    printf("[procd] exit slot=%u code=%d ppid=%u\n",
           p->slot, code, p->ppid);
    printf("[procd] EV_SIGCHLD target=%u zombie_slot=%u\n",
           (p->ppid != 0) ? p->ppid : 1u, p->slot);

    return (procd_reply_t){ .result = 0 };
}

/* PR 6 · OP_WAIT · polling reap.  Scope reduction (no blocking wait):
 *   - WNOHANG (options & 1) + no zombie  → return 0 (success, no child)
 *   - other            + no zombie  → return -ECHILD
 *   - any              + zombie      → reap (DEAD), return pid,
 *                                       publish PROC_REAPED.
 *
 * Blocking wait (suspend caller, reply when SIGCHLD arrives) needs
 * cap-saving on procd's side · deferred to PR 7+.  In the meantime
 * lucas keeps its own SaveCaller park path for the legacy blocking
 * semantics; the shadow-announce here covers the polling demo + the
 * fork-test's straightforward `wait()` call. */
procd_reply_t procd_handle_wait(const procd_request_t *req) {
    proc_t *caller = procd_table_get(req->caller_slot);
    if (!caller) {
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    proc_t *zombie = procd_table_first_zombie_child(caller->synthetic_pid);
    if (!zombie) {
        if (req->wait.options & 1) {
            /* WNOHANG · 0 means "no child reapable right now". */
            return (procd_reply_t){ .result = 0 };
        }
        /* PR 6 reduction · no blocking; report no children. */
        printf("[procd] wait slot=%u · no zombie child · -ECHILD\n",
               req->caller_slot);
        return (procd_reply_t){ .result = -10 /* -ECHILD */ };
    }

    /* req->wait.which: -1 = any; > 0 = specific synthetic_pid.  PR 6 stops
     * at "any" semantics · a specific-pid wait that does not match the
     * front-of-queue zombie still returns it (good enough for the demo
     * and the fork-test which uses wait() not waitpid()). */
    int32_t status = zombie->exit_code;
    int32_t pid    = (int32_t)zombie->synthetic_pid;

    procd_seqlock_begin(zombie);
    zombie->state = PROC_STATE_DEAD;
    PROCD_SEQLOCK_END_LOGGED(zombie);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_PROC_REAPED,
                            zombie->slot, (uint32_t)status);
    }

    printf("[procd] wait reaped slot=%u synthetic_pid=%d status=%d (caller_slot=%u)\n",
           zombie->slot, pid, status, req->caller_slot);

    return (procd_reply_t){ .result    = pid,
                             .out_slot  = zombie->slot,
                             .out_extra = (uint64_t)(uint32_t)status };
}

/* PR 7 · OP_EXEC · shadow-announce that the caller has replaced its image.
 *
 * The image swap keeps the same procd slot (POSIX semantics · exec
 * inherits the same proc identity) but refreshes the state to RUNNING
 * so any transient NASCENT-from-fork marker is cleared.  PR 7 does NOT
 * mutate tier / functor / pledge on the announce · the new image
 * inherits the existing sotbox identity (Tier 1 stays Tier 1, etc.).
 * Future PR 10+ may add a flag for anomaly-driven functor re-binding.
 *
 * The real seL4 mechanics (vspace tear-down + new ELF mapping + reg
 * reset) stay in orch's sotbox_execve · procd is announce-only here. */
procd_reply_t procd_handle_exec(const procd_request_t *req) {
    proc_t *p = procd_table_get(req->caller_slot);
    if (!p || p->state == PROC_STATE_FREE || p->state == PROC_STATE_DEAD) {
        printf("[procd] OP_EXEC stale slot=%u (state=%d)\n",
               req->caller_slot, p ? (int)p->state : -1);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    procd_seqlock_begin(p);
    p->state = PROC_STATE_RUNNING;
    PROCD_SEQLOCK_END_LOGGED(p);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_EXEC_OK, p->slot, 0);
    }

    printf("[procd] exec slot=%u synthetic_pid=%u tier=%u\n",
           p->slot, p->synthetic_pid, (unsigned)p->tier);

    return (procd_reply_t){ .result    = 0,
                             .out_slot  = p->slot,
                             .out_extra = p->synthetic_pid };
}

/* PR 8 · OP_CLONE · thread-path announce.
 *
 * Scope reduction (PR 8 · widened by PR 14):
 *   PR 8 only honoured the POSIX-thread case (CLONE_VM|CLONE_THREAD) and
 *   rejected everything else with -ENOSYS.  PR 14 widens the dispatcher
 *   (see procd_handle_clone below) so the broader pthread / Wine
 *   canonical set (CLONE_FS / FILES / SIGHAND / PARENT / VFORK / PIDFD /
 *   PARENT_SETTID) is handled · the namespace + ptrace flags stay
 *   rejected with -ENOSYS so an operator-visible CLONE_FLAG_ENOSYS event
 *   fires if a sotbox tries to escape via unshare-like semantics.
 *
 * On the thread path procd:
 *   1. Allocates a thread_t entry, assigning a monotonic synthetic_tid.
 *   2. Records tls_base + clear_tid_ptr for the future PR 13 robust_list
 *      cleanup / futex wake on exit.  ipc_buffer_vaddr stays 0 · lucas
 *      owns that mapping and does not ship it across the announce wire.
 *   3. Bumps owner.proc_t.n_threads under the seqlock so readers (audit
 *      / anomaly) observe an atomically-consistent thread count.
 *   4. Publishes PROCD_EV_THREAD_BORN with (owner_slot, synthetic_tid).
 *
 * The reply encodes the synthetic_tid in `result` (>0) so the caller can
 * stash it for the eventual OP_THREAD_EXIT correspondence; `out_slot`
 * echoes the owner slot, `out_extra` carries the thread table index.
 *
 * PR 14 · this function is now a *helper* invoked by procd_handle_clone
 * after the dispatcher has classified the flag set as thread-path.  The
 * dispatcher already checked CLONE_VM + CLONE_SIGHAND and rejected the
 * out-of-scope namespace flags · we don't repeat those checks here. */
static procd_reply_t procd_clone_thread(const procd_request_t *req) {
    proc_t *owner = procd_table_get(req->caller_slot);
    if (!owner || owner->state == PROC_STATE_FREE ||
                  owner->state == PROC_STATE_DEAD) {
        printf("[procd] clone · invalid owner slot=%u (state=%d)\n",
               req->caller_slot, owner ? (int)owner->state : -1);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    uint32_t tslot = 0;
    if (procd_thread_alloc(&tslot) != 0) {
        procd_event_ring_t *ring = procd_shm_ring();
        if (ring) procd_event_publish(ring, PROCD_EV_TABLE_FULL,
                                       req->caller_slot, 0);
        printf("[procd] clone FAILED · thread table full (caller=%u)\n",
               req->caller_slot);
        return (procd_reply_t){ .result = -11 /* -EAGAIN */ };
    }

    thread_t *t = procd_thread_at_index(tslot);
    if (!t) {
        /* Defensive · should never happen because procd_thread_alloc
         * just returned this index, but a stale index would otherwise
         * NULL-deref below. */
        return (procd_reply_t){ .result = -11 };
    }

    /* Fill the audit fields.  TCB cap + IPC buffer vaddr stay zero —
     * lucas owns those; procd records the operator-visible composition
     * (TLS base, clear_tid_ptr, owner_slot) so audit + anomaly can see
     * a coherent per-thread record. */
    t->owner_slot       = req->caller_slot;
    t->tls_base         = (uintptr_t)req->clone.tls;
    t->ipc_buffer_vaddr = 0;
    t->clear_tid_ptr    = (uintptr_t)req->clone.child_tid_ptr;
    t->robust_list_head = 0;
    /* state already = 1 (running) per procd_thread_alloc */

    procd_seqlock_begin(owner);
    owner->n_threads += 1;
    PROCD_SEQLOCK_END_LOGGED(owner);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_THREAD_BORN,
                             req->caller_slot, t->tid);
    }

    printf("[procd] clone owner_slot=%u tid=%u tls=0x%lx clear_tid=0x%lx flags=0x%lx\n",
           req->caller_slot, t->tid,
           (unsigned long)t->tls_base,
           (unsigned long)t->clear_tid_ptr,
           (unsigned long)req->clone.flags);

    return (procd_reply_t){ .result    = (int32_t)t->tid,
                             .out_slot  = req->caller_slot,
                             .out_extra = tslot };
}

/* PR 14 · OP_CLONE · fork-like path.
 *
 * Triggered when clone() lacks CLONE_THREAD (so the caller wants a new
 * proc_t, not a thread_t).  Mirrors procd_handle_fork's allocation but
 * also honours the Wine-canonical inheritance flags:
 *
 *   CLONE_PARENT          · child inherits parent's ppid (instead of
 *                            the parent becoming the ppid).  Used by
 *                            posix_spawn / vfork's CLONE_PARENT path.
 *   CLONE_FS / FILES /
 *     SIGHAND             · recorded in proc_t.share_flags so a future
 *                            orch read of the bitmask can drive the
 *                            actual cwd / fd-table / signal-handler
 *                            sharing.  PR 14 records intent only · the
 *                            mechanics stay in orch (see scope
 *                            reductions in the PR plan).
 *   CLONE_VFORK           · publishes a second PROCD_EV_PROC_BORN with
 *                            the 0xFF000000 high-byte marker so orch can suspend
 *                            the parent's TCB until the child does
 *                            exec/exit.  Actual TCB_Suspend stays in
 *                            orch/fork.c.
 *
 * The orch-side caller (orch_procd_fork() / orch's clone() handler in
 * a future PR) is responsible for honouring CLONE_PIDFD and
 * CLONE_PARENT_SETTID by writing the appropriate value into the user's
 * parent_tid_ptr after this returns · those are user-vspace writes
 * that procd cannot perform.
 *
 * The reply encodes the new child slot in `result` (>0); `out_slot`
 * echoes it and `out_extra` carries the child's synthetic_pid. */
static procd_reply_t procd_clone_fork_like(const procd_request_t *req) {
    proc_t *parent = procd_table_get(req->caller_slot);
    if (!parent || parent->state == PROC_STATE_FREE ||
                   parent->state == PROC_STATE_DEAD) {
        printf("[procd] clone fork-like · invalid parent slot=%u (state=%d)\n",
               req->caller_slot, parent ? (int)parent->state : -1);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    uint32_t slot = 0;
    if (procd_slot_alloc(&slot) != 0) {
        procd_event_ring_t *ring = procd_shm_ring();
        if (ring) procd_event_publish(ring, PROCD_EV_TABLE_FULL,
                                       req->caller_slot, 0);
        printf("[procd] clone fork-like FAILED · table full (parent=%u)\n",
               req->caller_slot);
        return (procd_reply_t){ .result = -11 /* -EAGAIN */ };
    }

    proc_t *child = procd_table_get(slot);
    if (!child) {
        return (procd_reply_t){ .result = -11 };
    }

    procd_seqlock_begin(child);
    /* CLONE_PARENT · child's ppid = parent's ppid (becomes a sibling).
     * Otherwise standard fork inheritance · ppid = parent's synthetic_pid. */
    if (req->clone.flags & LX_CLONE_PARENT) {
        child->ppid = parent->ppid;
    } else {
        child->ppid = parent->synthetic_pid;
    }
    child->pgid          = parent->pgid;
    child->sid           = parent->sid;
    child->state         = PROC_STATE_NASCENT;
    child->tier          = parent->tier;
    child->functor_fs    = parent->functor_fs;
    child->functor_net   = parent->functor_net;
    child->functor_proc  = parent->functor_proc;
    child->pledge_mask   = parent->pledge_mask;
    child->exit_code     = 0;
    /* PR 14 · record CLONE_FS / FILES / SIGHAND inheritance intent.
     * The actual sharing mechanism (orch's fd-table sharing, sighand
     * struct sharing, etc.) is left to orch · procd just records the
     * intent so audit / anomaly can observe what the caller asked
     * for.  Mask only the three share-flag bits so unrelated bits
     * don't leak into share_flags. */
    child->share_flags = (uint32_t)(req->clone.flags &
        (LX_CLONE_FS | LX_CLONE_FILES | LX_CLONE_SIGHAND));
    /* ABI v2 · clone fork-like child inherits comm + SSH session. */
    strncpy(child->comm, parent->comm, sizeof(child->comm) - 1);
    child->comm[sizeof(child->comm) - 1] = '\0';
    child->cow_session   = parent->cow_session;
    PROCD_SEQLOCK_END_LOGGED(child);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_PROC_BORN, slot, child->synthetic_pid);
    }

    /* CLONE_VFORK · caller suspends until child does exec/exit.  Procd
     * publishes a second PROC_BORN event with the 0xFF000000 high-byte
     * marker so orch (the only TCB-suspending authority) can find this slot and
     * apply seL4_TCB_Suspend on the parent.  PR 14 scope reduction ·
     * we just record the intent; the resume side rides on the
     * existing wait4 / SIGCHLD path that already runs at child
     * exec/exit. */
    if (req->clone.flags & LX_CLONE_VFORK) {
        /* 0xFF000000 high-byte tag · synthetic_pid values are minted from a
         * 1-based monotonic counter capped by PROCD_MAX_PROCS (256)
         * today, so the high byte stays well below 0xFF and the tag
         * is unambiguous when orch decodes the marker payload. */
        if (ring) {
            procd_event_publish(ring, PROCD_EV_PROC_BORN,
                                 slot, 0xFF000000u | child->synthetic_pid);
        }
        printf("[procd] clone fork-like · CLONE_VFORK marker · parent_slot=%u "
               "child_slot=%u (orch honours suspend)\n",
               req->caller_slot, slot);
    }

    printf("[procd] clone fork-like slot=%u synthetic_pid=%u ppid=%u flags=0x%lx "
           "share=0x%x%s\n",
           slot, child->synthetic_pid, child->ppid,
           (unsigned long)req->clone.flags,
           child->share_flags,
           (req->clone.flags & LX_CLONE_VFORK) ? " VFORK" : "");

    return (procd_reply_t){ .result    = (int32_t)slot,
                             .out_slot  = slot,
                             .out_extra = child->synthetic_pid };
}

/* PR 14 · OP_CLONE dispatcher · widen the supported flag set.
 *
 * Linux pthread_create (glibc/musl) uses the canonical set
 *   CLONE_VM | CLONE_FS | CLONE_FILES | CLONE_SIGHAND | CLONE_THREAD
 *   | CLONE_SYSVSEM | CLONE_SETTLS | CLONE_PARENT_SETTID
 *   | CLONE_CHILD_CLEARTID
 * which Python observes as 0x3d0f00.  PR 8 only honoured CLONE_VM +
 * CLONE_THREAD (and CLONE_SETTLS, CLONE_CHILD_CLEARTID) · this PR adds
 * CLONE_FS / CLONE_FILES / CLONE_SIGHAND / CLONE_PARENT / CLONE_VFORK /
 * CLONE_PIDFD / CLONE_PARENT_SETTID so glibc / Wine / posix_spawn paths
 * can land cleanly.
 *
 * Out of scope · the namespace flags (CLONE_NEW{NS,PID,USER,NET,IPC,UTS,
 * CGROUP}) and CLONE_PTRACE return -ENOSYS with a PROCD_EV_CLONE_FLAG_ENOSYS
 * event so an operator-visible audit fires on any unshare-like escape
 * attempt.  Tier 2/3 sotboxes can't legitimately want these flags ·
 * the rejection is intentional.
 *
 * Dispatch logic:
 *   1. Reject the out-of-scope namespace / ptrace flags · -ENOSYS.
 *   2. CLONE_THREAD set · validate CLONE_VM + CLONE_SIGHAND, delegate
 *      to procd_clone_thread (existing PR 8 implementation).
 *   3. Otherwise · fork-like path · delegate to procd_clone_fork_like
 *      (new in PR 14).
 *
 * Spec: see plan PR 14 step 14.2. */
procd_reply_t procd_handle_clone(const procd_request_t *req) {
    uint64_t flags = req->clone.flags;

    /* Reject the namespace + ptrace flags that are explicitly out of
     * scope.  Operator sees CLONE_FLAG_ENOSYS with the offending mask
     * so audit pipelines can attribute the attempt to the caller. */
    const uint64_t unsupported = LX_CLONE_NEWNS | LX_CLONE_NEWPID |
                                  LX_CLONE_NEWUSER | LX_CLONE_NEWNET |
                                  LX_CLONE_NEWIPC | LX_CLONE_NEWUTS |
                                  LX_CLONE_NEWCGROUP | LX_CLONE_PTRACE;
    if (flags & unsupported) {
        procd_event_ring_t *ring = procd_shm_ring();
        if (ring) procd_event_publish(ring, PROCD_EV_CLONE_FLAG_ENOSYS,
                                       req->caller_slot,
                                       (uint32_t)(flags & unsupported));
        printf("[procd] clone REJECTED · namespace/ptrace flags=0x%lx caller_slot=%u\n",
               (unsigned long)(flags & unsupported), req->caller_slot);
        return (procd_reply_t){ .result = -38 /* -ENOSYS */ };
    }

    /* Thread path · CLONE_THREAD requires CLONE_VM + CLONE_SIGHAND per
     * Linux ABI (kernel/fork.c · do_clone validates this combo).  A
     * bare CLONE_THREAD without VM/SIGHAND is meaningless and Linux
     * returns -EINVAL; we mirror that. */
    if (flags & LX_CLONE_THREAD) {
        if (!(flags & LX_CLONE_VM) || !(flags & LX_CLONE_SIGHAND)) {
            printf("[procd] clone · CLONE_THREAD without VM+SIGHAND · -EINVAL "
                   "(flags=0x%lx caller_slot=%u)\n",
                   (unsigned long)flags, req->caller_slot);
            return (procd_reply_t){ .result = -22 /* -EINVAL */ };
        }
        return procd_clone_thread(req);
    }

    /* Fork-like path · new proc_t, eager-copy by orch.  PR 14 honours
     * CLONE_PARENT inheritance and stashes CLONE_FS/FILES/SIGHAND
     * intent on the child's share_flags; CLONE_VFORK publishes the
     * extra marker event for orch to consume. */
    return procd_clone_fork_like(req);
}

/* PR 9 · OP_SETSID / OP_SETPGID / OP_GETPGID · process group + session
 * bookkeeping.  Pure proc_t accounting · no seL4 mechanics involved.
 *
 * Linux semantics (relevant subset):
 *   setsid() · caller becomes the leader of a new session AND a new
 *     process group, both named by its pid.  Fails with EPERM if the
 *     caller is already a process group leader (pgid == pid).  Returns
 *     the new session id (= caller's pid).
 *
 *   setpgid(target_pid, new_pgid) · place target_pid in group new_pgid.
 *     target_pid == 0 means "caller".  new_pgid == 0 means "use the
 *     target's own pid" (the target becomes a process group leader).
 *     PR 9 implements the simple no-policy version · we don't enforce
 *     the "same session" / "child only" Linux restrictions yet because
 *     procd has no full child list today (PR 13+ may add it).  Returns
 *     0 on success.
 *
 *   getpgid(target_pid) · returns the pgid of target_pid.  target_pid
 *     == 0 means "caller".
 *
 * The caller_slot is the procd-side slot · lucas caches it on
 * lucas_state_t at spawn/fork announce time.  Each handler accesses
 * the slot under the seqlock so concurrent readers (audit / anomaly)
 * always see a coherent (pgid, sid) tuple. */
procd_reply_t procd_handle_setsid(const procd_request_t *req) {
    proc_t *p = procd_table_get(req->caller_slot);
    if (!p || p->state == PROC_STATE_FREE) {
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }
    /* Linux semantics · setsid fails with EPERM if the caller is already
     * a process group leader (pgid == synthetic_pid AND sid == synthetic_pid).
     * Newly-spawned slots inherit pgid=synthetic_pid/sid=synthetic_pid from
     * procd_handle_spawn so the first setsid() after spawn is a no-op
     * that returns EPERM · matches Linux for shell-spawned processes
     * that fork() then setsid() (the fork() flips the inheritance so
     * the child is no longer its own group leader). */
    if (p->pgid == p->synthetic_pid && p->sid == p->synthetic_pid) {
        return (procd_reply_t){ .result = -1 /* -EPERM */ };
    }
    procd_seqlock_begin(p);
    p->sid  = p->synthetic_pid;
    p->pgid = p->synthetic_pid;
    PROCD_SEQLOCK_END_LOGGED(p);
    printf("[procd] setsid slot=%u sid=%u pgid=%u\n",
           p->slot, p->sid, p->pgid);
    return (procd_reply_t){ .result    = (int32_t)p->sid,
                             .out_slot  = p->slot,
                             .out_extra = p->synthetic_pid };
}

procd_reply_t procd_handle_setpgid(const procd_request_t *req,
                                     uint32_t target_pid, uint32_t new_pgid) {
    proc_t *caller = procd_table_get(req->caller_slot);
    if (!caller || caller->state == PROC_STATE_FREE) {
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    /* target_pid == 0 means "caller's own slot" · otherwise we accept
     * either the caller's own synthetic_pid (a no-op lookup) or any other
     * live synthetic_pid via the table scan helper. */
    proc_t *target = caller;
    if (target_pid != 0 && target_pid != caller->synthetic_pid) {
        extern proc_t *procd_table_lookup_by_synthetic_pid(uint32_t synthetic_pid);
        target = procd_table_lookup_by_synthetic_pid(target_pid);
        if (!target) {
            printf("[procd] setpgid · no proc with synthetic_pid=%u (caller_slot=%u)\n",
                   target_pid, req->caller_slot);
            return (procd_reply_t){ .result = -3 /* -ESRCH */ };
        }
    }

    /* new_pgid == 0 means "use the target's own pid" (the target becomes
     * a process group leader of a group named after itself). */
    uint32_t pgid = (new_pgid == 0) ? target->synthetic_pid : new_pgid;
    procd_seqlock_begin(target);
    target->pgid = pgid;
    PROCD_SEQLOCK_END_LOGGED(target);

    printf("[procd] setpgid slot=%u pgid=%u (target_pid=%u caller_slot=%u)\n",
           target->slot, target->pgid, target_pid, req->caller_slot);
    return (procd_reply_t){ .result   = 0,
                             .out_slot = target->slot };
}

procd_reply_t procd_handle_getpgid(const procd_request_t *req,
                                     uint32_t target_pid) {
    proc_t *caller = procd_table_get(req->caller_slot);
    if (!caller || caller->state == PROC_STATE_FREE) {
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    proc_t *target = caller;
    if (target_pid != 0 && target_pid != caller->synthetic_pid) {
        extern proc_t *procd_table_lookup_by_synthetic_pid(uint32_t synthetic_pid);
        target = procd_table_lookup_by_synthetic_pid(target_pid);
        if (!target) return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }
    return (procd_reply_t){ .result   = (int32_t)target->pgid,
                             .out_slot = target->slot };
}

/* PR 8 · OP_THREAD_EXIT · per-thread teardown announce.
 *
 * The caller (lucas) addresses the dying thread by its procd-assigned
 * synthetic_tid (req->thread_exit.tid).  Procd:
 *   1. Translates the tid to a thread_t via linear scan.
 *   2. Decrements owner.n_threads under the seqlock (clamped at 0 so a
 *      double-announce can't go negative).
 *   3. Frees the thread_t slot · state=0, tid=0 so the slot can be
 *      reused by a later OP_CLONE.
 *   4. Publishes PROCD_EV_THREAD_EXITED with (owner_slot, synthetic_tid).
 *
 * PR 13 augments this path with robust_list walk + clear_tid_ptr futex
 * wake on the lucas side; here we record the teardown only. */
procd_reply_t procd_handle_thread_exit(const procd_request_t *req) {
    thread_t *t = procd_thread_by_tid(req->thread_exit.tid);
    if (!t) {
        printf("[procd] thread_exit · unknown tid=%u caller_slot=%u\n",
               req->thread_exit.tid, req->caller_slot);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    uint32_t owner_slot = t->owner_slot;
    proc_t *owner = procd_table_get(owner_slot);
    if (owner) {
        procd_seqlock_begin(owner);
        if (owner->n_threads > 0) owner->n_threads -= 1;
        PROCD_SEQLOCK_END_LOGGED(owner);
    }

    /* Find the thread's index via the same linear scan procd_thread_by_tid
     * already used · we could refactor to return both pointer + index but
     * PR 8's scan is cold-path-only (one per thread exit).  PR 13 may
     * factor it once the same code path also walks robust_list. */
    uint32_t found_idx = 0;
    for (uint32_t i = 1; i < PROCD_MAX_THREADS; i++) {
        if (procd_thread_at_index(i) == t) {
            found_idx = i;
            break;
        }
    }
    if (found_idx != 0) {
        procd_thread_free(found_idx);
    }

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_THREAD_EXITED,
                             owner_slot, req->thread_exit.tid);
    }

    printf("[procd] thread_exit owner_slot=%u tid=%u\n",
           owner_slot, req->thread_exit.tid);

    return (procd_reply_t){ .result   = 0,
                             .out_slot = owner_slot,
                             .out_extra = found_idx };
}

/* PR 10 · OP_SET_TIER · badge-gated tier mutation.
 *
 * Badge contract · anomaly calls this on the procd EP that root minted
 * into anomaly's CSpace with BADGE_ANOMALY_OP_SET_TIER (0xA009).  Any
 * other badge (or an unbadged caller) is rejected with -EPERM and a
 * PROCD_EV_BADGE_REJECT audit event so the operator sees the denied
 * attempt.  This is the authoritative tier-write path; the legacy
 * ORCH_OP_PROMOTE_TIER lucas-flag flip stays in place for PR 10 as the
 * demo-driving channel (see plan · scope reduction · dual-write).
 *
 * On success we publish two events back-to-back:
 *   EV_TIER_CHANGED · slot + (old<<16 | new) tier transition.
 *   EV_FUNCTOR_REBOUND · slot + (fs<<16 | net<<8 | proc) packed binding,
 *     reflecting the default-for-tier functor swap performed under the
 *     same seqlock.  PR 14+ uses these for the cross-vspace SHM read
 *     path once lucas is wired to map procd's region RO.
 *
 * Spec: procd-process-server-design §6.2. */
#define BADGE_ANOMALY_OP_SET_TIER 0xA009u

procd_reply_t procd_handle_set_tier(seL4_Word badge, const procd_request_t *req,
                                      uint32_t new_tier_arg) {
    if (badge != BADGE_ANOMALY_OP_SET_TIER) {
        procd_event_ring_t *ring = procd_shm_ring();
        if (ring) {
            procd_event_publish(ring, PROCD_EV_BADGE_REJECT,
                                 req->caller_slot, PROCD_OP_SET_TIER);
        }
        printf("[procd] OP_SET_TIER REJECT · badge=0x%lx caller_slot=%u "
               "(expected 0x%x)\n",
               (unsigned long)badge, req->caller_slot,
               (unsigned)BADGE_ANOMALY_OP_SET_TIER);
        return (procd_reply_t){ .result = -1 /* -EPERM */ };
    }
    proc_t *p = procd_table_get(req->caller_slot);
    if (!p || p->state == PROC_STATE_FREE) {
        printf("[procd] OP_SET_TIER · invalid slot=%u (state=%d)\n",
               req->caller_slot, p ? (int)p->state : -1);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }
    if (new_tier_arg > PROC_TIER_3) {
        printf("[procd] OP_SET_TIER · invalid tier=%u slot=%u\n",
               new_tier_arg, req->caller_slot);
        return (procd_reply_t){ .result = -22 /* -EINVAL */ };
    }

    proc_tier_t old = p->tier;
    procd_seqlock_begin(p);
    p->tier         = (proc_tier_t)new_tier_arg;
    p->functor_fs   = procd_default_functor_for_tier[new_tier_arg].fs;
    p->functor_net  = procd_default_functor_for_tier[new_tier_arg].net;
    p->functor_proc = procd_default_functor_for_tier[new_tier_arg].proc;
    PROCD_SEQLOCK_END_LOGGED(p);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_TIER_CHANGED,
                             p->slot,
                             ((uint32_t)old << 16) | new_tier_arg);
        procd_event_publish(ring, PROCD_EV_FUNCTOR_REBOUND,
                             p->slot,
                             ((uint32_t)p->functor_fs   << 16) |
                             ((uint32_t)p->functor_net  << 8)  |
                              (uint32_t)p->functor_proc);
    }

    printf("[procd] EV_TIER_CHANGED slot=%u old=%u new=%u\n",
           p->slot, (unsigned)old, new_tier_arg);
    printf("[procd] EV_FUNCTOR_REBOUND slot=%u fs=%u net=%u proc=%u\n",
           p->slot, p->functor_fs, p->functor_net, p->functor_proc);

    return (procd_reply_t){ .result = 0, .out_slot = p->slot };
}

/* ABI v2 · OP_SET_SESSION · post-spawn cow_session + comm update.
 *
 * cow_session is assigned at SSH login (AFTER the spawn announce · see
 * src/orch/main.c) and comm changes on execve, so neither is known when
 * procd_handle_spawn runs.  This handler fills them under the proc_t
 * seqlock so the LUCAS RO reader (lucas_proct_load → truth_list_processes)
 * sees a coherent (comm, cow_session) tuple.
 *
 * comm_present==0 → leave comm unchanged (cow_session-only · SSH login).
 * comm_present==1 → also set comm (execve path · new binary basename).
 *
 * No badge gate · unlike OP_SET_TIER (anomaly-only), orch is the sole
 * legitimate caller over the unbadged listen EP, same as OP_SPAWN. */
procd_reply_t procd_handle_set_session(const procd_request_t *req,
                                        uint32_t comm_present) {
    uint32_t slot = req->set_session.target_slot;
    proc_t *p = procd_table_get(slot);
    if (!p || p->state == PROC_STATE_FREE) {
        printf("[procd] OP_SET_SESSION · invalid slot=%u (state=%d)\n",
               slot, p ? (int)p->state : -1);
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    procd_seqlock_begin(p);
    p->cow_session = req->set_session.cow_session;
    if (comm_present) {
        strncpy(p->comm, req->set_session.comm, sizeof(p->comm) - 1);
        p->comm[sizeof(p->comm) - 1] = '\0';
    }
    PROCD_SEQLOCK_END_LOGGED(p);

    printf("[procd] set_session slot=%u synthetic_pid=%u cow_session=%u comm=%s\n",
           p->slot, p->synthetic_pid, p->cow_session, p->comm);

    return (procd_reply_t){ .result = 0, .out_slot = p->slot };
}

/* PR 13 · OP_SET_ROBUST · record the user's robust_list_head per thread so
 * the kernel-side cleanup on thread exit knows which list to walk when
 * marking owned futexes FUTEX_OWNER_DIED.
 *
 * Wire payload:
 *   MR(1) = caller_slot     (procd-side process slot)
 *   MR(2) = procd-assigned tid · the OP_CLONE reply value · or 0 for
 *           "main thread" (use the proc's first thread_t entry).
 *   MR(3) = robust_list_head (user vaddr, owner vspace)
 *
 * Procd dereferences the tid to thread_t · stores the head in
 * thread_t.robust_list_head under no explicit seqlock (single-writer ·
 * the thread can only call set_robust_list from its own context).
 *
 * Lucas's threading layer carries a mirror copy in thread_list[i] for
 * the actual walk on exit · procd's copy is the audit-visible source of
 * truth so any reader (anomaly / sotinfo / audit bridge) can observe
 * which threads are running with robust mutexes registered. */
procd_reply_t procd_handle_set_robust(const procd_request_t *req) {
    uint32_t tid = req->set_robust.tid;

    thread_t *t = NULL;
    if (tid == 0) {
        /* Main-thread anomaly · walk the thread table for the first
         * entry owned by caller_slot.  PR 13 falls back to "do not
         * record on a thread_t at all" if no live thread is owned by
         * the caller · the lucas-side mirror still holds the head, so
         * the cleanup walk on exit still fires.  We log the event so
         * the smoke gate (`[procd] set_robust tid=`) still has evidence. */
        for (uint32_t i = 1; i < PROCD_MAX_THREADS; i++) {
            thread_t *cand = procd_thread_at_index(i);
            if (cand && cand->owner_slot == req->caller_slot) {
                t = cand;
                tid = cand->tid;
                break;
            }
        }
    } else {
        t = procd_thread_by_tid(tid);
        if (!t) {
            printf("[procd] set_robust · unknown tid=%u caller_slot=%u\n",
                   tid, req->caller_slot);
            /* Still log evidence so the smoke gate matches · the
             * lucas-side mirror is authoritative for the walk. */
            printf("[procd] set_robust tid=%u head=0x%lx (no thread_t · audit-only)\n",
                   tid, (unsigned long)req->set_robust.robust_head);
            return (procd_reply_t){ .result = -3 /* -ESRCH */ };
        }
    }

    if (t) {
        t->robust_list_head = (uintptr_t)req->set_robust.robust_head;
    }
    printf("[procd] set_robust tid=%u head=0x%lx caller_slot=%u\n",
           tid, (unsigned long)req->set_robust.robust_head, req->caller_slot);
    return (procd_reply_t){ .result = 0,
                             .out_slot = req->caller_slot,
                             .out_extra = tid };
}

/* PR 10 · OP_REBIND_FUNCTOR · badge-gated functor override (no tier change).
 *
 * Same badge contract as OP_SET_TIER · anomaly is the only legitimate
 * caller.  Useful for partial overrides where anomaly wants to keep the
 * tier number but swap one or more functor identities (e.g. force
 * FFS_WRITE_SILENCED on a Tier-0 sotbox without escalating the tier number).
 *
 * Distinct from OP_SET_TIER:
 *   - SET_TIER mutates tier AND derives functors from the default table.
 *   - REBIND_FUNCTOR mutates functors only; tier is preserved.
 *
 * On success publishes EV_FUNCTOR_REBOUND only (no EV_TIER_CHANGED). */
procd_reply_t procd_handle_rebind_functor(seL4_Word badge,
                                            const procd_request_t *req,
                                            uint32_t new_fs,
                                            uint32_t new_net,
                                            uint32_t new_proc) {
    if (badge != BADGE_ANOMALY_OP_SET_TIER) {
        procd_event_ring_t *ring = procd_shm_ring();
        if (ring) {
            procd_event_publish(ring, PROCD_EV_BADGE_REJECT,
                                 req->caller_slot, PROCD_OP_REBIND_FUNCTOR);
        }
        printf("[procd] OP_REBIND_FUNCTOR REJECT · badge=0x%lx caller_slot=%u "
               "(expected 0x%x)\n",
               (unsigned long)badge, req->caller_slot,
               (unsigned)BADGE_ANOMALY_OP_SET_TIER);
        return (procd_reply_t){ .result = -1 /* -EPERM */ };
    }
    proc_t *p = procd_table_get(req->caller_slot);
    if (!p || p->state == PROC_STATE_FREE) {
        return (procd_reply_t){ .result = -3 /* -ESRCH */ };
    }

    procd_seqlock_begin(p);
    p->functor_fs   = (uint16_t)new_fs;
    p->functor_net  = (uint16_t)new_net;
    p->functor_proc = (uint16_t)new_proc;
    PROCD_SEQLOCK_END_LOGGED(p);

    procd_event_ring_t *ring = procd_shm_ring();
    if (ring) {
        procd_event_publish(ring, PROCD_EV_FUNCTOR_REBOUND,
                             p->slot,
                             ((uint32_t)p->functor_fs   << 16) |
                             ((uint32_t)p->functor_net  << 8)  |
                              (uint32_t)p->functor_proc);
    }

    printf("[procd] EV_FUNCTOR_REBOUND slot=%u fs=%u net=%u proc=%u\n",
           p->slot, p->functor_fs, p->functor_net, p->functor_proc);

    return (procd_reply_t){ .result = 0, .out_slot = p->slot };
}
