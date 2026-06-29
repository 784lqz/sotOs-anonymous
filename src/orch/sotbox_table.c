/*
 * sotOs · orchestrator · multi-sotBox slot table.
 *
 * Each running sotBox occupies one slot.  The slot index + 1 is the
 * badge on the fault EP, so the fault loop can identify which
 * lucas_state_t to dispatch the syscall against.
 *
 * For L3a-T7 the table holds POINTERS to lucas_state_t instances
 * (the structs themselves live on the caller's stack inside
 * lucas_run_l1).  T9+ will move the instances into the table when
 * we add fork() · child sotBoxes need a longer-lived home.
 *
 * L3b-T1: also holds the shared fault EP singleton.
 * L3b-T2: sotbox_try_wakeup_waiter for blocking wait4.
 */

#include <orch/sotbox.h>
#include <orch/proto.h>
#include <orch/arena.h>
#include <vka/capops.h>
#include <vka/object.h>      /* P2a · vka_free_object */
#include <vspace/vspace.h>   /* P2a · vspace_t */
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdbool.h>

/* P2a · safe client-vspace reclaim (spawn.c — needs orch's g_parent_vspace). */
extern void orch_reclaim_client_vspace(vspace_t *client_abs);

static lucas_state_t *g_slots[SOTBOX_MAX_SLOTS];

/* L3b-T4: slot accessor for pipe.c (avoids extern on the static array). */
lucas_state_t *sotbox_get_slot(int i) {
    if (i < 0 || i >= SOTBOX_MAX_SLOTS) return NULL;
    return g_slots[i];
}

/* Curvature-anomaly exemption (strong override of the weak stub in
 * src/sotfs/graph_curvature.c): true when `pid` is a live package-manager box
 * (apk/apt pool · pkg_install set).  Such a box's install legitimately does mass
 * file ops that would otherwise trip the Forman-Ricci RANSOMWARE/LATERAL rules
 * and raise a false alert + tier-escalate.  Self-clearing — when the box reaps it
 * leaves g_slots, so no stale pid stays exempt. */
int sotfs_curvature_exempt(uint32_t pid) {
    if (pid == 0) return 0;
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = g_slots[i];
        if (st && (uint32_t)st->synthetic_pid == pid && st->pkg_install) return 1;
    }
    return 0;
}

/* wait4 · is `synthetic_pid` backed by a REAL running sotbox (a live TCB)?
 * A canary-shell real-fork child (dpkg-deb's decompressor/tar) is announced to
 * procd as FPROC_SYNTH_FORK yet DOES run for real — so wait4's "synth child →
 * return 0" shortcut must NOT fire for it (it made dpkg-deb's blocking
 * waitpid(tar) return 0 → "wait for tar subprocess failed: Success").  True iff
 * some slot carries this synthetic_pid with a live client_tcb. */
int sotbox_pid_has_real_tcb(int synthetic_pid) {
    if (synthetic_pid <= 0) return 0;
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = g_slots[i];
        if (st && st->synthetic_pid == (uint32_t)synthetic_pid && st->client_tcb)
            return 1;
    }
    return 0;
}

/*
 * S-PID · Translate a synthetic_pid (anomaly-ring index, slot+1) to the random
 * display_pid the sotbox sees through getpid().  Returns 0 if synthetic_pid is
 * out of range or the slot is empty.  Used at display-time (anomaly-log
 * reply build) to attach OBSD-ζ display values without disturbing the
 * load-bearing synthetic_pid index in producer call sites.
 */
uint32_t sotbox_synthetic_to_display_pid(uint32_t synthetic_pid) {
    if (synthetic_pid == 0 || synthetic_pid > SOTBOX_MAX_SLOTS) return 0;
    lucas_state_t *st = sotbox_get_slot((int)synthetic_pid - 1);
    if (!st) return 0;
    return (uint32_t)st->display_pid;
}

/* L3b-T1: shared fault EP for all sotBoxes. */
static seL4_CPtr g_orch_fault_ep = 0;

void orch_set_fault_ep(seL4_CPtr ep) { g_orch_fault_ep = ep; }
seL4_CPtr orch_get_fault_ep(void) { return g_orch_fault_ep; }

/* sotFS-β-Phase-B · STO server endpoint delegated from root at BOOTSTRAP.
 * 0 = not delegated (falls back to in-process counter in sto_local.c). */
static seL4_CPtr g_sto_ep = 0;

void orch_set_sto_ep(seL4_CPtr ep) { g_sto_ep = ep; }
seL4_CPtr orch_get_sto_ep(void) { return g_sto_ep; }

/* The UNBADGED STO listen endpoint (orch-owned · the cap orch_spawn_native
 * returned before orch minted its own 0xA003-badged copy).  Kept so orch can
 * mint a DISTINCT per-bench session badge from it — seL4 forbids re-badging an
 * already-badged cap, so the benches' sessions must derive from this unbadged
 * source, not from g_sto_ep. 0 = not available. */
static seL4_CPtr g_sto_listen_ep = 0;
void orch_set_sto_listen_ep(seL4_CPtr ep) { g_sto_listen_ep = ep; }
seL4_CPtr orch_get_sto_listen_ep(void) { return g_sto_listen_ep; }

/* virtio-blk Phase 2b · x86 IOPort cap delegated from root at BOOTSTRAP.
 * 0 = not delegated (PCI probe will be skipped). */
static seL4_CPtr g_io_port_cap = 0;

void orch_set_io_port_cap(seL4_CPtr cap) { g_io_port_cap = cap; }
seL4_CPtr orch_get_io_port_cap(void) { return g_io_port_cap; }

/* A3-Phase-B · external anomaly process event EP.
 * orch sends ORCH_OP_ANOMALY_EVENT to this EP when anomaly_on_write fires.
 * 0 = anomaly process not yet spawned (in-orch fallback rule still runs). */
static seL4_CPtr g_anomaly_ep = 0;

void orch_set_anomaly_ep(seL4_CPtr ep) { g_anomaly_ep = ep; }

/* When a TRUSTED Tier-0e egress handler runs, its network activity happens
 * INSIDE the orch process (the handler drives a nested fault loop on
 * orch_get_fault_ep, NOT the main dispatch).  A synchronous
 * seL4_Call(anomaly_ep) from that context lets anomaly-ext re-enter orch via
 * seL4_Call(orch_ep, ORCH_OP_PROMOTE_TIER) (TCP_OPEN / NET_PRECOMMIT-Rule-D /
 * CURVATURE auto-promote) — but the nested egress fault loop never services
 * orch_ep, so anomaly-ext blocks off its seL4_Recv and the NEXT net event's
 * Call(anomaly_ep) from orch deadlocks.  (Exposed by `pip install`, the first
 * guest to do two DNS resolutions / TCP opens in one egress handler.)  The
 * trusted egress client is OURS, not attacker-controlled, so it is exempt
 * from the malware auto-promote heuristics anyway: while it runs, report the
 * anomaly EP as absent so every emit site (all guard on `ep != 0`) cleanly
 * skips its Call and proceeds with the default COMMIT. */
int g_egress_trusted_active = 0;
seL4_CPtr orch_get_anomaly_ep(void) {
    return g_egress_trusted_active ? 0 : g_anomaly_ep;
}

/* sotNet-γ Phase 3-A · sotOs-net-synth process event EP (Path D).
 * synth_record_redirect() sends ORCH_OP_SYNTH_REDIRECT on this EP.
 * 0 = synth server not yet spawned (Phase 3-A disabled). */
static seL4_CPtr g_synth_event_ep = 0;

void orch_set_synth_event_ep(seL4_CPtr ep) { g_synth_event_ep = ep; }
seL4_CPtr orch_get_synth_event_ep(void) { return g_synth_event_ep; }

int sotbox_alive_count(void) {
    int n = 0;
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i)
        if (g_slots[i] != NULL) ++n;
    return n;
}

int sotbox_alloc_slot(lucas_state_t *st) {
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        if (g_slots[i] == NULL) {
            g_slots[i] = st;
            return i;
        }
    }
    return -1;
}

void sotbox_free_slot(int slot) {
    if (slot >= 0 && slot < SOTBOX_MAX_SLOTS) {
        g_slots[slot] = NULL;
    }
}

/* P2a · orch-owned shm pools etc. attached to a sotbox.  A later P2a task
 * defines the real implementation in the lucas lib; this weak empty stub lets
 * sotbox_destroy link now and is overridden at link time by the strong def. */
__attribute__((weak)) void lucas_free_owned_frames(lucas_state_t *st) { (void)st; }

/*
 * sotbox_destroy — P2a zero-leak teardown.  Manually reclaims every seL4
 * object the reaped sotbox owns so the allocman pool returns to baseline.
 *
 * CRITICAL · the reaped sotbox is NOT a sel4utils_process_t.  Its objects were
 * vka_alloc_*'d one-by-one in create_client_vspace + lucas_client_setup, and
 * the full vka_object_t (incl. the .ut allocman cookie) was captured on the
 * lucas_state_t at that time.  vka_free_object dereferences .ut to return the
 * untyped, so we MUST free the captured originals — a hand-built {.cptr,.ut=0}
 * would NULL-deref the allocator.  Every free is guarded on cptr != 0 so a
 * spawn-FAILURE state (objects never built · seL4_objects_owned==0) and a
 * partially-built one stay safe.
 */
void sotbox_destroy(int slot) {
    if (slot < 0 || slot >= SOTBOX_MAX_SLOTS) return;
    lucas_state_t *st = g_slots[slot];
    if (!st || !st->seL4_objects_owned) return;

    /* P2b · forked children now acquire their OWN arena (fork.c), and the shared-TEXT
     * cap-copies live in the child arena's cslot range so the uniform delete-sweep in
     * sotbox_arena_revoke reclaims them.  So a forked child is reclaimed like any sotbox;
     * only a truly arena-less state (no arena to revoke) is skipped. */
    if (!st->arena) {   /* no arena → nothing to revoke */
        return;
    }

    /* M4 · force-free any wl_shm pools this sotbox still owns (exit-with-live-
     * objects).  Run BEFORE arena revoke so the guest vspace is still valid for
     * the per-pool unmap.  The pool frames are orch-root (not arena), so arena
     * revoke would NOT reclaim them — this is the only place they're freed when
     * the client exits without tearing its wl objects down. */
    {
        extern void orch_shm_pool_free_owner(uint32_t);
        orch_shm_pool_free_owner((uint32_t)st->synthetic_pid);
    }

    /* Release the VFS backend handles pinned by this sotbox's lazy file-backed
     * mmaps (one per mapped shared library · skipped at guest close() so faults
     * could still read).  Without this the GLOBAL sysroot/binstore handle pools
     * leak a slot per library per launch — a 57-lib GTK3 app exhausts them.
     * Pure bookkeeping (no cap/vspace ops), so it is order-independent here.
     *
     * ONLY the OWNER releases: a forked child's lazy_regions[] are a verbatim
     * `*child = *parent` copy (fork.c) that ALIAS the parent's pinned global
     * handle slots, so a child releasing them would double-free / UAF the
     * parent's still-live handles.  The ordered teardown reaps forked sharers
     * BEFORE the owner, so skipping the child here and letting the owner release
     * once is correct.  (A child that pins its OWN post-fork handles would leak
     * them — none do today; per-handle refcounting is the full fix.) */
    if (!st->forked) {
        extern void lucas_release_lazy_regions(lucas_state_t *st);
        lucas_release_lazy_regions(st);
    }
    /* Close any still-open VFS fds (non-lazy-pinned) so their pooled backend
     * handles return to the pool.  Safe for forked children too: their VFS
     * handles are independent clones (lucas_dup_vfs_handles), and lazy-pinned
     * fds are skipped (released by the owner's lucas_release_lazy_regions).
     * Without this, a process reaped with open fds (dpkg's fork tree) leaked a
     * sotfs/union pool slot each → later ld-opens failed → exit 127. */
    {
        extern void lucas_release_open_vfs_fds(lucas_state_t *st);
        lucas_release_open_vfs_fds(st);
    }

    vka_t *vka = st->vka;

    /* The badged fault EP is a MINT/copy of orch's shared fault EP — it is NOT a
     * child of the arena untyped, so seL4_CNode_Revoke won't delete it.  Delete
     * the copy explicitly FIRST (its cslot is in the arena range → the bump
     * reset reclaims the slot).  The shared source EP (orch global cspace) is
     * untouched. */
    if (st->fault_ep) {
        cspacepath_t p; vka_cspace_make_path(vka, st->fault_ep, &p);
        seL4_CNode_Delete(p.root, p.capPtr, p.capDepth);
        st->fault_ep = 0;
    }

    /* v1.0-rc1 lifetime fix · ORDERED TEARDOWN.
     *
     * INVARIANT: no runnable TCB may retain an executable translation to frames
     * belonging to an arena that is about to be revoked.  A forked child's
     * TEXT+RODATA (0x400000) is RO cap-COPIES of THIS slot's arena frames
     * (share_region_ro); revoking this arena deletes those frame objects, so any
     * still-runnable sharer would instruction-fetch-fault at its ELF entry
     * (faultIP=0x40017c, ifetch=1) → exit code=139.  Before we revoke, enumerate
     * every live sharer (forked && text_owner_slot == this slot) and tear it down
     * FIRST: suspend its TCB (stop it executing the soon-dead text), then
     * recursively destroy + free its slot.  The sharer has its OWN arena; its
     * text cap-copies live in ITS cslot range, so its own revoke sweep reclaims
     * them — destroying it here is self-contained and does not touch our frames.
     *
     * Recursion is bounded: a sharer's text_owner_slot points at the ROOT owner
     * (inherited transitively in fork.c), never at a sibling, so this loop never
     * re-enters for `slot` and the depth is 1. */
    for (int s = 0; s < SOTBOX_MAX_SLOTS; ++s) {
        if (s == slot) continue;
        lucas_state_t *sh = g_slots[s];
        if (!sh || !sh->forked || sh->text_owner_slot != slot) continue;
        if (!sh->seL4_objects_owned) continue;   /* already torn down */
        printf("[p2a] ORDERED-TEARDOWN · owner slot=%d pid=%d revoking → first reaping"
               " TEXT sharer slot=%d pid=%d\n",
               slot, st->synthetic_pid, s, sh->synthetic_pid);
        /* Stop the sharer executing the about-to-vanish TEXT before we free it. */
        if (sh->client_tcb) seL4_TCB_Suspend(sh->client_tcb);
        /* Drop any parked kernel reply cap (mirror the fault-loop exit path). */
        if (sh->waiting_reply_cap != 0) {
            cspacepath_t rp; vka_cspace_make_path(sh->vka, sh->waiting_reply_cap, &rp);
            seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
            vka_cspace_free(sh->vka, sh->waiting_reply_cap);
            sh->waiting_reply_cap = 0;
        }
        int sh_pid = sh->synthetic_pid;
        sotbox_destroy(s);                  /* recursion depth 1 (root owner only) */
        sotbox_free_slot(s);
        /* Mark exited + record the zombie BEFORE releasing the child_storage idx:
         * fork_release_storage frees sh's child_storage[] slot, after which `sh`
         * may be reused by a future fork — so it must be the LAST touch of `sh`.
         * (Safe today single-threaded, but the order makes the contract explicit.) */
        sh->exited = 1;
        sotbox_record_exit(sh_pid, 137);    /* 128+SIGKILL · reaped with owner */
        sotbox_fork_release_storage(sh);    /* LAST touch of sh (frees its storage idx) */
    }

    /* Revoke the arena untyped → TCB, client CNode (+ its EP copy), vspace/PML4,
     * IPC frame, ELF/stack frames, page-table intermediates, client-vspace
     * bookkeeping all gone at once; untyped freeIndex resets; cslot bump resets;
     * arena returns to the free-list. */
    sotbox_arena_revoke(st->arena);
    st->arena = NULL;
    /* zero-leak · the revoke just freed + unmapped this slot's arena-backed
     * client-vspace bookkeeping leaf frames; reset the slot's bookkeeping window
     * (reuse its address range + PT next spawn) and drop the net page count. */
    extern void orch_vspace_window_release(int slot);
    orch_vspace_window_release(slot);
    st->seL4_objects_owned = 0;
    /* The cap mirror fields now dangle (objects revoked); zero them so nothing
     * re-uses a stale cptr. */
    st->client_tcb = 0; st->client_cnode = 0; st->client_vspace = 0;
    st->client_ipc_buffer_frame = 0;
    printf("[p2a] destroy slot=%d pid=%d · arena revoked\n", slot, st->synthetic_pid);
}

lucas_state_t *sotbox_lookup_by_badge(seL4_Word badge) {
    /* badge = slot_index + 1; badge==0 means unbadged · ignore. */
    if (badge == 0 || badge > SOTBOX_MAX_SLOTS) return NULL;
    int slot = (int)(badge - 1);
    return g_slots[slot];
}

/* Reaped-but-not-yet-waited-for table.  wait4(pid) pops from here.
 * L3a-T9 single-parent assumption; 32 slots give honest headroom so an
 * eviction is a rare, logged event rather than routine. */
#define MAX_ZOMBIES 32
/* parent_pid · the synthetic_pid of the box that forked this child (0 = unknown,
 * matches any waiter).  Recorded so a wait4(-1)/waitpid only reaps a process's
 * OWN direct children, never a grandchild (Linux semantics).  Without it, a
 * busybox shell's wait4(-1) stole apt-get's `dpkg --print-foreign-architectures`
 * grandchild, hanging `apt-get update` (apt parked on a child reaped by the
 * wrong process). */
static struct { int pid; int exit_code; int parent_pid; bool waiting; uint64_t seq; } g_zombies[MAX_ZOMBIES];
static uint64_t g_zombie_seq      = 0;   /* monotonic insertion order */
static uint64_t g_zombies_evicted = 0;   /* total oldest-evictions (honest accounting) */

void sotbox_record_exit_p(int pid, int exit_code, int parent_pid) {
    /* First free slot. */
    for (int i = 0; i < MAX_ZOMBIES; ++i) {
        if (!g_zombies[i].waiting) {
            g_zombies[i].pid        = pid;
            g_zombies[i].exit_code  = exit_code;
            g_zombies[i].parent_pid = parent_pid;
            g_zombies[i].waiting    = true;
            g_zombies[i].seq        = ++g_zombie_seq;
            return;
        }
    }
    /* Full · evict the OLDEST waiting zombie (smallest seq) so the NEW exit is
     * never lost — the newest exit is the one most likely to be waited on. */
    int oldest = 0;
    for (int i = 1; i < MAX_ZOMBIES; ++i)
        if (g_zombies[i].seq < g_zombies[oldest].seq) oldest = i;
    ++g_zombies_evicted;
    printf("[sotbox] zombie table full · evicted oldest pid=%d (evicted %lu total) to record pid=%d\n",
           g_zombies[oldest].pid, (unsigned long)g_zombies_evicted, pid);
    g_zombies[oldest].pid        = pid;
    g_zombies[oldest].exit_code  = exit_code;
    g_zombies[oldest].parent_pid = parent_pid;
    g_zombies[oldest].waiting    = true;
    g_zombies[oldest].seq        = ++g_zombie_seq;
}

/* Back-compat shim · unknown parent (matches any waiter). */
void sotbox_record_exit(int pid, int exit_code) {
    sotbox_record_exit_p(pid, exit_code, 0);
}

uint64_t sotbox_zombies_evicted(void) { return g_zombies_evicted; }

/* Synthetic pids are slot+1 and a slot is reused the instant its sotbox is
 * reaped — but Linux never reuses a pid while a zombie for it is pending.  A
 * freshly-forked child can be born with a pid that still has a STALE zombie (an
 * earlier same-slot child nobody wait4'd), and a later wait4(pid) FALSE-REAPS it
 * immediately with the old exit code instead of blocking for the new child
 * (broke dpkg -i: wait4(dpkg-split) got the prior pid=2 child's exit_code=0).
 * Purge any pending zombie for `pid` when that pid is (re)born. */
void sotbox_clear_zombie(int pid) {
    for (int i = 0; i < MAX_ZOMBIES; ++i)
        if (g_zombies[i].waiting && g_zombies[i].pid == pid)
            g_zombies[i].waiting = false;
}

/* Deterministic over-capacity proof.  Runs at orch bootstrap BEFORE any
 * sotbox exits, on an empty table, and drains itself so the live table is
 * left pristine.  REAP_TEST_PID_BASE is far above any real synthetic_pid (which is
 * slot+1 <= SOTBOX_MAX_SLOTS) so synthetic pids never collide with a sotbox. */
#define REAP_TEST_PID_BASE 0x70000000
void sotbox_reaper_selftest(void) {
    uint64_t base_evicted = sotbox_zombies_evicted();
    int n = MAX_ZOMBIES + 2;                 /* 2 over capacity */
    for (int k = 0; k < n; ++k)
        sotbox_record_exit(REAP_TEST_PID_BASE + k, 0x100 + k);
    uint64_t evicted = sotbox_zombies_evicted() - base_evicted;
    int out = -1;
    int newest = REAP_TEST_PID_BASE + (n - 1);
    int got = sotbox_reap(newest, &out);
    bool newest_ok = (got == newest && out == (0x100 + (n - 1)));
    int drain = 0;
    while (sotbox_reap(-1, &drain) != -1) { /* pop everything the test inserted */ }
    if (evicted == 2 && newest_ok)
        printf("[sotbox] reaper selftest OK · cap=%d · evicted 2 · newest reapable\n", MAX_ZOMBIES);
    else
        printf("[sotbox] reaper selftest FAILED · evicted=%lu newest_ok=%d\n",
               (unsigned long)evicted, (int)newest_ok);
}

/* L4-T1: dump zombie table entries into entries[] starting at start_idx.
 * Returns number of entries added.  Caller ensures start_idx + added <= max. */
int sotbox_dump_zombies(orch_status_entry_t *entries, int max, int start_idx) {
    int added = 0;
    for (int i = 0; i < MAX_ZOMBIES && start_idx + added < max; ++i) {
        if (g_zombies[i].waiting) {
            orch_status_entry_t *e = &entries[start_idx + added];
            e->slot_index = -2;   /* zombie marker */
            e->synthetic_pid   = g_zombies[i].pid;
            e->exit_code  = g_zombies[i].exit_code;
            e->state      = 4;    /* SOTBOX_STATE_EXITED */
            e->tier       = 0;
            e->name[0]    = '\0';
            ++added;
        }
    }
    return added;
}

/* caller_pid · the synthetic_pid of the wait4 caller.  A zombie is only reapable
 * by its OWN parent (zombie.parent_pid == caller_pid) — or by anyone when the
 * parent is unknown (parent_pid==0, legacy/force-exit) or the caller is unknown
 * (caller_pid==0).  This stops a grandparent's wait4(-1) stealing a grandchild. */
int sotbox_reap_p(int pid_want, int caller_pid, int *out_exit) {
    for (int i = 0; i < MAX_ZOMBIES; ++i) {
        if (!g_zombies[i].waiting) continue;
        if (pid_want != -1 && g_zombies[i].pid != pid_want) continue;
        if (caller_pid != 0 && g_zombies[i].parent_pid != 0 &&
            g_zombies[i].parent_pid != caller_pid) continue;   /* not your child */
        *out_exit = g_zombies[i].exit_code;
        int got = g_zombies[i].pid;
        g_zombies[i].waiting = false;
        return got;
    }
    return -1;
}

/* Back-compat shim · no parent filtering (selftest + legacy callers). */
int sotbox_reap(int pid_want, int *out_exit) {
    return sotbox_reap_p(pid_want, 0, out_exit);
}

/* Returns true if there are any zombies in the reap table that match pid_want
 * OR any living processes in the slot table other than the caller (by slot).
 * Used by wait4 to decide whether to park or return -ECHILD. */
bool sotbox_has_children(int caller_slot) {
    /* Check for zombies. */
    for (int i = 0; i < MAX_ZOMBIES; ++i) {
        if (g_zombies[i].waiting) return true;
    }
    /* Check for living children (any slot != caller_slot that is occupied). */
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        if (i == caller_slot) continue;
        if (g_slots[i] != NULL) return true;
    }
    return false;
}

/* L3b-T2: forward declaration for lucas_copy_to_client (in lucas static lib). */
extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                 const void *src_buf, size_t size);

/*
 * sotbox_try_wakeup_waiter — called by lucas_sys_exit_group when a sotBox exits.
 *
 * Iterates the slot table for any sotBox in WAITING_FOR_CHILD state whose
 * waiting_for_pid matches exited_pid (or is -1 = any child).  If found:
 *   1. Copies wstatus to parent's vspace if waiting_status_vaddr != 0.
 *   2. Re-reads parent's TCB registers, sets rax = exited_pid, rip += 2,
 *      writes back.
 *   3. seL4_Send to the saved reply cap → parent resumes.
 *   4. Frees the cslot, resets state = RUNNING.
 *
 * Returns 1 if a waiter was found and woken, 0 otherwise.
 */
int sotbox_try_wakeup_waiter_p(int exited_pid, int exit_code, int parent_pid) {
    /* Wake the waiter that is the genuine parent of the exited box.  A process
     * tree with two concurrent waiters — e.g. the busybox shell blocked in
     * wait4(-1) on its apt-get child, AND apt-get blocked in waitpid(3) on its
     * own `dpkg --print-foreign-architectures` grandchild — must NOT let the
     * SHELL's wildcard wait STEAL apt-get's child (Linux: wait4(-1) reaps only
     * DIRECT children).  Filter wildcard waiters by parent identity; an exact-pid
     * waiter is the true parent by definition (only a parent waitpid's its child).
     * Two passes: exact-pid first, then parent-matched wildcard. */
    for (int pass = 0; pass < 2; ++pass) {
    for (int i = 0; i < SOTBOX_MAX_SLOTS; ++i) {
        lucas_state_t *st = g_slots[i];
        if (!st) continue;
        if (st->state != SOTBOX_STATE_WAITING_FOR_CHILD) continue;
        if (pass == 0) {
            /* Pass 0 · exact-pid waiters only (the real parent). */
            if (st->waiting_for_pid != exited_pid) continue;
        } else {
            /* Pass 1 · wildcard wait4(-1) waiters — but only the genuine parent.
             * parent_pid==0 (unknown) falls back to legacy any-waiter behaviour. */
            if (st->waiting_for_pid != -1) continue;
            if (parent_pid != 0 && st->synthetic_pid != parent_pid) continue;
        }

        /* Match · unblock this parent. */
        int wstatus = (exit_code & 0xff) << 8;
        if (st->waiting_status_vaddr) {
            (void)lucas_copy_to_client(st, st->waiting_status_vaddr,
                                        &wstatus, sizeof(wstatus));
        }

        /* Write parent's RAX = exited_pid, RIP += 2 (skip syscall instr). */
        seL4_UserContext regs;
        int err = seL4_TCB_ReadRegisters(st->client_tcb, false, 0, 18, &regs);
        if (err == 0) {
            regs.rax = (uint64_t)exited_pid;
            regs.rip += 2;
            regs.rcx = regs.rip;    /* mirror for sysret path */
            regs.r11 = regs.rflags;
#ifdef LUCAS_TRACE_L2_WR
            printf("[l:wr-sotbox_table:203] tcb=%lu rax=0x%lx rip=0x%lx (wait4_wake)\n",
                   (unsigned long)st->client_tcb,
                   (unsigned long)regs.rax,
                   (unsigned long)regs.rip);
#endif
            seL4_TCB_WriteRegisters(st->client_tcb, false, 0, 18, &regs);
        }

        /* Unblock via Send to saved reply cap. */
        seL4_Send(st->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));

        /* Cleanup · DELETE the cap before freeing the cslot.  seL4_Send through a
         * SaveCaller reply cap USUALLY consumes it (slot ends empty), but under a
         * concurrent multi-process teardown (wine: services.exe wait4-reaps a
         * child while the child also faults-exit) the Send can leave the cap in
         * place → a bare vka_cspace_free aborts the root server with "slot is not
         * free: call vka_cnode_delete first".  Delete-then-free is the same
         * ordered teardown the fault-loop reap uses; Delete on an already-empty
         * slot is a harmless no-op. */
        {
            cspacepath_t rp;
            vka_cspace_make_path(st->vka, st->waiting_reply_cap, &rp);
            seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
            vka_cspace_free(st->vka, st->waiting_reply_cap);
        }
        st->waiting_reply_cap = 0;
        st->state = SOTBOX_STATE_RUNNING;
        /* Fork-bomb accounting · reaping a child cancels one outstanding fork
         * (see lucas_sys_wait4) so a long interactive session isn't SIGKILL'd as
         * a fork bomb after 16 commands. */
        if (st->fork_attempts > 0) st->fork_attempts--;
        printf("[orch] WAKEUP · sotbox pid=%d reaped child pid=%d code=%d\n",
               st->synthetic_pid, exited_pid, exit_code);
        return 1;
    }
    }
    return 0;
}

/* Back-compat shim · unknown parent (legacy any-waiter behaviour). */
int sotbox_try_wakeup_waiter(int exited_pid, int exit_code) {
    return sotbox_try_wakeup_waiter_p(exited_pid, exit_code, 0);
}
