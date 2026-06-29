/*
 * sotOs · LUCAS L3b-T1 · fork() implementation (shared fault EP model).
 *
 * When a sotBox calls fork():
 *   1. Allocate a new sotbox slot.
 *   2. Build a child sotbox_t (lucas_state_t) cloned from parent.
 *      - Borrowed env pointers (simple/vka/parent_vspace) stay.
 *      - Owned caps (client_tcb/vspace/cnode/fault_ep/ipc_buffer) get
 *        fresh allocations.
 *      - Linux process state (entry_point, brk_*, mmap_high_water,
 *        synthetic_pid, fd_table) copies; synthetic_pid overridden to slot+1.
 *   3. Eager-copy parent's vspace into child via copy_page / copy_region.
 *   4. lucas_client_setup for child: mints a badged copy of the shared fault
 *      EP, installs it in child's CNode, allocates IPC buffer and TCB.
 *   5. Set child's initial registers: copy parent's CURRENT register state
 *      (advance RIP+2 for the child so it resumes AFTER the syscall),
 *      override rax=0 (fork returns 0 in child).
 *   6. Resume child TCB.  Return child_pid to parent IMMEDIATELY.
 *      NO nested fault loop · parent and child are both serviced by
 *      orch_fault_loop concurrently.
 *
 * L3a's SaveCaller / reply_already_sent dance is GONE: the parent's fork()
 * handler in lucas_handle_one_fault writes rax=child_pid, advances RIP, and
 * calls seL4_Reply normally.  orch_fault_loop then picks up whoever faults
 * next (parent or child).
 */

#include <orch/sotbox.h>
#include <orch/arena.h>
#include <orch/pipe.h>
#include <sotos/random.h>
#include <sotos/pidrand.h>   /* C2 #10 · deterministic display_pid (ASLR-independent) */
#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sel4/sel4.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <sel4utils/api.h>     /* WINE-M1 · api_make_guard_skip_word for the vfork TCB */
#include <vspace/vspace.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <simple/simple.h>     /* WINE-M1 · simple_get_init_cap for the shared-vspace setup */
#include <lucas/syscalls.h>    /* WINE-M1 · LUCAS_WAIT4_DEFERRED sentinel */
extern int g_orch_quiet;   /* v2.9 · operator `watch` quiet mode (suppress per-fork region spam) */

#include <procd/proc.h>
#include <procd/shm.h>

/* These are defined in the lucas static library which orch links against. */
extern vka_t *orch_vka(void);
extern int  sotbox_alloc_slot(lucas_state_t *st);
extern void sotbox_free_slot(int slot);
extern int  create_client_vspace(lucas_state_t *st);
extern int  lucas_client_setup(lucas_state_t *st);

/* PR 11 · procd cross-vspace SHM base · captured by orch/main.c from
 * BOOTSTRAP.bs.procd_shm_base.  0 means the cross-vspace mapping has not
 * been wired yet (deferred to PR 14) · in that case we fall back to the
 * legacy lucas_state.tier field which is the authoritative demo-driving
 * tier today. */
extern void *g_procd_shm_base;
extern void *g_procd_shm_ro;   /* procd-readers · orch's RO view of procd's table */

extern int orch_procd_fork(uint32_t parent_slot,
                            uint32_t *out_slot,
                            uint32_t *out_synthetic_pid);

/* Eager copy of a single page from parent vspace to child vspace.
 * Both vaddrs are the SAME (POSIX fork).  If `shared_res` is non-NULL the page
 * maps into that pre-placed region reservation (no per-page reserve); else it
 * reserves a fresh 4 KiB range for this page.  Returns 0 on success, -1 on
 * error. */
static int copy_page_res(lucas_state_t *parent, lucas_state_t *child,
                         uintptr_t page_vaddr, reservation_t *shared_res) {
    seL4_CPtr p_frame = vspace_get_cap(&parent->client_vspace_abs,
                                       (void *)page_vaddr);
    if (!p_frame) return 0;  /* not mapped · skip silently */

    /* Already present in the child?  An earlier overlapping region copied it
     * (e.g. STACK ⊂ LIVE-STACK for a static-ELF fork whose live rsp sits near
     * stack_top).  Skip silently — re-reserving would fail noisily via the
     * library's ZF_LOGE("Range not available") AND our own log. */
    if (vspace_get_cap(&child->client_vspace_abs, (void *)page_vaddr))
        return 0;

    /* Allocate + map a fresh frame in the child at the same vaddr.  Reuse the
     * caller's whole-region reservation when given (coalesced · the per-page
     * reserve mallocs a bookkeeping node, and thousands of them per fork × the
     * concurrent dpkg fork tree exhausted orch's 1 MiB heap → reserve_at
     * "Malloc failed"). */
    reservation_t local_res = { 0 };
    reservation_t *res = shared_res;
    if (!res) {
        local_res = vspace_reserve_range_at(&child->client_vspace_abs,
                                            (void *)page_vaddr, 4096,
                                            seL4_ReadWrite, 1);
        if (local_res.res == NULL) {
            printf("[fork] reserve_at(0x%lx) failed\n", (unsigned long)page_vaddr);
            return -1;
        }
        res = &local_res;
    }
    int err = vspace_new_pages_at_vaddr(&child->client_vspace_abs,
                                        (void *)page_vaddr, 1, 12, *res);
    if (err) {
        printf("[fork] new_pages_at(0x%lx) failed err=%d\n",
               (unsigned long)page_vaddr, err);
        if (!shared_res)
            vspace_free_reservation(&child->client_vspace_abs, local_res);
        return -1;
    }
    seL4_CPtr c_frame = vspace_get_cap(&child->client_vspace_abs,
                                       (void *)page_vaddr);
    if (!c_frame) {
        printf("[fork] child get_cap(0x%lx) NULL after map\n",
               (unsigned long)page_vaddr);
        return -1;
    }

    /* Map both frames into orch's own vspace via dup_and_map, memcpy, unmap. */
    void *p_local = sel4utils_dup_and_map(parent->vka, parent->parent_vspace,
                                          p_frame, seL4_PageBits);
    if (!p_local) {
        printf("[fork] dup_and_map parent frame 0x%lx failed\n",
               (unsigned long)page_vaddr);
        return -1;
    }
    void *c_local = sel4utils_dup_and_map(parent->vka, parent->parent_vspace,
                                          c_frame, seL4_PageBits);
    if (!c_local) {
        printf("[fork] dup_and_map child frame 0x%lx failed\n",
               (unsigned long)page_vaddr);
        sel4utils_unmap_dup(parent->vka, parent->parent_vspace,
                            p_local, seL4_PageBits);
        return -1;
    }
    memcpy(c_local, p_local, 4096);
    sel4utils_unmap_dup(parent->vka, parent->parent_vspace,
                        c_local, seL4_PageBits);
    sel4utils_unmap_dup(parent->vka, parent->parent_vspace,
                        p_local, seL4_PageBits);
    return 0;
}

/* Walk a region [base..base+size) page-by-page, copying any mapped pages.
 * RESERVATION-COALESCED: reserve the WHOLE region once (one allocman bookkeeping
 * node) instead of once-per-page (thousands of nodes per fork).  The per-page
 * reserves exhausted orch's 1 MiB malloc heap under dpkg's concurrent fork tree
 * (dpkg→dpkg-deb→tar) → "sel4utils_reserve_range_at: Malloc failed" → the child
 * ran with missing pages → VMFault.  Sparse pages map into the one reservation;
 * unmapped gaps cost nothing.  Freed with the child vspace teardown (same as
 * the per-page reservations were).  FALLBACK: if the whole-region reserve can't
 * be placed (the range overlaps an already-copied region, e.g. STACK ⊂
 * LIVE-STACK), copy_page_res(...,NULL) reserves per-page and skips the
 * already-present pages — identical to the prior behaviour for that case. */
static int copy_region(lucas_state_t *parent, lucas_state_t *child,
                       uintptr_t base, size_t size, const char *what) {
    uintptr_t start = base & ~0xFFFUL;
    uintptr_t end   = (base + size + 0xFFFUL) & ~0xFFFUL;
    reservation_t region_res = vspace_reserve_range_at(&child->client_vspace_abs,
                                                       (void *)start, end - start,
                                                       seL4_ReadWrite, 1);
    reservation_t *res = (region_res.res != NULL) ? &region_res : NULL;
    int copied = 0;
    for (uintptr_t p = start; p < end; p += 4096) {
        if (copy_page_res(parent, child, p, res) == 0) ++copied;
    }
    if (!g_orch_quiet)
    printf("[fork]   region %s: 0x%lx..0x%lx · %d pages copied%s\n",
           what, (unsigned long)start, (unsigned long)end, copied,
           res ? " (coalesced)" : " (per-page)");
    return 0;
}

/* Share a read-only region from parent into child WITHOUT allocating new
 * frame objects.  Uses cap copies of the parent's existing frames.
 * This saves one frame allocation per page — crucial for TEXT which is
 * identical across all busybox instances and never written.
 * Returns 0 (skips non-mapped pages silently). */
/* Returns the number of pages shared (RO cap-copies) so the caller can record
 * the TEXT-owner lifetime dependency only when sharing actually happened. */
static int share_region_ro(lucas_state_t *parent, lucas_state_t *child,
                            uintptr_t base, size_t size, const char *what) {
    uintptr_t start = base & ~0xFFFUL;
    uintptr_t end   = (base + size + 0xFFFUL) & ~0xFFFUL;
    int shared = 0;

    for (uintptr_t p = start; p < end; p += 4096) {
        seL4_CPtr p_frame = vspace_get_cap(&parent->client_vspace_abs,
                                           (void *)p);
        if (!p_frame) continue;  /* not mapped · skip */

        /* Reserve the same vaddr in the child. */
        reservation_t res = vspace_reserve_range_at(&child->client_vspace_abs,
                                                    (void *)p, 4096,
                                                    seL4_CanRead, 1);
        if (res.res == NULL) continue;  /* skip on failure */

        /* Cap-copy the parent's frame cap into a fresh cslot so we can
         * pass it to vspace_map_pages_at_vaddr. */
        seL4_CPtr tmp_cptr;
        if (vka_cspace_alloc(child->vka, &tmp_cptr) != 0) {
            vspace_free_reservation(&child->client_vspace_abs, res);
            continue;
        }
        cspacepath_t src_path, dst_path;
        vka_cspace_make_path(parent->vka, p_frame, &src_path);
        vka_cspace_make_path(child->vka, tmp_cptr, &dst_path);
        if (vka_cnode_copy(&dst_path, &src_path, seL4_CanRead) != 0) {
            vka_cspace_free(child->vka, tmp_cptr);
            vspace_free_reservation(&child->client_vspace_abs, res);
            continue;
        }

        seL4_CPtr caps[1] = { tmp_cptr };
        uintptr_t cookies[1] = { 0 };
        int err = vspace_map_pages_at_vaddr(&child->client_vspace_abs,
                                            caps, cookies,
                                            (void *)p, 1, 12, res);
        if (err != 0) {
            vka_cnode_delete(&dst_path);
            vka_cspace_free(child->vka, tmp_cptr);   /* tmp_cptr was alloc'd from child->vka */
            vspace_free_reservation(&child->client_vspace_abs, res);
            continue;
        }
        /* Don't free tmp_cptr here — the vspace now holds the mapping.
         * cslot is leaked intentionally (child exit cleanup handles this). */
        ++shared;
    }

    if (!g_orch_quiet)
    printf("[fork]   region %s: 0x%lx..0x%lx · %d pages shared (RO)\n",
           what, (unsigned long)start, (unsigned long)end, shared);
    return shared;
}

/* Storage for child sotBoxes.  We support at most SOTBOX_MAX_SLOTS-1 children
 * (slot 0 always belongs to the first parent from lucas_run_l1). */
static lucas_state_t  child_storage[SOTBOX_MAX_SLOTS - 1];
static bool           child_storage_used[SOTBOX_MAX_SLOTS - 1];

/* Replace each inherited VFS file handle in `child`'s fd table with an
 * INDEPENDENT clone (backend dup_handle), so the child's close() cannot free a
 * pooled backend handle the parent still has open.  Best-effort: backends with
 * no dup_handle, or a dup that fails (pool full), keep the shallow-copied
 * pointer (the pre-existing aliasing behaviour — degraded, not a crash). */
static void lucas_dup_vfs_handles(lucas_state_t *child)
{
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        lucas_fd_t *e = &child->fds[i];
        if (e->kind != LUCAS_FD_VFS || !e->mount || !e->handle) continue;
        /* SKIP lazy-mmap-pinned fds: the guest already close()d them (the close
         * was skipped, the handle is kept ONLY for on-demand faulting via the
         * lazy_region), so the guest never closes them again — sharing the handle
         * is safe and the OWNER's lucas_release_lazy_regions frees it once.
         * Duping here would mint an extra pooled handle that nothing ever frees
         * (the child's lazy_region aliases the parent's handle, not this dup) →
         * a per-fork pool leak across dpkg's fork tree. */
        if (e->lazy_pinned) continue;
        const vfs_ops_t *ops = e->mount->ops;
        if (!ops || !ops->dup_handle) continue;
        void *dup = ops->dup_handle(e->mount->backend_state, e->handle);
        if (dup) e->handle = dup;
    }
}

int64_t sotbox_fork(lucas_state_t *parent) {
    /* PR 11 · synth fork policy gate.
     *
     * If the parent is Tier 2 (shadow / synth), skip the seL4 mechanics
     * entirely · no eager-vspace-copy, no TCB allocation.  Procd allocates
     * a "silence" slot whose state stays NASCENT forever and whose seL4 caps
     * stay 0; the malware sees a valid positive synthetic_pid (the synth
     * child's identity) and can attempt to "communicate" with it through
     * the F_proc functor · the operator sees EV_SYNTH_FORK and no new
     * sotbox in sotinfo.
     *
     * Tier-detection · two-source check.  The authoritative demo-driving
     * tier today is lucas_state_t.tier (set by lucas_set_tier(); reflected
     * in F_2 / functor->is_isolated).  We ALSO consult procd's proc_t.tier
     * when the cross-vspace SHM mapping is live (g_procd_shm_base != 0) ·
     * forward-compat for PR 14+ when SHM becomes the source of truth.
     * Either signal triggers the synth path. */
    bool parent_is_tier2 = (parent->tier == 2);

    /* SSH canary-shell exception (Phase B).  An interactive canary shell served
     * over SSH (console_src == SSH_RING, inherited by the whole fork subtree
     * via `*child = *parent`) MUST run its children for real — the attacker
     * has to SEE real `cat /etc/passwd` / `ls` / `id` output streamed back as
     * CHANNEL_DATA, which only a real fork+exec produces.  Containment is
     * still intact: the child inherits tier == 2, so its file writes are
     * silenced-dropped, its network is synth, the fork-bomb quota still counts
     * each fork, and its arena is revoked at reap.  We lift ONLY the
     * "don't really run children" deception for this subtree. */
    bool canary_shell_real_fork =
        (parent->console_src == LUCAS_CONSOLE_SRC_SSH_RING) ||
        parent->console_interactive;   /* local keyboard bbsh too: its applets
                                        * (id/ls/...) must really run so the
                                        * on-screen shell is usable. Same tier-2
                                        * containment as the SSH subtree. */
    if (!parent_is_tier2 && parent->procd_slot != 0 &&
        g_procd_shm_ro != NULL) {
        procd_shm_header_t *hdr = (procd_shm_header_t *)g_procd_shm_ro;
        if (hdr->magic == PROCD_SHM_MAGIC &&
            parent->procd_slot < hdr->table_n) {
            proc_t *parent_pt = (proc_t *)((uint8_t *)g_procd_shm_ro +
                                             hdr->table_ofs +
                                             sizeof(proc_t) * parent->procd_slot);
            if (procd_tier_load_bounded(parent_pt, 64) == PROC_TIER_2) {
                parent_is_tier2 = true;   /* additive · never downgrades */
            }
        }
    }

    if (parent_is_tier2 && !canary_shell_real_fork) {
        uint32_t pd_slot = 0, pd_synthetic = 0;
        int rc = orch_procd_fork(parent->procd_slot, &pd_slot, &pd_synthetic);
        if (rc >= 0) {
            printf("[orch] synth fork · child=%u parent_slot=%u (no real TCB)\n",
                   pd_synthetic, parent->procd_slot);
            /* Return synth PID to caller; no real child created. */
            return (int64_t)pd_synthetic;
        }
        printf("[orch] synth fork announce failed rc=%d · falling through to real fork\n",
               rc);
        /* Fall through · the real-fork path will run, which is a safe
         * (if non-ideal) fallback that still creates a child sotbox. */
    }

    /* --- Step 1: find free child storage slot --- */
    int local_idx = -1;
    for (int i = 0; i < SOTBOX_MAX_SLOTS - 1; ++i) {
        if (!child_storage_used[i]) {
            local_idx = i;
            child_storage_used[i] = true;
            break;
        }
    }
    if (local_idx < 0) {
        printf("[fork] no free child_storage\n");
        return -(int64_t)11;  /* -EAGAIN */
    }
    lucas_state_t *child = &child_storage[local_idx];

    /* --- Step 2: shallow-copy parent state, reset owned caps --- */
    *child = *parent;
    /* Phase C · the COW-lite session id MUST follow the child so a fork+exec'd
     * vim reads back its own `:w` edits within the SSH session.  The `*child =
     * *parent` above already copies it; this explicit line documents the
     * invariant and survives a future switch to a field-by-field copy. */
    child->cow_session       = parent->cow_session;
    /* P2b · arena-backed fork child (closes P2a's B2 leak); acquired after slot alloc. */
    child->arena             = NULL;   /* set below, after sotbox_alloc_slot */
    child->fork_attempts     = 0;      /* do NOT inherit the parent's count (*child=*parent) */
    child->marked_for_teardown            = 0;
    child->parent_slot       = parent->slot_index;
    child->child_storage_idx = local_idx;
    child->text_owner_slot   = -1;     /* set below iff share_region_ro shares TEXT */
    /* child->vka stays the inherited parent value for now; overwritten below
     * (after the arena acquire) before any allocation. */
    /* Reset the procd binding · child must get its own slot via the
     * announce below. If announce fails, procd_slot stays 0 and lucas
     * skips the exit/wait announces, preserving the invariant
     * "procd_slot==0 means no procd binding". */
    child->procd_slot = 0;
    /* Borrowed env (simple, vka, parent_vspace) intentionally kept. */
    child->client_tcb               = 0;
    child->client_vspace            = 0;
    memset(&child->client_vspace_abs,  0, sizeof(child->client_vspace_abs));
    memset(&child->client_vspace_data, 0, sizeof(child->client_vspace_data));
    child->fault_ep                 = 0;
    child->client_cnode             = 0;
    child->client_ipc_buffer_frame  = 0;
    child->exited                   = 0;
    child->exit_code                = 0;
    /* L3b-T1: no SaveCaller fields needed */
    child->reply_already_sent       = 0;
    child->saved_reply_cap          = 0;
    /* L3b-T2: child starts RUNNING; it does not inherit parent's wait state. */
    child->state                    = SOTBOX_STATE_RUNNING;
    child->waiting_reply_cap        = 0;
    child->waiting_for_pid          = 0;
    child->waiting_status_vaddr     = 0;
    /* L3b-T4: child does not inherit pipe-blocking state. */
    child->waiting_pipe             = NULL;
    child->pipe_reply_cap           = 0;     /* don't inherit a parent's pipe-park */
    child->pipe_wait_kind           = 0;
    child->waiting_pipe_buf         = 0;
    child->waiting_pipe_count       = 0;

    /* L3b-T4: bump pipe refcounts for all inherited pipe fds.
     * The shallow copy already replicated the pipe pointer; we need to
     * tell the pipe object that another end is open. */
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        if (child->fds[i].kind == LUCAS_FD_PIPE_READ && child->fds[i].pipe) {
            lucas_pipe_add_reader(child->fds[i].pipe);
        } else if (child->fds[i].kind == LUCAS_FD_PIPE_WRITE && child->fds[i].pipe) {
            lucas_pipe_add_writer(child->fds[i].pipe);
        }
    }

    /* Install-arc · give the child INDEPENDENT VFS file handles.  The shallow
     * fd copy replicated the orch-side handle POINTER, so parent and child
     * aliased ONE pooled backend handle — the first close() freed it for BOTH,
     * and the other process's next read hit EBADF.  This broke dpkg-deb's
     * decompressor: dpkg-deb opens /tmp/hello.deb, forks the (in-process liblzma)
     * decompressor child, the child closes its unused inherited hello.deb fd →
     * op_close frees the shared handle → the parent's read fails ("dpkg-deb:
     * cannot copy archive member ... to decompressor pipe: failed to read (Bad
     * file descriptor)").  dup_handle clones the backend handle (same inode/
     * flags/path; the read/write offset lives per-fd in .cursor, already
     * independent after the copy), so each process owns its handle's lifetime.
     * Mirrors the pipe-refcount loop above. */
    lucas_dup_vfs_handles(child);

    /* Register in the slot table so badged fault messages can find it. */
    int slot = sotbox_alloc_slot(child);
    if (slot < 0) {
        printf("[fork] sotbox_alloc_slot failed · table full\n");
        child_storage_used[local_idx] = false;
        return -(int64_t)11;
    }
    child->slot_index = slot;

    /* WINE-M1 socketpair channel ends: bump refcount + retarget the end's owner
     * slot to the child.  MUST run after slot_index is assigned (above), since
     * the retarget records child->slot_index. */
    extern void lucas_unix_inherit_fd(lucas_state_t *, int);
    for (int i = 0; i < LUCAS_MAX_FDS; ++i)
        lucas_unix_inherit_fd(child, i);
    child->synthetic_pid   = slot + 1;   /* simple but collision-free for L3b */
    { extern void sotbox_clear_zombie(int pid); sotbox_clear_zombie(child->synthetic_pid); }
    /* OBSD-ζ PID-DISPLAY · child gets a display_pid distinct from the parent
     * (keyed on the child's own synthetic_pid) so the Linux-visible getpid() differs
     * between parent and child · C2 #10 · reproducible-by-design (deterministic
     * · never 0) · SEPARATE PRNG so the ASLR/entropy stream is untouched. */
    child->display_pid = sotos_pid_display((uint32_t)child->synthetic_pid);
    printf("[fork] parent pid=%d → child pid=%d (slot=%d) child_display_pid=%u\n",
           parent->synthetic_pid, child->synthetic_pid, slot,
           (unsigned int)child->display_pid);

    /* P2b · the child's OWN objects (PML4/TCB/copy_page DATA+STACK frames + client-side
     * page-tables) come from a dedicated arena → revoked wholesale at reap. orch's
     * parent-vspace bookkeeping stays on orch_vka() (orch_parent_new_pages is NOT routed —
     * the P2a blocker-1/2 lesson). */
    /* CAPACITY · the wine new_process (wineboot) child is the real heavy consumer
     * (8 builtin DLLs + heaps + locale.nls + 3.4 MiB sortdefault.nls → >8192 cslots).
     * Route it to the single HEAVY arena. Gate narrowly so ONLY the wineboot takes
     * heavy, not the lightweight launcher or its first-hop helper:
     *   (a) exe_path contains "wine" (the wine loader subtree; inherited via *child=*parent
     *       before any execve, so it is set at fork time); AND
     *   (b) the parent is ITSELF a fork/vfork child (parent->parent_slot >= 0), i.e. this
     *       is a deep wine child (the wineboot), not the launcher's first-hop helper whose
     *       parent is the top-level spawn (parent_slot == -1).
     * Fallback to a regular arena if heavy is busy/unavailable (unchanged behavior).
     * Non-wine guests (busybox forks, gtk/doom/python — spawned via sotbox_spawn_into,
     * not fork children) never match this gate and are unaffected. */
    child->arena = NULL;
    /* Gate must select the WINEBOOT fork-child and EXCLUDE the wineserver daemon.
     * Both are deep wine children (parent_slot>=0) whose inherited exe_path contains
     * "wine", but the wineserver daemon forks FIRST (trace:1108) and — being single-
     * instance — would pin the one heavy arena forever, starving the later wineboot
     * fork (trace:2708) → identical OOM.  At fork time the child inherits the parent's
     * pre-execve exe_path: the wineboot's parent is the launcher ("…/wine-preloader");
     * the daemon's parent already execve'd "…/wineserver".  So gate on: contains
     * "wine" AND NOT "wineserver" → matches the wineboot, never the daemon. */
    if (parent->parent_slot >= 0 &&
        strstr(child->exe_path, "wine") != NULL &&
        strstr(child->exe_path, "wineserver") == NULL) {
        child->arena = sotbox_heavy_acquire();
    }
    /* apt arc · apt forks a transport METHOD child (/usr/lib/apt/methods/http)
     * that is a small ELF but drags a large shared-lib closure (libcurl + the
     * TLS/zstd/… stack) → it exhausts a regular 8192-cslot arena ("cspace
     * exhausted 8192/8192" → "Method http has died unexpectedly").  apt itself
     * runs in a HEAVY arena (orch_spawn_apt_pool); route its fork children to a
     * heavy arena too so the method's closure fits.  Gate on parent-is-heavy
     * (robust · no path string), mirroring the wine clause above. */
    {
        extern int sotbox_arena_vka_is_heavy(vka_t *vka);
        if (!child->arena && parent->vka &&
            sotbox_arena_vka_is_heavy(parent->vka)) {
            child->arena = sotbox_heavy_acquire();
            if (!child->arena)
                printf("[fork] apt-method · heavy pool busy · regular fallback "
                       "(may OOM loading the method's lib closure)\n");
        }
    }
    if (!child->arena) child->arena = sotbox_arena_acquire();
    if (!child->arena) {
        printf("[fork] no free arena for child · pool exhausted\n");
        sotbox_free_slot(slot);
        child_storage_used[local_idx] = false;
        return -(int64_t)11;  /* -EAGAIN */
    }
    child->vka = &child->arena->vka;   /* overrides the inherited parent vka */
    extern void orch_set_vspace_owner(lucas_state_t *st);
    orch_set_vspace_owner(child);      /* zero-leak · charge child bookkeeping to its window+arena */

    /* --- Step 3: create child vspace (fresh PML4 + ASID) --- */
    if (create_client_vspace(child) != 0) {
        printf("[fork] create_client_vspace failed\n");
        goto fail_child;
    }

    /* vDSO arc · Task 4 · map [vvar][vdso] at SOTOS_VDSO_BASE into the child's
     * fresh vspace (the eager-copy below only touches the low program ranges,
     * not the 128-TiB vDSO window).  The child's stack — copied from the parent
     * — already carries AT_SYSINFO_EHDR pointing here.  Non-fatal. */
    if (lucas_map_vdso(child) != 0)
        printf("[fork] vDSO map failed · child libc uses syscall fallback\n");

    /* --- Step 4: eager-copy memory regions ---
     * We use vspace_get_cap over conservative ranges.  For any page NOT
     * mapped in the parent, copy_page silently skips it (returns 0). */

    /* TEXT + RODATA: first PT_LOAD, typically 0x400000 .. ~0x600000.
     * TEXT is read-only and identical for all busybox instances — share
     * the parent's frames (RO cap copies) instead of allocating new ones.
     * This halves the frame allocation cost of each fork(). */
    int text_shared = share_region_ro(parent, child, 0x400000, 0x200000,
                                      "TEXT+RODATA");
    if (text_shared > 0) {
        /* v1.0-rc1 lifetime fix · record which arena OWNS the frame objects the
         * child now executes from.  The child's caps are RO cap-COPIES derived
         * from the parent's mapped TEXT frames; if the PARENT is itself a sharer
         * (its TEXT is the grandparent's frames) the true owner is transitive —
         * inherit parent->text_owner_slot in that case so the dependency points
         * at the arena that actually backs the frame objects. */
        child->text_owner_slot = (parent->text_owner_slot >= 0)
                               ? parent->text_owner_slot
                               : parent->slot_index;
        if (!g_orch_quiet)
        printf("[fork]   TEXT lifetime · owner slot=%d pid=%d → sharer slot=%d pid=%d"
               " · vrange 0x%lx..0x%lx · %d pages (RO cap-copies of owner arena)\n",
               child->text_owner_slot,
               (sotbox_get_slot(child->text_owner_slot)
                    ? sotbox_get_slot(child->text_owner_slot)->synthetic_pid : -1),
               child->slot_index, child->synthetic_pid,
               0x400000UL, 0x600000UL, text_shared);
    }
    /* DATA: second PT_LOAD, typically 0x600000 .. ~0x800000.
     * DATA is writable and must be copied (COW semantics). */
    copy_region(parent, child, 0x600000, 0x200000, "DATA");
    /* BRK: heap grown by sbrk/brk */
    if (parent->brk_base != 0 && parent->brk_top > parent->brk_base) {
        copy_region(parent, child, parent->brk_base,
                    parent->brk_top - parent->brk_base, "BRK");
    }
    /* STACK: conservative 16 pages below stack_top (grows down) */
    if (parent->stack_top != 0) {
        uintptr_t stack_base = parent->stack_top - 16 * 4096;
        copy_region(parent, child, stack_base, 16 * 4096, "STACK");
    }
    /* LIVE-STACK · the static STACK copy above uses parent->stack_top, the
     * original ELF entry stack (~0x100f0000).  But a wine process runs on a
     * thread stack that ntdll allocates high in the address space
     * (~0x7ffffe0ff000), far above stack_top.  When such a process fork()s
     * (ntdll fork_and_exec for CreateProcess → services.exe), the child inherits
     * the parent's CURRENT rsp (step 6) yet the page under it was never copied →
     * the first `call` push VMFaults (run27: slot=1 @0x40049852
     * addr=0x7ffffe0ff7b8 fsr=0x6, 64× → code=139).  Copy a generous window
     * around the parent's live rsp (read here while it is paused at the fork
     * syscall) — below it for new pushes, above it for the live call-chain frames
     * up toward the stack base.  copy_region skips unmapped pages, so the window
     * is safe even when the real stack is smaller; for a plain static-ELF fork
     * (rsp near stack_top) it just re-copies pages already handled above. */
    {
        /* WORKER-THREAD FORK · read the FORKING thread's regs (cur_fault_tcb),
         * not the main thread's (client_tcb).  apt is multithreaded during
         * install and forks dpkg from a libapt worker; its live rsp lives on
         * that worker's stack, far from the main thread's ~0x10100000.  Reading
         * client_tcb here copied the wrong stack window → the child's first push
         * VMFaulted.  Mirrors the sotbox_vfork caller_tcb fix. */
        seL4_CPtr fork_tcb = parent->cur_fault_tcb ? parent->cur_fault_tcb
                                                   : parent->client_tcb;
        seL4_UserContext pr;
        if (seL4_TCB_ReadRegisters(fork_tcb, false, 0,
                                   sizeof(pr)/sizeof(seL4_Word), &pr) == 0
            && pr.rsp != 0) {
            uintptr_t sp_page = pr.rsp & ~0xFFFUL;
            uintptr_t below = 128 * 4096UL, above = 256 * 4096UL;
            uintptr_t live_base = (sp_page > below) ? sp_page - below : 0;
            copy_region(parent, child, live_base, below + above, "LIVE-STACK");
        }
    }
    /* MMAP: anonymous mappings above LUCAS_MMAP_BASE */
    if (parent->mmap_high_water > 0x40000000UL) {
        copy_region(parent, child, 0x40000000UL,
                    parent->mmap_high_water - 0x40000000UL, "MMAP");
    }
    /* WINE-M1 · dynamic-PIE image regions.  The hardcoded 0x400000/0x600000
     * static ranges above copy NOTHING for a PIE — its code+data live at
     * bin_base (the PIE itself) and interp_base (ld-musl).  A forking dynamic
     * process (wineserver daemonizes via fork()) needs both in the child or it
     * ifetch-faults in ld-musl/PIE text never mapped into its vspace (observed:
     * slot=2 VMFault ifetch=1 @0x14004384d = interp_base+0x4384d).  copy_region
     * skips unmapped pages, so a generous fixed span is safe; pages still lazy
     * in the parent resolve in the child via the inherited lazy_regions[].  The
     * copies map RW but stay executable (this build uses the no-NX default
     * VMAttributes · see handlers_mem.c), so the child can run the copied text. */
    if (parent->is_dynamic) {
        if (parent->bin_base)
            copy_region(parent, child, parent->bin_base,    0x800000UL, "DYN-BIN");
        if (parent->interp_base)
            copy_region(parent, child, parent->interp_base, 0x800000UL, "DYN-INTERP");
        /* WINE-M1 · the Windows high region — the reserved block at 0x7fde0000
         * which holds the PEB (~0x7ffd0000) and the mprotect'd 0x7ffc0000 page,
         * plus KUSER_SHARED_DATA at 0x7ffe0000 — is mapped at FIXED addresses
         * ABOVE mmap_high_water, so the MMAP copy above misses it entirely.  When
         * a wine process fork()s for CreateProcess (ntdll fork_and_exec), the
         * forked child runs pre-exec setup that dereferences the inherited PEB
         * pointer; without this copy it VMFaults @0x7ffd0020 (observed: slot=3,
         * the wineboot child).  copy_region skips unmapped pages, so the span is
         * safe even though the parent maps only part of it. */
        copy_region(parent, child, 0x7fde0000UL, 0x201000UL, "WIN-HIGH");
        /* WINE-M1 · the wine thread-stack / TEB high band.  Wine allocates each
         * thread's stack + per-thread data via NtAllocateVirtualMemory at FIXED
         * addresses near the TOP of the 47-bit user AS (observed: 0x7ffffe0ff…
         * stacks, 0x7ffffe310… per-thread structs).  These are committed anonymous
         * MAP_FIXED regions tracked in NEITHER lazy_regions (file-backed) NOR
         * mmap_high_water (the low 0x40000000 arena) NOR WIN-HIGH (the ~2 GiB
         * PEB/TEB block).  When wineboot fork()s for services.exe and its children,
         * the child runs pre-execve glue that touches them → terminal VMFault
         * (run27: 0x7ffffe0ff7b8 · run28: 0x7ffffe310cd0).  Rather than chase each
         * address with a hardcoded range, scan the top 64 MiB and copy only the
         * COMMITTED pages: copy_page's vspace_get_cap is a cheap userspace lookup
         * that skips unmapped pages in O(1), so one pass replicates every thread's
         * high allocation — a GENERAL fix for the whole fork cascade, not a patch
         * per fault.  (0x800000000000 = 2^47 = top of the canonical lower half.) */
        copy_region(parent, child, 0x7ffffc000000UL, 0x4000000UL, "WIN-THREAD-HIGH");
    }
    orch_set_vspace_owner(NULL);   /* child bookkeeping done */

    /* --- Step 5: lucas_client_setup for child ---
     * Mints a badged copy of the shared fault EP (badge = child->slot_index+1),
     * installs it in child's CNode, allocates IPC buffer, TCB, configures.
     * Writes initial registers (entry_point / stack_top from shallow copy)
     * but we overwrite them in step 6. */
    if (lucas_client_setup(child) != 0) {
        printf("[fork] lucas_client_setup failed\n");
        goto fail_child;
    }

    /* --- Step 6: set child's register state ---
     * Read the parent's CURRENT registers (while it is paused in the fault
     * handler for the fork() syscall).  The handler has NOT yet advanced
     * RIP by +2, so we must do it ourselves for the child so it resumes
     * AFTER the syscall instruction, matching what the parent will see
     * when orch_fault_loop writes parent's registers back. */
    seL4_UserContext p_regs;
    /* Read ALL 20 fields (rip..r15 + fs_base + gs_base) so the child
     * inherits the parent's TLS base (fs_base).  Without this the child
     * starts with fs_base=0 and any musl %fs: access segfaults at NULL.
     *
     * WORKER-THREAD FORK · read the FORKING thread (cur_fault_tcb), not the
     * main thread (client_tcb).  When apt forks dpkg from a libapt worker, the
     * main thread is parked elsewhere (futex/poll) — resuming the child at the
     * main thread's rip/rsp/fs_base lands it mid-unrelated-code → glibc TLS #GP.
     * The worker's regs are paused exactly at the fork syscall.  Mirrors the
     * sotbox_vfork caller_tcb fix. */
    seL4_CPtr fork_reg_tcb = parent->cur_fault_tcb ? parent->cur_fault_tcb
                                                   : parent->client_tcb;
    int rerr = seL4_TCB_ReadRegisters(fork_reg_tcb, false, 0,
                                      sizeof(p_regs)/sizeof(seL4_Word), &p_regs);
    if (rerr) {
        printf("[fork] ReadRegisters(parent) failed err=%d\n", rerr);
        goto fail_child;
    }
    /* Child sees rax=0 (fork returns 0 in child), rip advanced past syscall. */
    p_regs.rax = 0;
    p_regs.rip = p_regs.rip + 2;   /* skip `syscall` instruction */
    p_regs.rcx = p_regs.rip;       /* mirror for sysret path */
    p_regs.r11 = p_regs.rflags;
    /* fs_base / gs_base are preserved from parent (TLS shared-memory copy). */

#ifdef LUCAS_TRACE_L2_WR
    printf("[l:wr-orch_fork:318] tcb=%lu rax=0x%lx rip=0x%lx (fork child)\n",
           (unsigned long)child->client_tcb,
           (unsigned long)p_regs.rax,
           (unsigned long)p_regs.rip);
#endif
    int werr = seL4_TCB_WriteRegisters(child->client_tcb, false, 0,
                                       sizeof(p_regs)/sizeof(seL4_Word), &p_regs);
    if (werr) {
        printf("[fork] WriteRegisters(child) failed err=%d\n", werr);
        goto fail_child;
    }

    /* --- Step 7: resume child and return IMMEDIATELY to parent ---
     * L3b-T1: NO nested fault loop, NO SaveCaller dance.
     * The child is now a live TCB registered in the slot table with its
     * badge set.  orch_fault_loop will pick up its faults next iteration.
     * The parent's fork() handler returns child_pid here; orch_fault_loop
     * writes it into parent's rax and sends seL4_Reply normally. */
    int rerr2 = seL4_TCB_Resume(child->client_tcb);
    if (rerr2) {
        printf("[fork] TCB_Resume(child) failed err=%d\n", rerr2);
        goto fail_child;
    }
    printf("[fork] child resumed (slot=%d pid=%d) · no nested loop · returning to parent\n",
           slot, child->synthetic_pid);

    /* PR 6/7 · shadow-announce the new child to procd so procd owns the
     * proc_t accounting (ppid, pgid, sid, tier, functor binding,
     * pledge) for the freshly forked sotbox.  Orch keeps the eager
     * vspace-copy seL4 mechanics that just executed above · this is
     * announce-only.  PR 7 dropped the PROCD_TAKEOVER_SPAWN gate · the
     * announce is now unconditional.
     *
     * parent_slot is the parent's procd-side slot · cached on
     * lucas_state_t at the spawn announce.  0 (anomaly) means the
     * parent has no procd binding (an announce earlier failed); procd
     * treats 0 as "no parent" and still allocates a valid child slot. */
    {
        extern int orch_procd_fork(uint32_t parent_slot,
                                    uint32_t *out_slot,
                                    uint32_t *out_synthetic_pid);
        uint32_t parent_slot   = parent->procd_slot;
        uint32_t pd_child_slot = 0, pd_child_pid = 0;
        int rc = orch_procd_fork(parent_slot,
                                  &pd_child_slot, &pd_child_pid);
        if (rc < 0) {
            printf("[orch] procd OP_FORK announce failed rc=%d · sotbox still spawned\n",
                   rc);
        } else {
            printf("[orch] procd fork announced child slot=%u synthetic_pid=%u (parent_slot=%u)\n",
                   pd_child_slot, pd_child_pid, parent_slot);
            /* Stash procd_slot on the new lucas_state_t so the child's
             * later exit_group can announce against the right slot. */
            child->procd_slot = pd_child_slot;
        }
    }

    /* P2a · the child's own seL4 objects (fresh vspace/TCB/CNode/IPC frame/
     * fault EP) are built and the child is resumed.  Mark it owned so reap
     * reclaims them.  forked=1: the child's TEXT frames are RO cap-copies of
     * the LIVE parent's frames (share_region_ro above), so sotbox_destroy must
     * tear the child's vspace down WITHOUT freeing the shared frame objects. */
    child->seL4_objects_owned = 1;
    child->forked             = 1;

    /* Return child_pid to parent's fault handler.
     * orch_fault_loop writes this into parent's rax and replies normally.
     * Child and parent are now both live TCBs in the shared-EP table. */
    return (int64_t)child->synthetic_pid;

fail_child:
    /* P2b · every post-acquire failure lands here: revoke the child's arena
     * (else it permanently burns 1 of 8 arenas → pool drain under churn) and
     * release the slot + child_storage index. */
    if (child->arena) { sotbox_arena_revoke(child->arena); child->arena = NULL; }
    extern void orch_vspace_window_release(int slot);
    orch_vspace_window_release(slot);
    sotbox_free_slot(slot);
    child_storage_used[local_idx] = false;
    return -(int64_t)12;  /* -ENOMEM */
}

/* P2b · release the child_storage[] slot a forked child occupies, at its reap.
 * Without this the slot leaks (set true at fork, never cleared on a successful
 * child's exit) → after SOTBOX_MAX_SLOTS-1 lifetime forks every fork -> -EAGAIN. */
void sotbox_fork_release_storage(lucas_state_t *st)
{
    if (st && st->child_storage_idx >= 0 &&
        st->child_storage_idx < (int)(SOTBOX_MAX_SLOTS - 1)) {
        child_storage_used[st->child_storage_idx] = false;
        st->child_storage_idx = -1;
    }
}

/* ===================================================================== */
/* WINE-M1 · TRUE vfork — clone(CLONE_VM | CLONE_VFORK, !CLONE_THREAD).   */
/* ===================================================================== */
/*
 * The wine launcher starts wineserver via glibc's vfork-based exec helper
 * (posix_spawn → clone(0x4111) → trampoline → execve).  Routing that flags
 * combo to sotbox_fork() (copy-fork) handed the child a FROZEN snapshot of
 * the parent's stack; glibc's vfork continuation runs its function epilogue
 * expecting the LIVE shared stack, pops stale code-bytes into r12..r15, and
 * #GPs deref'ing a non-canonical r12 (workflow wzpfobbwo).
 *
 * The correct model (matching Linux): the child SHARES the parent's vspace
 * (no copy), runs on the live shared stack, and the parent BLOCKS until the
 * child execve()s into its own fresh vspace or _exit()s.  We implement the
 * parent block with the same SaveCaller / deferred-reply machinery wait4
 * uses — the parent stays parked in WAITING_FOR_VFORK and is resumed
 * (rax = child pid) by sotbox_vfork_resume_parent() from the child's execve
 * (post-SetSpace) or exit path.
 *
 * Identity: the child is a SEPARATE sotbox (own slot/pid/badged-EP/TCB) so
 * its syscalls route to its own state and SIGCHLD/wait4 see a real pid — but
 * its vspace + cnode are the parent's during the borrow window.  Its own
 * arena backs the fresh TCB/CNode/IPC frame (and, post-execve, its own
 * vspace), so arena-revoke teardown never touches a parent-owned object.
 *
 * IPC buffer: mapped at a vfork-private vaddr in the shared vspace, distinct
 * from the parent's (0x7ffff1000000) and the thread IPC region
 * (0x7ffff1001000+).  Like the full-reload execve path, the binding goes
 * stale once the child gets its own vspace — harmless, a linuxABI client's
 * faults deliver into orch's IPC buffer, not its own.
 */
#define VFORK_IPC_BASE 0x7ffff1010000UL

int64_t sotbox_vfork(lucas_state_t *parent, uint64_t newsp) {
    /* --- Step 1: child_storage slot (mirrors sotbox_fork) --- */
    int local_idx = -1;
    for (int i = 0; i < SOTBOX_MAX_SLOTS - 1; ++i) {
        if (!child_storage_used[i]) { local_idx = i; child_storage_used[i] = true; break; }
    }
    if (local_idx < 0) { printf("[vfork] no free child_storage\n"); return -(int64_t)11; }
    lucas_state_t *child = &child_storage[local_idx];

    /* --- Step 2: shallow-copy, reset owned caps — but KEEP the vspace shared. */
    *child = *parent;
    child->cow_session       = parent->cow_session;   /* Phase C · inherit the SSH overlay session */
    child->arena             = NULL;
    child->fork_attempts     = 0;
    child->marked_for_teardown = 0;
    child->parent_slot       = parent->slot_index;
    child->child_storage_idx = local_idx;
    child->text_owner_slot   = -1;     /* shares the WHOLE vspace, not a TEXT cap-copy set */
    child->procd_slot        = 0;
    /* Owned caps we re-allocate below (DO NOT reset client_vspace / _abs / cnode:
     * those stay = parent's, shared.  client_vspace_obj IS zeroed so teardown can
     * never individually free the parent's PML4 — arena-revoke handles our own). */
    child->client_tcb               = 0;
    memset(&child->client_tcb_obj,  0, sizeof(child->client_tcb_obj));
    memset(&child->client_vspace_obj, 0, sizeof(child->client_vspace_obj));
    child->fault_ep                 = 0;
    child->client_cnode             = 0;
    memset(&child->client_cnode_obj, 0, sizeof(child->client_cnode_obj));
    child->client_ipc_buffer_frame  = 0;
    memset(&child->client_ipc_buffer_obj, 0, sizeof(child->client_ipc_buffer_obj));
    child->exited                   = 0;
    child->exit_code                = 0;
    child->reply_already_sent       = 0;
    child->saved_reply_cap          = 0;
    child->state                    = SOTBOX_STATE_RUNNING;
    child->waiting_reply_cap        = 0;
    child->waiting_for_pid          = 0;
    child->waiting_status_vaddr     = 0;
    child->waiting_pipe             = NULL;
    child->pipe_reply_cap           = 0;     /* don't inherit a parent's pipe-park */
    child->pipe_wait_kind           = 0;
    child->waiting_pipe_buf         = 0;
    child->waiting_pipe_count       = 0;
    /* `forked` skips the OWNER-only lazy-region release at reap while the
     * child still aliases the parent's pinned VFS handles; cleared once the
     * child execve()s into its own vspace (sotbox_vfork_resume_parent). */
    child->forked                   = 1;
    child->vfork_parent_slot1       = 0;   /* set after parent slot known (below) */
    child->vfork_child_pid          = 0;
    child->vfork_parent_tcb         = 0;

    /* Inherited pipe fds: bump refcounts (mirror sotbox_fork). */
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        if (child->fds[i].kind == LUCAS_FD_PIPE_READ && child->fds[i].pipe)
            lucas_pipe_add_reader(child->fds[i].pipe);
        else if (child->fds[i].kind == LUCAS_FD_PIPE_WRITE && child->fds[i].pipe)
            lucas_pipe_add_writer(child->fds[i].pipe);
    }
    /* Independent VFS file handles (mirror sotbox_fork · see the rationale there:
     * decouples the child's handle lifetime so its close() can't free the
     * parent's pooled backend handle). */
    lucas_dup_vfs_handles(child);

    int slot = sotbox_alloc_slot(child);
    if (slot < 0) {
        printf("[vfork] sotbox_alloc_slot failed · table full\n");
        child_storage_used[local_idx] = false;
        return -(int64_t)11;
    }
    child->slot_index    = slot;
    /* WINE-M1 socketpair ends: retarget owner slot to the child (needs slot_index). */
    extern void lucas_unix_inherit_fd(lucas_state_t *, int);
    for (int i = 0; i < LUCAS_MAX_FDS; ++i)
        lucas_unix_inherit_fd(child, i);
    child->synthetic_pid = slot + 1;
    { extern void sotbox_clear_zombie(int pid); sotbox_clear_zombie(child->synthetic_pid); }
    child->display_pid   = sotos_pid_display((uint32_t)child->synthetic_pid);
    child->vfork_parent_slot1 = parent->slot_index + 1;   /* 1-based; >0 marks a vfork child */
    printf("[vfork] parent pid=%d → child pid=%d (slot=%d) · SHARED vspace cap=%lu newsp=0x%lx\n",
           parent->synthetic_pid, child->synthetic_pid, slot,
           (unsigned long)child->client_vspace, (unsigned long)newsp);

    /* CAPACITY · mirror sotbox_fork's wine-gated heavy route so the new_process
     * (wineboot) child gets heavy even if it ever arrives via vfork rather than
     * copy-fork. Same narrow gate (deep wine child: exe_path contains "wine" AND
     * parent is itself a fork/vfork child) + regular fallback, so the launcher,
     * first-hop helpers, and all non-wine guests are unaffected. In the confirmed
     * trace the wineboot is a copy-fork (sotbox_fork), so this is future-proofing. */
    child->arena = NULL;
    /* Gate must select the WINEBOOT fork-child and EXCLUDE the wineserver daemon.
     * Both are deep wine children (parent_slot>=0) whose inherited exe_path contains
     * "wine", but the wineserver daemon forks FIRST (trace:1108) and — being single-
     * instance — would pin the one heavy arena forever, starving the later wineboot
     * fork (trace:2708) → identical OOM.  At fork time the child inherits the parent's
     * pre-execve exe_path: the wineboot's parent is the launcher ("…/wine-preloader");
     * the daemon's parent already execve'd "…/wineserver".  So gate on: contains
     * "wine" AND NOT "wineserver" → matches the wineboot, never the daemon. */
    if (parent->parent_slot >= 0 &&
        strstr(child->exe_path, "wine") != NULL &&
        strstr(child->exe_path, "wineserver") == NULL) {
        child->arena = sotbox_heavy_acquire();
    }
    if (!child->arena) child->arena = sotbox_arena_acquire();
    if (!child->arena) {
        printf("[vfork] no free arena for child · pool exhausted\n");
        sotbox_free_slot(slot);
        child_storage_used[local_idx] = false;
        return -(int64_t)11;
    }
    child->vka = &child->arena->vka;
    extern void orch_set_vspace_owner(lucas_state_t *st);
    orch_set_vspace_owner(child);   /* charge the child's IPC-buffer page-tables to its arena */

    /* --- Step 3: shared-vspace client setup (badged EP + private cnode +
     * private IPC buffer mapped into the SHARED vspace + TCB sharing the
     * parent's PML4 + cnode-root).  Mirrors lucas_client_setup but does NOT
     * create a vspace and maps the IPC buffer at a vfork-private vaddr. */
    extern seL4_CPtr orch_get_fault_ep(void);
    seL4_CPtr shared_ep = orch_get_fault_ep();
    if (!shared_ep) { printf("[vfork] shared fault EP unset\n"); goto fail_child; }

    cspacepath_t shared_ep_path;
    vka_cspace_make_path(child->vka, shared_ep, &shared_ep_path);
    seL4_CPtr badged_slot = 0;
    if (vka_cspace_alloc(child->vka, &badged_slot) || !badged_slot) {
        printf("[vfork] badged EP cspace_alloc failed\n"); goto fail_child;
    }
    cspacepath_t badged_path;
    vka_cspace_make_path(child->vka, badged_slot, &badged_path);
    if (vka_cnode_mint(&badged_path, &shared_ep_path, seL4_AllRights,
                       (seL4_Word)(child->slot_index + 1))) {
        printf("[vfork] badged EP mint failed\n"); goto fail_child;
    }
    child->fault_ep = badged_slot;

    vka_object_t cnode_obj;
    if (vka_alloc_cnode_object(child->vka, 4 /*CLIENT_CNODE_BITS*/, &cnode_obj)) {
        printf("[vfork] cnode alloc failed\n"); goto fail_child;
    }
    child->client_cnode     = cnode_obj.cptr;
    child->client_cnode_obj = cnode_obj;

    {
        seL4_CPtr cnode_cap = simple_get_init_cap(child->simple, seL4_CapInitThreadCNode);
        if (seL4_CNode_Copy(child->client_cnode, 1 /*FAULT_EP_SLOT*/, 4 /*depth*/,
                            cnode_cap, badged_slot, seL4_WordBits, seL4_AllRights)) {
            printf("[vfork] badged EP copy into child cnode failed\n"); goto fail_child;
        }
    }

    vka_object_t ipc_frame_obj;
    if (vka_alloc_frame(child->vka, 12, &ipc_frame_obj)) {
        printf("[vfork] IPC frame alloc failed\n"); goto fail_child;
    }
    child->client_ipc_buffer_frame = ipc_frame_obj.cptr;
    child->client_ipc_buffer_obj   = ipc_frame_obj;

    uintptr_t ipc_vaddr = VFORK_IPC_BASE + (uintptr_t)child->slot_index * 0x1000UL;
    if (sel4utils_map_page_leaky(child->vka, child->client_vspace,
                                 child->client_ipc_buffer_frame,
                                 (void *)ipc_vaddr, seL4_ReadWrite, 1)) {
        printf("[vfork] IPC buffer map @0x%lx failed\n", (unsigned long)ipc_vaddr);
        goto fail_child;
    }

    vka_object_t tcb_obj;
    if (vka_alloc_tcb(child->vka, &tcb_obj)) {
        printf("[vfork] TCB alloc failed\n"); goto fail_child;
    }
    child->client_tcb     = tcb_obj.cptr;
    child->client_tcb_obj = tcb_obj;

    {
        seL4_Word cspace_root_data = api_make_guard_skip_word(seL4_WordBits - 4);
        if (seL4_TCB_Configure(child->client_tcb, 1 /*FAULT_EP_SLOT*/,
                               child->client_cnode, cspace_root_data,
                               child->client_vspace /*SHARED — parent's PML4*/,
                               seL4_NilData, ipc_vaddr,
                               child->client_ipc_buffer_frame)) {
            printf("[vfork] TCB_Configure failed\n"); goto fail_child;
        }
        seL4_TCB_SetPriority(child->client_tcb,
                             simple_get_init_cap(child->simple, seL4_CapInitThreadTCB),
                             seL4_MaxPrio);
        int ferr = seL4_TCB_SetFlags(child->client_tcb, 0, seL4_TCBFlag_linuxABI).error;
        if (ferr) printf("[vfork] SetFlags(linuxABI) failed err=%d\n", ferr);
    }
    orch_set_vspace_owner(NULL);

    /* --- Step 4: child registers — clone the caller's post-syscall context.
     * Read the FAULTING thread's regs (cur_fault_tcb; falls back to client_tcb)
     * so a worker-thread vfork still resumes at the caller's __clone tail. */
    {
        seL4_CPtr caller_tcb = parent->cur_fault_tcb ? parent->cur_fault_tcb
                                                     : parent->client_tcb;
        seL4_UserContext r;
        if (seL4_TCB_ReadRegisters(caller_tcb, false, 0,
                                   sizeof(r)/sizeof(seL4_Word), &r)) {
            printf("[vfork] ReadRegisters(parent) failed\n"); goto fail_child;
        }
        r.rax = 0;                 /* vfork/clone returns 0 in the child */
        r.rip = r.rip + 2;         /* skip the `syscall` opcode */
        r.rcx = r.rip;
        r.r11 = r.rflags;
        if (newsp) r.rsp = (seL4_Word)newsp;   /* else share the parent's live stack */
        /* fs_base / gs_base preserved from the parent (shared TLS during borrow). */
        if (seL4_TCB_WriteRegisters(child->client_tcb, false, 0,
                                    sizeof(r)/sizeof(seL4_Word), &r)) {
            printf("[vfork] WriteRegisters(child) failed\n"); goto fail_child;
        }
    }

    /* --- Step 5: park the PARENT (SaveCaller + WAITING_FOR_VFORK) BEFORE
     * resuming the child, so a SaveCaller failure can cleanly abort without
     * a half-running child racing the parent on the shared stack. */
    {
        seL4_CPtr cslot;
        if (vka_cspace_alloc(parent->vka, &cslot)) {
            printf("[vfork] parent SaveCaller cspace_alloc failed\n"); goto fail_child;
        }
        cspacepath_t cpath;
        vka_cspace_make_path(parent->vka, cslot, &cpath);
        if (seL4_CNode_SaveCaller(cpath.root, cpath.capPtr, cpath.capDepth)) {
            printf("[vfork] parent SaveCaller failed\n");
            vka_cspace_free(parent->vka, cslot);
            goto fail_child;
        }
        parent->waiting_reply_cap = cslot;
        parent->state             = SOTBOX_STATE_WAITING_FOR_VFORK;
        parent->vfork_child_pid   = child->synthetic_pid;
        parent->vfork_parent_tcb  = parent->cur_fault_tcb ? parent->cur_fault_tcb
                                                          : parent->client_tcb;
    }

    /* --- Step 6: announce to procd (best-effort) + resume the child. */
    {
        uint32_t pd_child_slot = 0, pd_child_pid = 0;
        int rc = orch_procd_fork(parent->procd_slot, &pd_child_slot, &pd_child_pid);
        if (rc >= 0) child->procd_slot = pd_child_slot;
    }
    child->seL4_objects_owned = 1;
    if (seL4_TCB_Resume(child->client_tcb)) {
        printf("[vfork] TCB_Resume(child) failed\n");
        /* Undo the parent park so the parent isn't wedged forever. */
        if (parent->waiting_reply_cap) {
            cspacepath_t rp; vka_cspace_make_path(parent->vka, parent->waiting_reply_cap, &rp);
            seL4_CNode_Delete(rp.root, rp.capPtr, rp.capDepth);
            vka_cspace_free(parent->vka, parent->waiting_reply_cap);
            parent->waiting_reply_cap = 0;
        }
        parent->state = SOTBOX_STATE_RUNNING;
        goto fail_child;
    }
    printf("[vfork] child resumed (slot=%d pid=%d) · parent pid=%d PARKED (WAITING_FOR_VFORK)\n",
           slot, child->synthetic_pid, parent->synthetic_pid);

    /* Parent stays blocked: signal orch_fault_loop to NOT reply.  The reply
     * (rax = child pid) fires from sotbox_vfork_resume_parent when the child
     * execve()s or exits. */
    return LUCAS_WAIT4_DEFERRED;

fail_child:
    orch_set_vspace_owner(NULL);
    if (child->arena) { sotbox_arena_revoke(child->arena); child->arena = NULL; }
    extern void orch_vspace_window_release(int slot);
    orch_vspace_window_release(slot);
    sotbox_free_slot(slot);
    child_storage_used[local_idx] = false;
    return -(int64_t)12;  /* -ENOMEM */
}

/* Resume a parent parked in clone(CLONE_VM|CLONE_VFORK) once its vfork child
 * stops borrowing the parent's address space (execve into its own vspace, or
 * _exit).  Idempotent + a no-op for non-vfork children (vfork_parent_slot1==0)
 * so it is safe to call unconditionally from execve / exit / reap. */
void sotbox_vfork_resume_parent(lucas_state_t *child) {
    if (!child || child->vfork_parent_slot1 == 0) return;
    int pslot = child->vfork_parent_slot1 - 1;
    child->vfork_parent_slot1 = 0;   /* idempotent — never resume twice */
    /* The child now owns its own post-execve vspace + lazy regions (or is
     * exiting): clear `forked` so its OWN pinned VFS handles get released at
     * reap (the flag only meant "aliases the parent's" during the borrow). */
    child->forked = 0;

    lucas_state_t *parent = sotbox_get_slot(pslot);
    if (!parent) return;
    if (parent->state != SOTBOX_STATE_WAITING_FOR_VFORK) return;
    if (parent->waiting_reply_cap == 0) return;

    seL4_CPtr ptcb = parent->vfork_parent_tcb ? parent->vfork_parent_tcb
                                              : parent->client_tcb;
    seL4_UserContext regs;
    if (seL4_TCB_ReadRegisters(ptcb, false, 0, 18, &regs) == 0) {
        regs.rax = (uint64_t)parent->vfork_child_pid;   /* clone() returns child pid */
        regs.rip += 2;
        regs.rcx = regs.rip;
        regs.r11 = regs.rflags;
        seL4_TCB_WriteRegisters(ptcb, false, 0, 18, &regs);
    }
    seL4_Send(parent->waiting_reply_cap, seL4_MessageInfo_new(0, 0, 0, 0));
    vka_cspace_free(parent->vka, parent->waiting_reply_cap);
    parent->waiting_reply_cap = 0;
    parent->state             = SOTBOX_STATE_RUNNING;
    parent->vfork_parent_tcb  = 0;
    printf("[orch] VFORK-RESUME · parent pid=%d resumed (rax=child pid=%d)\n",
           parent->synthetic_pid, parent->vfork_child_pid);
}
