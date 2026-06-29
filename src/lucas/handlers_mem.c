/*
 * sotOs · LUCAS · memory handlers · brk, mmap.
 *
 * L1 scope: brk grows a contiguous heap region; mmap supports only
 * MAP_ANONYMOUS|MAP_PRIVATE (added in T18).
 *
 * obsd-γ: guard pages + ASLR jitter in lucas_sys_mmap (spec §12.7.3).
 */

#include "handlers.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/mpk.h>
#include <sotos/random.h>

#include <sel4utils/mapping.h>
#include <sel4utils/vspace.h>
#include <vspace/vspace.h>
#include <vka/object.h>
#include <stdio.h>
#include <string.h>
extern int g_orch_quiet;   /* v2.9 · operator `watch` quiet mode (suppress per-mmap spam) */

/* DOOM-DBG · write-path paddr watch (defined in handlers_fs.c).  Flags any
 * client-frame WRITE whose dest physical frame == the chocodoom text frame. */
void lucas_doom_watch_frame(seL4_CPtr frame, uintptr_t client_vaddr, const char *tag);

#define LUCAS_BRK_BASE  0x10000000UL    /* fixed location for heap */

int64_t lucas_sys_brk(lucas_state_t *st, uint64_t new_brk,
                       uint64_t _a1, uint64_t _a2, uint64_t _a3,
                       uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    /* Initialize brk on first call. */
    if (st->brk_base == 0) {
        st->brk_base = LUCAS_BRK_BASE;
        st->brk_top  = LUCAS_BRK_BASE;
    }

    if (new_brk == 0) {
        /* Query · return current brk_top. */
        return (int64_t)st->brk_top;
    }
    if (new_brk < st->brk_base) {
        return (int64_t)st->brk_top;  /* Linux semantics: refuse, return current */
    }
    if (new_brk == st->brk_top) {
        return (int64_t)st->brk_top;
    }

    if (new_brk > st->brk_top) {
        /* Grow. Map pages from brk_top up to round(new_brk, page). */
        uintptr_t cur_top   = (st->brk_top + 4095) & ~4095UL;
        uintptr_t target_top = (new_brk + 4095) & ~4095UL;
        size_t bytes_needed = target_top - cur_top;

        if (bytes_needed > 0) {
            /* L2 fix: use vspace API (with reservation) so the mapping is
             * registered in vspace_t metadata, allowing copy_from/to_client
             * to find frame caps via vspace_get_cap. */
            size_t pages = bytes_needed / 4096;
            reservation_t res = vspace_reserve_range_at(&st->client_vspace_abs,
                                                          (void *)cur_top,
                                                          bytes_needed,
                                                          seL4_ReadWrite, 1);
            if (res.res == NULL) {
                printf("[lucas] sys_brk: vspace_reserve_range_at failed\n");
                return (int64_t)st->brk_top;
            }
            int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                                 (void *)cur_top,
                                                 pages, 12, res);
            if (err) {
                printf("[lucas] sys_brk: vspace_new_pages_at_vaddr failed (err=%d)\n", err);
                vspace_free_reservation(&st->client_vspace_abs, res);
                return (int64_t)st->brk_top;
            }
        }
    } else {
        /* Shrink not supported in L1 (we leak pages until L2 munmap). */
    }

    st->brk_top = new_brk;
    return (int64_t)st->brk_top;
}

/* MAP_SHARED bit · not in lucas/linux_abi.h yet, defined locally to keep
 * U5 within its allowed file scope. */
#ifndef LX_MAP_SHARED
#define LX_MAP_SHARED   0x01
#endif
/* MAP_FIXED_NOREPLACE (Linux 4.17+) · map at EXACTLY addr, fail (EEXIST) if any
 * page is occupied — never relocate, never replace.  Wine's try_map_free_area
 * probes for a free span for the PE image with this flag and rejects+retries any
 * mmap that does not return the requested address; honouring addr verbatim (via
 * the fresh-reserve path, which fails if occupied) stops that probe loop, which
 * otherwise retypes a fresh frame per attempt and exhausts the arena untyped. */
#ifndef LX_MAP_FIXED_NOREPLACE
#define LX_MAP_FIXED_NOREPLACE 0x100000
#endif

/* N3/D3 · register a lazy file-backed region (span reserved, no frames yet). */
static int lucas_lazy_register(lucas_state_t *st, uintptr_t vstart, uintptr_t vend,
                               uint64_t file_off, uint64_t file_len,
                               seL4_CapRights_t rights, reservation_t res,
                               const void *mount, void *handle) {
    for (int i = 0; i < LUCAS_MAX_LAZY_REGIONS; ++i) {
        if (st->lazy_regions[i].in_use) continue;
        st->lazy_regions[i] = (lucas_lazy_region_t){
            .in_use = true, .vstart = vstart, .vend = vend,
            .file_off = file_off, .file_len = file_len, .rights = rights,
            .res = res, .mount = mount, .handle = handle };
        return 0;
    }
    return -1;  /* table full */
}

/* Release every lazy region's PINNED VFS backend handle at sotbox teardown.
 * A lazy file-backed mmap (e.g. a shared library) keeps its backend handle open
 * past the guest's close() (close() skips op_close when lazy_pinned, so on-demand
 * faults can still read the .so bytes).  Nothing freed those handles when the
 * sotbox exited → the GLOBAL backend handle pools (e.g. sysroot's g_handles[])
 * leaked one slot per mapped library per launch.  Harmless when dynamic apps were
 * small + few (the pins stayed under the old cap of 16); a 57-lib GTK3 app — or
 * just many app launches over time — exhausts the pool.  sotbox_destroy calls
 * this (frames are reclaimed by the arena revoke; these handles are NOT, so this
 * is the only place they're freed).  op_close is pure bookkeeping (marks the
 * slot free) — no vspace/cap ops — so ordering vs the arena revoke is irrelevant.
 *
 * NOTE (fork): a forked child inherits COPIES of the parent's lazy_regions that
 * alias the SAME backend handles; if such a child were torn down independently it
 * would free a handle the parent still faults through.  Today only dynamic apps
 * have lazy regions and none of them fork (static fixtures have zero lazy
 * regions, so this loop is a no-op for them), so the alias never arises.  A
 * future forking dynamic guest would need per-handle refcounting here. */
void lucas_release_lazy_regions(lucas_state_t *st) {
    if (!st) return;
    for (int i = 0; i < LUCAS_MAX_LAZY_REGIONS; ++i) {
        lucas_lazy_region_t *r = &st->lazy_regions[i];
        if (!r->in_use) continue;
        const vfs_mount_t *m = (const vfs_mount_t *)r->mount;
        if (m && m->ops && m->ops->close && r->handle)
            m->ops->close(m->backend_state, r->handle);
        r->in_use = false;
        r->mount  = NULL;
        r->handle = NULL;
    }
}

/* Close the backend handles of any STILL-OPEN VFS fds at sotbox teardown.  The
 * guest closes most fds itself (op_close frees the pooled backend handle), and
 * lazy-mmap-pinned fds are released by lucas_release_lazy_regions above — but a
 * process that exits with VFS fds still open (a member of dpkg's fork tree
 * reaped mid-operation) leaks a backend-pool slot per open fd.  At 16 sotfs /
 * 128 union slots that leak exhausted the pools across dpkg's heavy fork tree,
 * so a LATER process's ld couldn't open its libs → exited 127 (the tui-gate vim
 * flake).  Each forked child's VFS handles are INDEPENDENT clones
 * (lucas_dup_vfs_handles on fork), so closing the child's own fds never double-
 * frees the parent's.  SKIP lazy_pinned fds — their handle IS the lazy region's
 * (already freed above) → closing it here would double-free. */
void lucas_release_open_vfs_fds(lucas_state_t *st) {
    if (!st) return;
    for (int i = 0; i < LUCAS_MAX_FDS; ++i) {
        lucas_fd_t *e = &st->fds[i];
        if (e->kind != LUCAS_FD_VFS || !e->mount || !e->handle) continue;
        if (e->lazy_pinned) continue;
        if (e->mount->ops && e->mount->ops->close)
            e->mount->ops->close(e->mount->backend_state, e->handle);
        e->handle = NULL;
        e->mount  = NULL;
        e->kind   = LUCAS_FD_INVALID;
    }
}

/* N3/D3 · back one page of a lazy region on first-touch.  Returns 0 if the
 * fault address fell in a lazy region (we backed it, or consumed the fault),
 * -1 if it is not in any lazy region (caller falls through to normal fault). */
int lucas_lazy_back_page_ex(lucas_state_t *st, uintptr_t fault_vaddr, int is_write) {
    uintptr_t page = fault_vaddr & ~0xFFFUL;
    for (int i = 0; i < LUCAS_MAX_LAZY_REGIONS; ++i) {
        lucas_lazy_region_t *r = &st->lazy_regions[i];
        if (!r->in_use || page < r->vstart || page >= r->vend) continue;

        /* GUARD · a WRITE fault into a lazy region whose rights lack write
         * (e.g. a relocation into a GOT/.data.rel.ro slot on an R|X-mapped page)
         * would silently fail to land → NULL function pointer.  Surface it (this
         * fires only on the bug; verified silent on the GTK/dynamic path). */
        if (is_write && r->rights.words[0] != seL4_ReadWrite.words[0])
            printf("[lazy] WARN WRITE-fault to RO lazy region · vaddr=0x%lx page=0x%lx rights=0x%lx\n",
                   (unsigned long)fault_vaddr, (unsigned long)page,
                   (unsigned long)r->rights.words[0]);

        /* Already backed? (second fault on the same page) → just succeed. */
        if (vspace_get_cap(&st->client_vspace_abs, (void *)page) != seL4_CapNull)
            return 0;

        int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                            (void *)page, 1, 12, r->res);
        if (err) {
            printf("[lazy] back page 0x%lx · new_pages err=%d\n",
                   (unsigned long)page, err);
            return 0;  /* consume the fault (avoid a tight refault loop) */
        }
        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)page);
        lucas_doom_watch_frame(frame, page, "lazy-back");
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                            frame, seL4_PageBits);
        if (local) {
            memset(local, 0, 4096);
            uint64_t off_in_region = (uint64_t)(page - r->vstart);
            if (off_in_region < r->file_len) {
                size_t want = 4096;
                if (off_in_region + want > r->file_len)
                    want = (size_t)(r->file_len - off_in_region);
                const vfs_mount_t *m = (const vfs_mount_t *)r->mount;
                /* Phase C · thread the caller into op_read so the COW read-merge
                 * fires — an edited-then-mmap'd file must serve the session
                 * overlay, not leak the pristine base (mirrors handlers_fs.c). */
                lucas_set_current_caller(st);
                int64_t got = m->ops->read(m->backend_state, r->handle, local, want,
                                           (int64_t)(r->file_off + off_in_region));
                lucas_set_current_caller(NULL);
                /* GUARD · a short read leaves the page-tail zero-filled — a NULL
                 * function pointer if it lands in a GOT/.data.rel.ro/vtable page.
                 * The return was previously discarded; surface a short read (it
                 * fires only on a real backend mismatch · verified silent here). */
                if (got < 0 || (size_t)got != want)
                    printf("[lazy] WARN short read · page=0x%lx off=%lu file_off=%lu want=%zu got=%ld\n",
                           (unsigned long)page, (unsigned long)off_in_region,
                           (unsigned long)r->file_off, want, (long)got);
            }
            sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
        }
        return 0;
    }
    return -1;
}

/* Back-compat shim · the read fault path passes is_write=0 (treated read). */
int lucas_lazy_back_page(lucas_state_t *st, uintptr_t fault_vaddr) {
    return lucas_lazy_back_page_ex(st, fault_vaddr, 0);
}

/* ===================================================================== *
 * Wine-prep · logical address-space RESERVATIONS (state.h resv_regions). *
 *                                                                        *
 * A large PROT_NONE anonymous mmap reserves a Windows address range (the *
 * wine-preloader reserves the DOS area + ~1.7 GiB low + a high top-down  *
 * window BEFORE the PE loader runs, so Win32 images land where they      *
 * expect).  We record a LOGICAL span only — no vspace reservation, no    *
 * frames (committing 1.7 GiB of page bookkeeping would exhaust the       *
 * arena).  A later MAP_FIXED mmap, or an mprotect that makes a page      *
 * accessible, commits just the touched sub-range; the anon/file high-    *
 * water allocator skips reserved spans so a non-fixed mmap never lands   *
 * inside a reserved-but-uncommitted Windows range.                       *
 * ===================================================================== */
#define LUCAS_MMAP_RESERVE_MIN (8u * 1024 * 1024)   /* >= 8 MiB PROT_NONE = a reservation, not a guard page */

static struct lucas_resv_region *lucas_resv_find(lucas_state_t *st, uintptr_t vaddr) {
    for (int i = 0; i < LUCAS_MAX_RESV_REGIONS; ++i) {
        struct lucas_resv_region *r = &st->resv_regions[i];
        if (r->in_use && vaddr >= r->vstart && vaddr < r->vend) return r;
    }
    return NULL;
}

static int lucas_resv_register(lucas_state_t *st, uintptr_t vstart, uintptr_t vend) {
    for (int i = 0; i < LUCAS_MAX_RESV_REGIONS; ++i) {
        if (st->resv_regions[i].in_use) continue;
        st->resv_regions[i] = (struct lucas_resv_region){ .in_use = true, .vstart = vstart, .vend = vend };
        return 0;
    }
    return -1;   /* table full */
}

/* Bump a high-water candidate [start, start+len) past every reservation it
 * intersects, so a non-fixed mmap never collides with a reserved window. */
static uintptr_t lucas_resv_skip(lucas_state_t *st, uintptr_t start, size_t len) {
    bool moved = true;
    while (moved) {
        moved = false;
        for (int i = 0; i < LUCAS_MAX_RESV_REGIONS; ++i) {
            struct lucas_resv_region *r = &st->resv_regions[i];
            if (r->in_use && start < r->vend && r->vstart < start + len) {
                start = r->vend; moved = true;
            }
        }
    }
    return start;
}

/* Commit one page at `va` when it lies inside a logical reservation (called by
 * mprotect on an otherwise-unmapped page, and reusable elsewhere).  Returns 1 if
 * va is in a reservation (committed it if prot is accessible; left it reserved-
 * unmapped for PROT_NONE), 0 if va is not reserved (caller handles as before). */
int lucas_mmap_commit_reserved(lucas_state_t *st, uintptr_t va, uint64_t prot) {
    va &= ~0xFFFUL;
    if (!lucas_resv_find(st, va)) return 0;          /* not reserved · caller's problem */
    if (prot == 0) return 1;                          /* PROT_NONE · stays reserved/unmapped */
    int can_read  = (prot & (LX_PROT_READ | LX_PROT_EXEC)) ? 1 : 0;
    int can_write = (prot & LX_PROT_WRITE) ? 1 : 0;
    seL4_CapRights_t rights = seL4_CapRights_new(0, 0, can_read, can_write);
    if (vspace_get_cap(&st->client_vspace_abs, (void *)va) != seL4_CapNull) {
        seL4_CPtr fr = vspace_get_cap(&st->client_vspace_abs, (void *)va);
        (void)seL4_X86_Page_Map(fr, st->client_vspace, (seL4_Word)va, rights,
                                seL4_X86_Default_VMAttributes);
        return 1;
    }
    reservation_t res = vspace_reserve_range_at(&st->client_vspace_abs, (void *)va,
                                                4096, rights, 1);
    if (!res.res) {
        printf("[mmap-commit] reserve @0x%lx failed (consuming)\n", (unsigned long)va);
        return 1;   /* in-reservation but couldn't back · don't fall to EACCES */
    }
    int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs, (void *)va, 1, 12, res);
    if (err) {
        printf("[mmap-commit] new_page @0x%lx err=%d\n", (unsigned long)va, err);
        vspace_free_reservation(&st->client_vspace_abs, res);
        return 1;
    }
    seL4_CPtr fr = vspace_get_cap(&st->client_vspace_abs, (void *)va);
    (void)seL4_X86_Page_Map(fr, st->client_vspace, (seL4_Word)va, rights,
                            seL4_X86_Default_VMAttributes);
    return 1;
}

/* U5 · MS-M5 partial · file-backed mmap (MAP_PRIVATE only).
 *
 * Allocates frames in the client's vspace and seeds them with file content
 * fetched via the VFS op_read of the open fd.  Read-only or copy-on-read
 * for now · MAP_SHARED write-back is deferred.  The dynamic-linker text/data
 * mappings the musl loader emits use MAP_PRIVATE, which is what this path
 * targets.  Pattern mirrors elf_segments.c lucas_elf_reload_data: dup the
 * frame cap into parent_vspace, memcpy through that window, unmap.  Returns
 * the chosen vaddr on success, negative Linux errno on failure. */
static int64_t lucas_mmap_file_backed(lucas_state_t *st, uint64_t addr,
                                       uint64_t length, uint64_t prot,
                                       uint64_t flags, int fd, uint64_t offset) {
    /* N3/D2 · file-backed mappings up to 16 MiB (real .so segments).  The
     * ceiling bounds eager frame seeding against the static allocman pool;
     * a single musl .so segment is well under this.  (Lazy fault-in is a
     * future optimisation; eager is the lower-risk D2 path.) */
    const size_t LUCAS_MMAP_FILE_MAX = 16 * 1024 * 1024;  /* 16 MiB */
    if (length > LUCAS_MMAP_FILE_MAX) {
        printf("[mmap] file-backed · len=%lu > 16 MiB cap · -ENOMEM\n",
               (unsigned long)length);
        return -(int64_t)LX_ENOMEM;
    }

    if (fd < 0 || fd >= LUCAS_MAX_FDS) return -(int64_t)LX_EBADF;
    lucas_fd_t *fde = &st->fds[fd];
    if (fde->kind != LUCAS_FD_VFS || fde->mount == NULL ||
        fde->mount->ops == NULL || fde->mount->ops->read == NULL) {
        printf("[mmap] file-backed · fd=%d not a VFS fd (kind=%d) · -ENOSYS\n",
               fd, (int)fde->kind);
        return -(int64_t)LX_ENOSYS;
    }
    /* MAP_SHARED handling.  A WRITABLE shared file map needs real write-back
     * (dirty pages propagated to the file) which is still deferred.  But a
     * READ-ONLY (no PROT_WRITE) shared map needs NO write-back — it is
     * semantically identical to a private read-only map (content seeded from the
     * file, no dirty pages to flush), so we allow it via the same seed path.
     * Many libraries mmap data files this way: e.g. libxkbcommon maps the xkb
     * rules/keymap files MAP_SHARED|PROT_READ (GTK keymap compile).  The musl
     * dynamic linker uses MAP_PRIVATE for code+data. */
    bool wine_shared_zero_ok = false;   /* wine writable MAP_SHARED · tolerate a failed seed-read (zeroed section) */
    if (!(flags & LX_MAP_PRIVATE)) {
        /* Linux requires EXACTLY one of MAP_PRIVATE / MAP_SHARED (/SHARED_VALIDATE,
         * which includes the MAP_SHARED bit) · neither → EINVAL.  Don't silently
         * accept flags==0 as a read-only map (a deception tell + lenient input). */
        if (!(flags & LX_MAP_SHARED))
            return -(int64_t)22;   /* -EINVAL */
        int is_wine = 0;
        for (const char *p = st->exe_path; *p; ++p)
            if (p[0]=='w'&&p[1]=='i'&&p[2]=='n'&&p[3]=='e') { is_wine = 1; break; }
        if (prot & LX_PROT_WRITE) {
            /* WINE-M1 · writable MAP_SHARED file-backed.  TRUE cross-process
             * shared-frame write-back is a larger feature (a global inode→frames
             * registry · TODO).  But wine's __wine_user_shared_data section only
             * needs the map to SUCCEED; a per-process seeded copy of the (zeroed)
             * backing is enough to unblock the SCM.  GATE to the wine chain so
             * every OTHER guest keeps the honest -ENOSYS: a genuine MAP_SHARED IPC
             * user must NOT silently get a private copy (worse than a clean
             * failure it can handle).  Falls through to the seed/overlay path. */
            if (!is_wine) {
                printf("[mmap] file-backed · writable MAP_SHARED write-back not supported · -ENOSYS\n");
                return -(int64_t)LX_ENOSYS;
            }
            printf("[mmap] file-backed · writable MAP_SHARED · WINE per-process seeded copy "
                   "(cross-process sharing TODO) · pid=%d fd=%d len=%lu\n",
                   st->synthetic_pid, fd, (unsigned long)length);
            /* fall through to the seed/overlay path */
        }
        /* WINE-M1 · a wine MAP_SHARED section (RW *or* RO) may be backed by an
         * open-but-unlinked wineserver tmpmap whose SCM-dup'd handle reads EISDIR
         * — e.g. __wine_user_shared_data, which services.exe maps READ-ONLY at
         * 0x7ffe0000 (run38).  Such sections are zero-initialized, so tolerate a
         * failed seed-read (leave the page zeroed) below.  Non-wine RO MAP_SHARED
         * (libxkbcommon keymaps, …) keeps the flag false → a read failure stays a
         * real error, as it must be. */
        if (is_wine) wine_shared_zero_ok = true;
        /* read-only MAP_SHARED → fall through, treated as a seeded (or zeroed) map */
    }

    size_t pages = (length + 4095) / 4096;

    /* Pick vaddr · mirror the MAP_ANONYMOUS branch (without ASLR jitter for
     * file-backed since the dynamic linker passes specific addrs). */
    uintptr_t chosen_vaddr;
    if ((flags & LX_MAP_FIXED) && addr != 0) {
        chosen_vaddr = addr & ~4095UL;
    } else if (addr != 0) {
        /* Hint · honour it page-aligned (musl ld.so uses hint+MAP_FIXED later). */
        chosen_vaddr = addr & ~4095UL;
    } else {
        if (st->mmap_high_water == 0) st->mmap_high_water = LUCAS_MMAP_BASE;
        chosen_vaddr = lucas_resv_skip(st, st->mmap_high_water, length);  /* avoid Windows reservations */
        uintptr_t end = (chosen_vaddr + length + 0xFFFUL) & ~0xFFFUL;
        st->mmap_high_water = end + 4096;  /* one-page guard gap */
    }

    /* OBSD-ε XONLY / W⊕X enforcement.  Reject contradictory combos
     * outright; downgrade EXEC-only to read-only (closest seL4 has
     * to pure execute-only on x86_64).  Mirror of OpenBSD mprotect
     * semantics adapted for capability-based MMU.  File-backed seeding
     * via sel4utils_dup_and_map(parent_vspace, frame, ...) is independent
     * of the client-side rights stored in the reservation, so applying
     * the W^X policy here does not break the seed loop below. */
    seL4_CapRights_t rights;
    {
        const uint64_t W = LX_PROT_WRITE;
        const uint64_t X = LX_PROT_EXEC;
        const uint64_t R = LX_PROT_READ;

        if ((prot & W) && (prot & X)) {
            if (st->trusted) {
                /* SP1 · the trusted in-OS C compiler needs writable-executable
                 * memory for code generation.  Grant ReadWrite caprights;
                 * pages stay executable via the default (no-NX) VMAttributes
                 * the mapping path already uses.  Untrusted sotboxes keep the
                 * W^X rejection below. */
                rights = seL4_ReadWrite;
            } else {
                /* W⊕X violation · OpenBSD rejects this outright.  We log + reject
                 * with -EINVAL.  Anomaly logs this as an exploit indicator. */
                printf("[obsd-ε] W^X violation pid=%d prot=0x%lx · rejecting (file-backed)\n",
                       st->synthetic_pid, (unsigned long)prot);
                return -(int64_t)22;  /* -EINVAL */
            }
        } else if (prot & X) {
            /* Execute-only request · we don't have pure XO on x86_64
             * but seL4_CanRead is the closest (still readable, but at least
             * not writable · same as OpenBSD's fallback on non-XO archs). */
            rights = seL4_CanRead;
        } else if (prot & W) {
            /* Writable (with or without R · userland always implicitly R) */
            rights = seL4_ReadWrite;
        } else if (prot & R) {
            /* Pure read-only */
            rights = seL4_CanRead;
        } else {
            /* PROT_NONE · map but make unreadable.  seL4 forces at least
             * CanRead; fault-on-access is the userland-visible effect via
             * a guard-page handler.  Use seL4_CanRead and document. */
            rights = seL4_CanRead;
        }
    }

    /* TIER1-MMAP-RO · disabled · forcing seL4_CanRead on every Tier-1
     * mmap broke the L6·silenced smoke (busybox couldn't allocate writable
     * heap and crashed before reaching its silent-success write path).
     * Tier-1 hardening at the mmap level is too aggressive: the sotbox
     * still needs writable heap/stack/data to function · STAR's
     * deception requires the malware to KEEP RUNNING, not crash on a
     * mprotect/munmap pattern.  The behavioral hardening in
     * src/lucas/functor.c + handlers_fs.c + handlers_net.c covers the
     * actually-observable side-effects (writes, sockets, connects).
     * See docs/star-tier2-hardening.md for the cap-revoke audit. */

    /* N3/D3 · LAZY path for large file-backed MAP_PRIVATE mappings (the .so
     * span reservation the dynamic loader makes).  Reserve the span WITHOUT
     * allocating/seeding frames; register a lazy region; the VMFault handler
     * backs pages on first-touch.  Keep D2's eager path for small mappings and
     * for the MAP_FIXED segment overlays (handled below).  Pin the VFS handle:
     * the guest closes the .so fd right after mmap, so the region owns it. */
    #define LUCAS_LAZY_THRESHOLD (64 * 1024)   /* 64 KiB */
    if (!(flags & LX_MAP_FIXED) && length >= LUCAS_LAZY_THRESHOLD) {
        reservation_t lres = vspace_reserve_range_at(&st->client_vspace_abs,
                                                     (void *)chosen_vaddr,
                                                     pages * 4096,
                                                     rights, 1 /*cacheable*/);
        if (lres.res == NULL) {
            printf("[mmap] lazy · reserve_range_at failed at 0x%lx (pages=%zu)\n",
                   (unsigned long)chosen_vaddr, pages);
            return -(int64_t)LX_ENOMEM;
        }
        if (lucas_lazy_register(st, chosen_vaddr, chosen_vaddr + pages * 4096,
                                offset, length, rights, lres,
                                fde->mount, fde->handle) != 0) {
            printf("[mmap] lazy · region table full · -ENOMEM\n");
            vspace_free_reservation(&st->client_vspace_abs, lres);
            return -(int64_t)LX_ENOMEM;
        }
        fde->lazy_pinned = true;   /* close() must not free the handle */
        printf("[mmap] lazy ok · pid=%d fd=%d off=%lu len=%lu prot=0x%lx · vaddr=0x%lx pages=%zu (on-demand)\n",
               st->synthetic_pid, fd, (unsigned long)offset, (unsigned long)length,
               (unsigned long)prot, (unsigned long)chosen_vaddr, pages);
        return (int64_t)chosen_vaddr;
    }

    /* N3/D2 · MAP_FIXED overlay.  The musl dynamic loader reserves a .so's
     * whole span with one mmap, then MAP_FIXED-overlays each PT_LOAD segment
     * (e.g. the RW data segment) onto that span.  Those target pages are
     * already mapped, so vspace_reserve_range_at would fail with "Range not
     * available".  Detect the overlay and RE-MAP the existing frames with the
     * new prot's rights (seL4_X86_Page_Map · the mprotect idiom) instead of
     * reserving fresh; the seed loop below then overwrites their content. */
    /* Find a lazy region covering chosen_vaddr (a MAP_FIXED segment overlay
     * onto a lazily-reserved .so span · e.g. the RW data segment). */
    lucas_lazy_region_t *lazy_hit = NULL;
    if (flags & LX_MAP_FIXED) {
        for (int i = 0; i < LUCAS_MAX_LAZY_REGIONS; ++i) {
            lucas_lazy_region_t *r = &st->lazy_regions[i];
            if (r->in_use && chosen_vaddr >= r->vstart &&
                chosen_vaddr + pages * 4096 <= r->vend) { lazy_hit = r; break; }
        }
    }
    bool overlay = false;
    if ((flags & LX_MAP_FIXED) &&
        vspace_get_cap(&st->client_vspace_abs, (void *)chosen_vaddr) != seL4_CapNull) {
        overlay = true;
    }

    if (overlay) {
        for (size_t i = 0; i < pages; ++i) {
            uintptr_t pv = chosen_vaddr + i * 4096;
            seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
            if (!frame) {
                /* Overlay must stay within the already-reserved span. */
                printf("[mmap] file-backed overlay · gap page at 0x%lx · -ENOMEM\n",
                       (unsigned long)pv);
                return -(int64_t)LX_ENOMEM;
            }
            lucas_doom_watch_frame(frame, pv, "mmap-overlay");
            int merr = seL4_X86_Page_Map(frame, st->client_vspace, (seL4_Word)pv,
                                         rights, seL4_X86_Default_VMAttributes);
            if (merr) {
                printf("[mmap] file-backed overlay · Page_Map failed at 0x%lx (err=%d)\n",
                       (unsigned long)pv, merr);
                return -(int64_t)LX_ENOMEM;
            }
        }
    } else if (lazy_hit) {
        /* MAP_FIXED segment overlay onto a lazy span · alloc just these pages
         * into the lazy region's existing reservation (small · the RW data
         * segment) + map with the overlay's rights.  The seed loop below then
         * fills their file content. */
        for (size_t i = 0; i < pages; ++i) {
            uintptr_t pv = chosen_vaddr + i * 4096;
            if (vspace_get_cap(&st->client_vspace_abs, (void *)pv) == seL4_CapNull) {
                int e = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                                  (void *)pv, 1, 12, lazy_hit->res);
                if (e) {
                    printf("[mmap] lazy-overlay · new_pages err=%d at 0x%lx\n",
                           e, (unsigned long)pv);
                    return -(int64_t)LX_ENOMEM;
                }
            }
            seL4_CPtr fr = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
            (void)seL4_X86_Page_Map(fr, st->client_vspace, (seL4_Word)pv, rights,
                                    seL4_X86_Default_VMAttributes);
        }
    } else {
        /* Reserve + allocate fresh frames at chosen_vaddr. */
        reservation_t res = vspace_reserve_range_at(&st->client_vspace_abs,
                                                     (void *)chosen_vaddr,
                                                     pages * 4096,
                                                     rights, 1 /*cacheable*/);
        if (res.res == NULL) {
            printf("[mmap] file-backed · reserve_range_at failed at 0x%lx (pages=%zu)\n",
                   (unsigned long)chosen_vaddr, pages);
            return -(int64_t)LX_ENOMEM;
        }
        int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                             (void *)chosen_vaddr,
                                             pages, 12, res);
        if (err) {
            printf("[mmap] file-backed · new_pages_at_vaddr failed (err=%d)\n", err);
            vspace_free_reservation(&st->client_vspace_abs, res);
            return -(int64_t)LX_ENOMEM;
        }
    }

    /* Seed each frame with file content via the VFS op_read.  Use the
     * dup_and_map window pattern (same as elf_segments.c reload_data). */
    size_t total_filled = 0;
    for (size_t i = 0; i < pages; ++i) {
        uintptr_t pv = chosen_vaddr + i * 4096;
        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
        if (!frame) {
            printf("[mmap] file-backed · no frame at 0x%lx after alloc\n",
                   (unsigned long)pv);
            return -(int64_t)LX_ENOMEM;
        }
        lucas_doom_watch_frame(frame, pv, "mmap-seed");
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                             frame, seL4_PageBits);
        if (!local) {
            printf("[mmap] file-backed · dup_and_map failed at 0x%lx\n",
                   (unsigned long)pv);
            return -(int64_t)LX_ENOMEM;
        }

        /* Compute the portion of the file mapped into this page.  Page i
         * corresponds to file offset (offset + i*4096), capped at length. */
        size_t want = 4096;
        size_t page_start_in_map = i * 4096;
        if (page_start_in_map + want > length) {
            want = length - page_start_in_map;
        }
        /* Zero the page first · pages past EOF or trailing bytes are zero
         * per POSIX mmap semantics. */
        memset(local, 0, 4096);
        if (want > 0) {
            /* Phase C · thread the caller into op_read so the COW read-merge
             * fires — an edited-then-mmap'd file must serve the session overlay,
             * not leak the pristine base (mirrors handlers_fs.c). */
            lucas_set_current_caller(st);
            int64_t got = fde->mount->ops->read(fde->mount->backend_state,
                                                fde->handle, local, want,
                                                (int64_t)(offset + page_start_in_map));
            lucas_set_current_caller(NULL);
            if (got < 0) {
                if (wine_shared_zero_ok) {
                    /* wine writable MAP_SHARED · the backing can't be seeded — e.g.
                     * __wine_user_shared_data is backed by an open-but-unlinked
                     * wineserver tmpmap whose SCM-dup'd handle reads EISDIR.  The
                     * section is zero-initialized anyway, so leave the page zeroed
                     * (memset'd above) and proceed instead of failing the mmap
                     * (run37: services.exe virtual_map_user_shared_data → EISDIR). */
                    printf("[mmap] wine MAP_SHARED · seed read rc=%ld tolerated · page zeroed (fd=%d off=%lu)\n",
                           (long)got, fd, (unsigned long)(offset + page_start_in_map));
                    got = 0;
                } else {
                    printf("[mmap] file-backed · op_read failed at off=%lu (rc=%ld) · fd=%d kind=%d handle=%p pinned=%d memfd=%d\n",
                           (unsigned long)(offset + page_start_in_map), (long)got,
                           fd, (int)fde->kind, fde->handle, fde->lazy_pinned ? 1 : 0, fde->is_memfd);
                    sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
                    return (int64_t)got;
                }
            }
            total_filled += (size_t)got;
            /* Short read · remainder already zeroed by memset above. */
        }
        /* Wine M1 · Phase 5k · author KUSER_SHARED_DATA.SystemCall (offset 0x308).
         * That ULONG byte selects how wine's PE-side ntdll syscall stubs
         * transition: bit0 SET → `call *[0x7ffe1000]` (__wine_syscall_dispatcher,
         * a userspace routine); CLEAR → a raw `syscall` instruction.  On real
         * wine only the wineserver sets SystemCall=1, via a *writable* MAP_SHARED
         * of the USD section — which LUCAS refuses (writable shared write-back is
         * unimplemented, returns -ENOSYS above), so the flag never reaches the
         * section backing.  The spawned wineboot is then the first process to run
         * the PE-side stubs, hits the raw `syscall` with eax=0x0b
         * (NtAllocateVirtualMemory), which LUCAS reads as Linux munmap (#11) →
         * the alloc silently no-ops → RtlCreateHeap returns NULL → ProcessHeap
         * NULL → VMFault locking a NULL heap's CS.  Author the bit deterministically
         * as we seed the USD page (fixed guest vaddr 0x7ffe0000, SystemCall is in
         * page 0) so every wine process takes the dispatcher path.  The per-process
         * dispatcher pointer at 0x7ffe1000 is already written by wine's own
         * signal_init_process, so setting bit0 here is sufficient. */
        if (i == 0 && chosen_vaddr == 0x7ffe0000UL) {
            int is_wine = 0;
            for (const char *p = st->exe_path; *p; ++p)
                if (p[0] == 'w' && p[1] == 'i' && p[2] == 'n' && p[3] == 'e') { is_wine = 1; break; }
            if (is_wine) {
                ((volatile uint8_t *)local)[0x308] |= 0x1u;
                printf("[mmap] wine USD · KUSER[0x308].SystemCall |= 1 → dispatcher path (pid=%d)\n",
                       st->synthetic_pid);
            }
        }
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
    }

#ifdef CONFIG_X86_MPK
    /* OBSD-η · attach protection key 1 to execute-only mappings.
     * Combined with the orch-startup PKRU config that sets key 1 = AD,
     * this gives pure execute-only: malware can jump to .text but
     * cannot read its bytes back (defeats ROP gadget scouting). */
    if ((prot & LX_PROT_EXEC) && !(prot & LX_PROT_WRITE)) {
        for (size_t i = 0; i < pages; ++i) {
            uintptr_t pv = chosen_vaddr + i * 4096;
            seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs,
                                              (void *)pv);
            if (frame) {
                (void)seL4_X86_Frame_SetProtectionKey(frame, 1);
            }
        }
    }
#endif

    /* C1 · one line per successful file-backed mmap (entry+ok coalesced) ·
     * Python/busybox startup maps many files, so a single summary line per
     * call keeps the trace readable; error paths above keep their own lines. */
    printf("[mmap] file-backed ok · pid=%d fd=%d off=%lu len=%lu prot=0x%lx flags=0x%lx · vaddr=0x%lx pages=%zu seeded=%zu bytes\n",
           st->synthetic_pid, fd, (unsigned long)offset, (unsigned long)length,
           (unsigned long)prot, (unsigned long)flags,
           (unsigned long)chosen_vaddr, pages, total_filled);
    return (int64_t)chosen_vaddr;
}

int64_t lucas_sys_mmap(lucas_state_t *st, uint64_t addr, uint64_t length,
                       uint64_t prot, uint64_t flags, uint64_t fd, uint64_t offset) {
    /* L13 · wl_shm pool: map the shared frames RW into the guest. Must precede the
     * file-backed early-return (MAP_SHARED would otherwise hit -ENOSYS). */
    if (fd < LUCAS_MAX_FDS && st->fds[fd].is_memfd && (flags & LX_MAP_SHARED)) {
        int pid = st->fds[fd].shm_pool_id;
        if (pid < 0) return -22;                  /* -EINVAL: ftruncate must precede mmap */
        extern uintptr_t orch_shm_pool_map_guest(int, vspace_t *, uintptr_t, size_t);
        /* pass the mmap length so the pool grows to cover what the guest maps. */
        uintptr_t va = orch_shm_pool_map_guest(pid, &st->client_vspace_abs,
                                               LUCAS_SHM_POOL_BASE, (size_t)length);
        if (!va) return -12;                       /* -ENOMEM */
        st->fds[fd].shm_guest_vaddr = va;
        printf("[l13-mmap] memfd fd=%lu pool=%d -> guest @0x%lx (%lu B)\n",
               (unsigned long)fd, pid, (unsigned long)va,
               (unsigned long)st->fds[fd].shm_pool_size);
        return (int64_t)va;
    }
    /* File-backed path · MS-M5 partial (U5). */
    if (!(flags & LX_MAP_ANONYMOUS)) {
        if (length == 0) return -(int64_t)LX_EINVAL;
        return lucas_mmap_file_backed(st, addr, length, prot, flags,
                                       (int)(int64_t)fd, offset);
    }

    (void)offset;
    if (!(flags & LX_MAP_PRIVATE)) {
        return -(int64_t)LX_EINVAL;
    }
    if (fd != (uint64_t)-1 && !(flags & LX_MAP_ANONYMOUS)) {
        return -(int64_t)LX_EINVAL;
    }
    if (length == 0) return -(int64_t)LX_EINVAL;

    size_t pages = (length + 4095) / 4096;

    /* Wine-prep · a LARGE PROT_NONE anonymous mapping is an address-space
     * RESERVATION, not real memory (the wine-preloader reserves the Windows low
     * ranges before the PE loader runs).  Record a logical span — no vspace
     * reservation, no frames — and return its base; a later MAP_FIXED mmap or
     * mprotect-to-accessible commits the touched pages.  Small PROT_NONE
     * mappings (guard pages) keep the eager path below. */
    if ((prot & (LX_PROT_READ | LX_PROT_WRITE | LX_PROT_EXEC)) == 0 &&
        length >= LUCAS_MMAP_RESERVE_MIN) {
        uintptr_t rv;
        if ((flags & LX_MAP_FIXED) && addr != 0) {
            rv = addr & ~4095UL;
        } else {
            if (st->mmap_high_water == 0) st->mmap_high_water = LUCAS_MMAP_BASE;
            rv = lucas_resv_skip(st, st->mmap_high_water, length);
            st->mmap_high_water = ((rv + length + 0xFFFUL) & ~0xFFFUL) + 4096;
        }
        uintptr_t rvend = (rv + length + 0xFFFUL) & ~0xFFFUL;
        if (lucas_resv_register(st, rv, rvend) != 0) {
            printf("[mmap] pid=%d RESERVE · resv table full · -ENOMEM\n", st->synthetic_pid);
            return -(int64_t)LX_ENOMEM;
        }
        printf("[mmap] pid=%d RESERVE vaddr=0x%lx len=%lu fixed=%d (frame-less · Windows range)\n",
               st->synthetic_pid, (unsigned long)rv, (unsigned long)length,
               (flags & LX_MAP_FIXED) ? 1 : 0);
        return (int64_t)rv;
    }

    /* Pick vaddr. */
    uintptr_t chosen_vaddr;
    uint32_t  jitter_pages = 0;
    if ((flags & LX_MAP_FIXED) && addr != 0) {
        /* MAP_FIXED must honour the requested address verbatim;
         * guard-page logic does NOT apply to this branch.  (A MAP_FIXED that
         * lands inside a logical reservation just commits frames there via the
         * fresh-reserve path below — the span was never vspace-reserved.) */
        chosen_vaddr = addr & ~4095UL;
    } else if ((flags & LX_MAP_FIXED_NOREPLACE) && addr != 0) {
        /* MAP_FIXED_NOREPLACE · honour addr verbatim but DO NOT take the
         * MAP_FIXED replace/overlay path below (NOREPLACE must never clobber an
         * existing mapping).  The fresh-reserve path reserves at this exact
         * address and fails if it is occupied, which is the correct EEXIST-ish
         * behaviour — and for a free address (wine's probe) returns addr, ending
         * the retry loop.  Do not touch mmap_high_water (addr is caller-chosen). */
        chosen_vaddr = addr & ~4095UL;
    } else {
        if (st->mmap_high_water == 0) {
            st->mmap_high_water = LUCAS_MMAP_BASE;
        }
        /* obsd-γ (§12.7.3): jitter base by 0-15 pages before each
         * allocation so successive mmaps don't land on predictable
         * addresses (ASLR).  arc4random is seeded at orch BOOTSTRAP
         * (obsd-β). */
        jitter_pages = sotos_arc4random_uniform(16);
        chosen_vaddr = st->mmap_high_water + (uintptr_t)jitter_pages * 4096;
        /* Wine-prep · skip past any reserved Windows window (LUCAS_MMAP_BASE
         * 0x40000000 falls inside the preloader's ~1.7 GiB low reservation). */
        chosen_vaddr = lucas_resv_skip(st, chosen_vaddr, length);

        /* Round the end of the mapped region up to a page boundary. */
        uintptr_t end = (chosen_vaddr + length + 0xFFFUL) & ~0xFFFUL;

        /* obsd-γ: leave a 1-page guard gap so any overrun past `end`
         * hits an unmapped page and page-faults rather than silently
         * corrupting the next allocation. */
        st->mmap_high_water = end + 4096;
    }

    /* OBSD-ε XONLY / W⊕X enforcement.  Reject contradictory combos
     * outright; downgrade EXEC-only to read-only (closest seL4 has
     * to pure execute-only on x86_64).  Mirror of OpenBSD mprotect
     * semantics adapted for capability-based MMU. */
    seL4_CapRights_t rights;
    const uint64_t W = LX_PROT_WRITE;
    const uint64_t X = LX_PROT_EXEC;
    const uint64_t R = LX_PROT_READ;

    if ((prot & W) && (prot & X)) {
        if (st->trusted) {
            /* SP1 · the trusted in-OS C compiler needs writable-executable
             * memory for code generation.  Grant ReadWrite caprights; pages
             * stay executable via the default (no-NX) VMAttributes the mapping
             * path already uses.  Untrusted sotboxes keep the W^X rejection
             * below. */
            rights = seL4_ReadWrite;
        } else {
            /* W⊕X violation · OpenBSD rejects this outright.  We log + reject
             * with -EINVAL.  Anomaly logs this as an exploit indicator. */
            printf("[obsd-ε] W^X violation pid=%d prot=0x%lx · rejecting\n",
                   st->synthetic_pid, (unsigned long)prot);
            return -(int64_t)22;  /* -EINVAL */
        }
    } else if (prot & X) {
        /* Execute-only request · we don't have pure XO on x86_64
         * but seL4_CanRead is the closest (still readable, but at least
         * not writable · same as OpenBSD's fallback on non-XO archs). */
        rights = seL4_CanRead;
    } else if (prot & W) {
        /* Writable (with or without R · userland always implicitly R) */
        rights = seL4_ReadWrite;
    } else if (prot & R) {
        /* Pure read-only */
        rights = seL4_CanRead;
    } else {
        /* PROT_NONE · map but make unreadable.  seL4 forces at least
         * CanRead; fault-on-access is the userland-visible effect via
         * a guard-page handler.  Use seL4_CanRead and document. */
        rights = seL4_CanRead;
    }

    /* TIER1-MMAP-RO · disabled · forcing seL4_CanRead on every Tier-1
     * mmap broke the L6·silenced smoke (busybox couldn't allocate writable
     * heap and crashed before reaching its silent-success write path).
     * Tier-1 hardening at the mmap level is too aggressive: the sotbox
     * still needs writable heap/stack/data to function · STAR's
     * deception requires the malware to KEEP RUNNING, not crash on a
     * mprotect/munmap pattern.  The behavioral hardening in
     * src/lucas/functor.c + handlers_fs.c + handlers_net.c covers the
     * actually-observable side-effects (writes, sockets, connects).
     * See docs/star-tier2-hardening.md for the cap-revoke audit. */

    /* L2 fix: use vspace_reserve_range_at + vspace_new_pages_at_vaddr
     * (rather than sel4utils_map_page_leaky) so the mapping is registered
     * in the vspace_t metadata · this is what vspace_get_cap relies on
     * for the companion to be able to read/write client buffers via
     * dup_and_map.  sel4utils_map_page_leaky was "leaky" in the sense
     * that it bypassed this bookkeeping. */
    /* N3/D3 · anonymous MAP_FIXED overlay onto a lazy span (the .so's bss tail:
     * musl maps the zero-fill bss as a separate MAP_ANONYMOUS|MAP_FIXED region
     * at the end of the data segment, INSIDE the lazily-reserved span).  Those
     * vaddrs are owned by the lazy reservation, so reserve_range_at would fail.
     * Alloc the pages into the lazy region's reservation (seL4 zero-fills) +
     * map with the rights · no seeding (anonymous = zero). */
    lucas_lazy_region_t *anon_lazy_hit = NULL;
    bool anon_fixed_premapped = false;
    if (flags & LX_MAP_FIXED) {
        for (int i = 0; i < LUCAS_MAX_LAZY_REGIONS; ++i) {
            lucas_lazy_region_t *r = &st->lazy_regions[i];
            if (r->in_use && chosen_vaddr >= r->vstart &&
                chosen_vaddr + pages * 4096 <= r->vend) { anon_lazy_hit = r; break; }
        }
        /* No lazy region, but the target is ALREADY MAPPED → an anon MAP_FIXED
         * overlay onto an EAGERLY-mapped (<64 KiB) lib span.  musl maps a small
         * lib's whole span (incl .bss pages) from the file, then anon-overlays
         * the .bss pages to zero them.  The lazy path registers a region so this
         * is caught above; the eager path does NOT — so without this case the
         * overlay fell through to the fresh-reserve below and failed "Range not
         * available" (e.g. libeconf/libblkid/libz · the GTK closure's small libs).
         * Mirror the file-backed `overlay` detection (cap-present, not lazy). */
        if (!anon_lazy_hit &&
            vspace_get_cap(&st->client_vspace_abs, (void *)chosen_vaddr) != seL4_CapNull)
            anon_fixed_premapped = true;
    }
    if (anon_fixed_premapped) {
        extern int lucas_copy_to_client(lucas_state_t *, uintptr_t, const void *, size_t);
        static const uint8_t zero_pg2[4096];
        for (size_t i = 0; i < pages; ++i) {
            uintptr_t pv = chosen_vaddr + i * 4096;
            seL4_CPtr fr = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
            if (!fr) {   /* a gap inside the overlay (bss beyond the mapped span) */
                printf("[lucas] sys_mmap: anon fixed-overlay gap at 0x%lx · -ENOMEM\n",
                       (unsigned long)pv);
                return -(int64_t)LX_ENOMEM;
            }
            (void)seL4_X86_Page_Map(fr, st->client_vspace, (seL4_Word)pv, rights,
                                    seL4_X86_Default_VMAttributes);
            (void)lucas_copy_to_client(st, pv, zero_pg2, 4096);   /* anon ≡ zero */
        }
    } else if (anon_lazy_hit) {
        extern int lucas_copy_to_client(lucas_state_t *, uintptr_t, const void *, size_t);
        static const uint8_t zero_pg[4096];
        for (size_t i = 0; i < pages; ++i) {
            uintptr_t pv = chosen_vaddr + i * 4096;
            int preexisting =
                (vspace_get_cap(&st->client_vspace_abs, (void *)pv) != seL4_CapNull);
            if (!preexisting) {
                int e = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                                  (void *)pv, 1, 12, anon_lazy_hit->res);
                if (e) {
                    printf("[lucas] sys_mmap: anon lazy-overlay new_pages err=%d at 0x%lx\n",
                           e, (unsigned long)pv);
                    return -(int64_t)LX_ENOMEM;
                }
            }
            seL4_CPtr fr = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
            (void)seL4_X86_Page_Map(fr, st->client_vspace, (seL4_Word)pv, rights,
                                    seL4_X86_Default_VMAttributes);
            /* N3 · anonymous MAP_FIXED ≡ zero-fill.  A FRESH vspace page is
             * already zero, but a page that PRE-EXISTED at this vaddr was seeded
             * by musl's whole-segment file-backed over-map (map_library maps
             * this_max-this_min, which spans the .bss pages, from the file).
             * The dynamic loader then anonymously MAP_FIXED-overlays exactly
             * those pages so the .bss reads as ZERO — so we must wipe the stale
             * file bytes here, else .bss globals (e.g. SDL_generic_TLS_mutex)
             * hold garbage → a non-canonical pointer → #GP. */
            if (preexisting)
                (void)lucas_copy_to_client(st, pv, zero_pg, 4096);
        }
    } else {
    reservation_t res = vspace_reserve_range_at(&st->client_vspace_abs,
                                                  (void *)chosen_vaddr,
                                                  pages * 4096,
                                                  rights, 1 /*cacheable*/);
    if (res.res == NULL) {
        printf("[lucas] sys_mmap: vspace_reserve_range_at failed at 0x%lx (pages=%zu)\n",
               (unsigned long)chosen_vaddr, pages);
        return -(int64_t)LX_ENOMEM;
    }
    int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                         (void *)chosen_vaddr,
                                         pages, 12 /*page_bits*/, res);
    if (err) {
        printf("[lucas] sys_mmap: vspace_new_pages_at_vaddr failed (err=%d)\n", err);
        vspace_free_reservation(&st->client_vspace_abs, res);
        return -(int64_t)LX_ENOMEM;
    }
    }

#ifdef CONFIG_X86_MPK
    /* OBSD-η · attach protection key 1 to execute-only mappings.
     * Combined with the orch-startup PKRU config that sets key 1 = AD,
     * this gives pure execute-only: malware can jump to .text but
     * cannot read its bytes back (defeats ROP gadget scouting).
     *
     * Iterate frames in the new mapping and set key 1 on each.  The
     * X86_Frame_SetProtectionKey invocation comes from sibling Unit M1
     * (KernelLucasMPK cmake flag → CONFIG_X86_MPK).  Block is dead code
     * when the kernel patch isn't applied. */
    if ((prot & X) && !(prot & W)) {
        for (size_t i = 0; i < pages; ++i) {
            uintptr_t pv = chosen_vaddr + i * 4096;
            seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs,
                                              (void *)pv);
            if (frame) {
                (void)seL4_X86_Frame_SetProtectionKey(frame, 1);
            }
        }
    }
#endif

    /* obsd-γ: log every successful anonymous mmap for visibility.
     * guard@ is the first byte of the unmapped guard page past the
     * allocation's end.  Anomaly composition point: a VMFault on
     * the guard page is the signal sotFS-θ uses for the overrun-
     * detector rule (wired in L6-Phase-B, A3). */
    {
        uintptr_t end = (chosen_vaddr + length + 0xFFFUL) & ~0xFFFUL;
        if (!g_orch_quiet)
        printf("[mmap] pid=%d obsd-γ vaddr=0x%lx len=%lu guard@0x%lx (jitter=%u pages)\n",
               st->synthetic_pid,
               (unsigned long)chosen_vaddr,
               (unsigned long)length,
               (unsigned long)end,
               jitter_pages);
    }

    return (int64_t)chosen_vaddr;
}

/* === L2 munmap stub ===================================================== */

/* True if `va` falls inside a LAZY file-backed mmap region or an address-space
 * RESERVATION.  The arena reclaim must NOT zero/recycle/unmap such pages: a lazy
 * region pins a VFS handle and faults pages on-demand INTO a vspace reservation,
 * so tearing its frames + reservation out from under the lazy_regions[]
 * bookkeeping invokes an invalid cap on the next fault (the GTK breaker); a
 * reservation has no committed frames at all.  Only PURE anon-private frames
 * (the python/pip churn the reclaim exists for) are safe to recycle. */
static int lucas_va_in_lazy_or_resv(const lucas_state_t *st, uintptr_t va)
{
    for (int i = 0; i < LUCAS_MAX_LAZY_REGIONS; ++i)
        if (st->lazy_regions[i].in_use &&
            va >= st->lazy_regions[i].vstart && va < st->lazy_regions[i].vend)
            return 1;
    for (int i = 0; i < LUCAS_MAX_RESV_REGIONS; ++i)
        if (st->resv_regions[i].in_use &&
            va >= st->resv_regions[i].vstart && va < st->resv_regions[i].vend)
            return 1;
    return 0;
}

/* mremap IN-PLACE extend · grow an anon region by mapping ONLY the delta pages
 * [old_end, new_end) when that span is free.  Returns 0 on success, -1 if it
 * cannot extend (next page occupied/reserved, or reserve/map fails → caller
 * relocates).  apt's pkgCacheGenerator grows its ~50 MiB DynamicMMap by
 * mremap(MAYMOVE); the always-move fallback advances the arena's untyped
 * watermark every grow → "Dynamic MMap ran out of room" at ~22 MiB.  In-place
 * maps only the 1 MiB delta against the SAME base: monotonic, no copy, no
 * double residency, no watermark churn.  apt's cache lives at the mmap high-
 * water + grows contiguous, so the span after it is normally free → in-place hits. */
int lucas_mmap_extend_inplace(lucas_state_t *st, uint64_t addr,
                              uint64_t old_size, uint64_t new_size) {
    if (new_size <= old_size) return 0;
    uintptr_t base    = addr & ~0xFFFUL;
    uintptr_t old_end = (base + old_size + 0xFFFUL) & ~0xFFFUL;
    uintptr_t new_end = (base + new_size + 0xFFFUL) & ~0xFFFUL;
    if (new_end <= old_end) return 0;
    for (uintptr_t va = old_end; va < new_end; va += 4096) {
        if (vspace_get_cap(&st->client_vspace_abs, (void *)va) != seL4_CapNull)
            return -1;                            /* occupied · must relocate */
        if (lucas_va_in_lazy_or_resv(st, va))
            return -1;                            /* reserved/lazy · must relocate */
    }
    size_t bytes = (size_t)(new_end - old_end);
    size_t pages = bytes / 4096;
    reservation_t res = vspace_reserve_range_at(&st->client_vspace_abs,
                                                (void *)old_end, bytes,
                                                seL4_ReadWrite, 1);
    if (res.res == NULL) return -1;
    if (vspace_new_pages_at_vaddr(&st->client_vspace_abs, (void *)old_end,
                                  pages, 12, res) != 0) {
        vspace_free_reservation(&st->client_vspace_abs, res);
        return -1;
    }
    if (new_end + 4096 > st->mmap_high_water) st->mmap_high_water = new_end + 4096;
    return 0;
}

int64_t lucas_sys_munmap(lucas_state_t *st, uint64_t addr, uint64_t length,
                         uint64_t _a2, uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    if (addr == 0 || length == 0) return 0;

    /* ARENA IN-LIFE RECLAIM.  Historically munmap was a NO-OP that LEAKED the pages
     * (seL4's untyped watermark can't roll back, so a freed frame's memory is lost
     * until the wholesale arena revoke).  For a CHURNING heavy guest (python import
     * / pip: mmap→munmap→mmap a moving heap) that exhausts the 128 MiB arena even
     * with a tiny live set.  Reclaim by REUSE: unmap each page keeping its cap
     * (vspace_unmap_pages with vka=NULL), zero it, and hand the cap to the arena's
     * frame free-list (arena_utspace_alloc reuses it for the next 4 KiB mmap).
     *
     * GATED for safety by ADDRESS RANGE (not arena class): only the PRIVATE mmap
     * region (addr >= 0x40000000).  NEVER the low text/data/fork-shared region — a
     * fork child's RO-shared frames alias the parent's, so zeroing + reusing one
     * would corrupt the parent.  Pages outside that window keep the historical no-op
     * (a benign leak reclaimed wholesale at teardown). */
    extern int sotbox_arena_recycle_frame(vka_t *vka, seL4_CPtr frame_cap);
    extern int lucas_copy_to_client(lucas_state_t *st, uintptr_t client_vaddr,
                                    const void *src_buf, size_t size);
    /* UNCONDITIONAL for ALL arenas — heavy AND regular ("light").  This reclaim is
     * what stops musl's mmap->munmap->mmap churn from growing without bound; light
     * boxes (busybox-static `ls`, the persistent canary shell) churn just as hard as
     * heavy ones, and gating it to heavy arenas leaked their freed frames until the
     * wholesale revoke — a single `ls` climbed toward the 8192-cslot ceiling
     * (`cspace exhausted` -> code=1) and the shell's footprint grew over uptime.
     * The reclaim ZEROS + RECYCLES each freed frame, so it must NEVER touch a frame
     * that is SHARED (another vspace/process still reads it).  The REAL safety
     * invariant is the ADDRESS-SPACE LAYOUT — not the arena class — and it makes the
     * safe set exact, with no per-region tracking (enforced by the clamp just below):
     *   - [0x40000000, LUCAS_SHM_POOL_BASE) is the PRIVATE anon-mmap window (the
     *     churn heap).  BELOW 0x40000000 = fork-shared TEXT/RODATA (a child's RO
     *     cap-copies ALIAS the parent · zeroing one corrupts the parent).  AT/ABOVE
     *     LUCAS_SHM_POOL_BASE (0x200000000) = wl_shm pools — orch-owned frames the
     *     compositor still reads, the exact frames that broke GTK when the gate was
     *     merely "heavy arena".  File-backed MAP_SHARED inside the window is a
     *     per-process SEEDED COPY (private frames · cross-process write-back is a
     *     TODO in lucas_mmap_file_backed), hence safe to reclaim.
     *   - A vfork child shares the parent's WHOLE vspace (CLONE_VM), so reclaiming
     *     its high pages would corrupt the parent · skip vfork children entirely. */
    if (st->vfork_parent_slot1 != 0)
        return 0;   /* vfork child shares the parent vspace · never reclaim here */

    uintptr_t start = addr & ~(uintptr_t)0xFFFu;
    uintptr_t end   = (addr + length + 0xFFFu) & ~(uintptr_t)0xFFFu;
    /* Clamp to the private anon-mmap window · never zero fork-text or wl_shm. */
    if (start < 0x40000000UL)          start = 0x40000000UL;
    if (end   > LUCAS_SHM_POOL_BASE)   end   = LUCAS_SHM_POOL_BASE;
    if (start >= end) return 0;   /* nothing reclaimable in this munmap */
    size_t    npages = (end - start) >> 12;
    static const uint8_t zero4k[4096];   /* .bss · all-zero */
    int recycled = 0;

    /* Does this munmap range touch a lazy/reservation region?  If not (the common
     * pure-anon churn case · python/pip), take the FAST path: zero+recycle every
     * page then ONE bulk unmap.  If it does, go per-page so lazy/resv pages are
     * left completely untouched (historical no-op · reclaimed at the wholesale
     * revoke) while the interleaved anon pages are still recycled+unmapped. */
    int has_special = 0;
    for (uintptr_t va = start; va < end && !has_special; va += 4096u)
        has_special = lucas_va_in_lazy_or_resv(st, va);

    if (!has_special) {
        for (uintptr_t va = start; va < end; va += 4096u) {
            seL4_CPtr cap = vspace_get_cap(&st->client_vspace_abs, (void *)va);
            if (!cap) continue;                              /* lazy/reserved/unmapped */
            /* zero the frame WHILE still mapped here, so the reused frame is clean for
             * the next MAP_ANONYMOUS (POSIX zero-fill · musl calloc-via-mmap relies on
             * it).  lucas_copy_to_client maps the frame into orch, memsets, unmaps. */
            (void)lucas_copy_to_client(st, va, zero4k, 4096);
            if (sotbox_arena_recycle_frame(st->vka, cap)) recycled++;
        }
        /* unmap the whole range from the client WITHOUT freeing the caps (vka=NULL
         * keeps them · we recycled them).  clear_entries frees the vaddr for reuse. */
        vspace_unmap_pages(&st->client_vspace_abs, (void *)start, npages, seL4_PageBits, NULL);
    } else {
        for (uintptr_t va = start; va < end; va += 4096u) {
            if (lucas_va_in_lazy_or_resv(st, va)) continue;  /* leave lazy/resv intact */
            seL4_CPtr cap = vspace_get_cap(&st->client_vspace_abs, (void *)va);
            if (!cap) continue;
            (void)lucas_copy_to_client(st, va, zero4k, 4096);
            if (sotbox_arena_recycle_frame(st->vka, cap)) recycled++;
            vspace_unmap_pages(&st->client_vspace_abs, (void *)va, 1, seL4_PageBits, NULL);
        }
    }
    if (recycled)
        printf("[munmap] pid=%d · reclaimed %d frame(s) [0x%lx..0x%lx)\n",
               st->synthetic_pid, recycled, (unsigned long)start, (unsigned long)end);
    return 0;
}
