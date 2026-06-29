#ifndef SOTOS_ORCH_ARENA_H
#define SOTOS_ORCH_ARENA_H

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Per-sotbox arena: one WHOLE delegated untyped + a contiguous cslot range in
 * orch's CNode.  A custom minimal vka allocates the sotbox's objects from here;
 * sotbox_arena_revoke() reclaims everything in O(1) via seL4_CNode_Revoke. */
typedef struct sotbox_arena {
    seL4_CPtr  ut;            /* the whole arena untyped cap (orch cspace) */
    size_t     ut_size_bits;  /* its size_bits (>= SOTBOX_ARENA_MIN_BITS) */
    seL4_CPtr  cslot_base;    /* base of this arena's reserved contiguous cslot range */
    seL4_Word  cslot_n;       /* range size (SOTBOX_ARENA_CSLOTS) */
    seL4_Word  cslot_bump;    /* high-water mark of allocated cslots; reset to 0 on revoke.
                               * The revoke sweep deletes [base, base+bump), so this stays the
                               * max-ever-used even with free-list reuse below. */
    vka_t      vka;           /* the vka_t handed to the sotbox (data = this struct) */
    bool       in_use;
    /* In-life cslot reuse · without this, cspace_free was a no-op and every
     * sel4utils_dup_and_map (write/copy/mmap) permanently consumed a slot —
     * a long-lived sotbox (e.g. an interactive shell writing a prompt per
     * keystroke) exhausted the 768-slot range during startup. The LIFO holds
     * freed cslot OFFSETS (relative to cslot_base) for re-handout. */
    seL4_Word  cslot_free_n;
    bool       is_heavy;      /* heavy arena · borrows allocman cslots + an on-demand
                              * untyped (both freed at revoke); does NOT use cslot_free */
    uint16_t   cslot_free[8192 /* SOTBOX_ARENA_CSLOTS */];
    /* In-LIFE FRAME RECLAIM (the arena reclaim).  seL4's untyped watermark can't
     * roll back, so a freed 4 KiB frame's memory is lost until the wholesale
     * revoke — UNLESS the frame is REUSED.  munmap (handlers_mem.c) unmaps a page
     * keeping its cap (vspace_unmap_pages with vka=NULL), zeros it, and pushes the
     * cap-cslot here; arena_utspace_alloc pops one for the next 4 KiB-frame request
     * (CNode_Move into the dest slot) instead of retyping fresh from the untyped.
     * Bounds a churning heavy guest (python import / pip) that would otherwise
     * exhaust the arena via alloc→free→alloc even with a tiny live set. */
    seL4_CPtr  frame_free[2048];
    int        frame_free_n;
    /* APT-INSTALL-DIAG · untyped-consumption instrumentation.  Each FRESH 4 KiB
     * retype advances the untyped watermark by 4 KiB and can NEVER roll back;
     * free-list reuse does NOT advance it.  So retyped_frames*4 KiB == the live
     * untyped high-water → tells us how much of the 256 MiB arena apt actually
     * consumed at the exhaustion abort.  Reset to 0 on acquire/revoke. */
    uint32_t   retyped_frames;   /* fresh retypes (watermark advances) */
    uint32_t   reused_frames;    /* free-list hits (watermark unchanged) */
} sotbox_arena_t;

/* 25 (was 23 = 8 MiB): Chocolate Doom + SDL2 needs a ~16 MiB zone + 2.2 MiB
 * binary + SDL surfaces + stacks + client-vspace bookkeeping = ~24 MiB, which
 * overflowed a 16 MiB (24-bit) arena untyped → "Untyped Retype: 0 bytes
 * available" → libsel4utils perform_reservation ASSERT → root abort. A 32 MiB
 * floor leaves comfortable headroom. The delegated untypeds are 24-29 bits;
 * floor 25 strands only the lone 24-bit (16 MiB) block to the allocman, which
 * keeps a 29-bit (512 MiB) block — plenty for orch's 28 MiB staging. */
#define SOTBOX_ARENA_MIN_BITS  25     /* 32 MiB floor */
/* 8192 (was 4096): Chocolate's 16 MiB default zone alone is 4096 frames = the
 * whole old range; +binary +SDL +stacks +PTs ~ 6000 cslots → "cspace exhausted
 * (4096/4096)". 8 arenas × 8192 = 65536 cslots, still half of orch's 1<<17
 * CNode (allocman keeps ~65k). */
#define SOTBOX_ARENA_CSLOTS    8192   /* per-sotbox cslot range (frames + ELF + PTs + objects) */

/* HEAVY arena · for a large guest (CPython · python3.12-static is 24 MiB ≈ 6000+
 * frame-cslots + heap + 2.6 MiB stdlib) that exceeds a regular arena.  ONE at a
 * time.  BORROWS cslots from orch's allocman on demand (no bootstrap reservation
 * → orch keeps its full budget during the demo; growing the CNode instead breaks
 * the root's untyped delegation) + an on-demand 64 MiB untyped; both returned to
 * the allocman at revoke.  CSLOTS caps the borrowed-slot tracking array. */
#define SOTBOX_HEAVY_CSLOTS    65536  /* 256 MiB / 4 KiB · one cslot per frame */
#define SOTBOX_HEAVY_MIN_BITS  28     /* 256 MiB · 128 MiB held GTK/wine but `apt-get
                                       * update` over the FULL trixie main index is the
                                       * heavy-tail consumer: pkgCacheGenerator mmaps
                                       * the 54 MB Packages file AND grows a ~50 MB
                                       * DynamicMMap cache by mremap-copy (transient ~2x)
                                       * → peak ~170 MB, which exhausted a 128 MiB arena
                                       * mid-MergeList ("arena ut exhausted").  256 MiB
                                       * covers it; heavy_acquire falls back 256->128->64
                                       * MiB under memory pressure so lighter method
                                       * forks (http/gpgv) still get a workable arena. */

/* Register one reserved arena (called by bootstrap once per reserved untyped).
 * ut = the delegated untyped cap; cslot_base = first cslot of its reserved range. */
void sotbox_arena_pool_add(seL4_CPtr ut, size_t ut_size_bits, seL4_CPtr cslot_base);

/* Pop a free arena (sets up its vka) or NULL if the pool is exhausted. */
sotbox_arena_t *sotbox_arena_acquire(void);

/* Heavy arena · acquire borrows cslots + a 64 MiB untyped from orch's allocman
 * on demand (NULL if busy / OOM).  Reaped via sotbox_arena_revoke (is_heavy). */
sotbox_arena_t *sotbox_heavy_acquire(void);

/* Reclaim EVERYTHING the arena holds: explicit caller must have already deleted
 * any NON-child caps living in the cslot range (e.g. the minted fault-EP copy),
 * then this revokes the untyped (deletes all children, resets freeIndex),
 * resets the cslot bump, and returns the arena to the free-list. */
void sotbox_arena_revoke(sotbox_arena_t *a);

int  sotbox_arena_pool_count_free(void);   /* diagnostics */

/* Arena in-life FRAME RECLAIM (see sotbox_arena.frame_free).  munmap unmaps a page
 * keeping its cap (vspace_unmap_pages, vka=NULL) + zeros it, then hands the cap here
 * for arena_utspace_alloc to reuse.  Heavy-arena-gated (returns 1 recycled / 0 not). */
int  sotbox_arena_recycle_frame(vka_t *vka, seL4_CPtr frame_cap);
int  sotbox_arena_vka_is_heavy(vka_t *vka);

/* NOTE (adversarial review): we deliberately do NOT introduce a g_active_arena_vka
 * to route orch_parent_new_pages/map_pages through the arena.  Doing so would pull
 * orch's OWN persistent staging region (g_stage_base, 28 MiB) and orch-PML4
 * page-table intermediates (mapped at the monotonic, never-reset bump range) into
 * the arena untyped — revoke would then delete memory orch's own address space
 * references (blockers 1 & 2).  Only the CLIENT's own objects (allocated via
 * st->vka and mapped into the CLIENT vspace) are arena-backed.  orch's parent-vspace
 * bookkeeping + staging stay on orch_vka() (a small per-vspace bookkeeping residual
 * — NOT the K=104 frame leak; documented follow-up). */

#endif
