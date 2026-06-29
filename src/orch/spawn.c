/*
 * sotOs · orchestrator · sotbox_spawn entry.
 *
 * For L3a, sotbox_spawn is a thin wrapper around the existing
 * lucas_run_l1 from the sotOs-lucas static library.  It accepts the
 * ELF bytes (already located in orch's CPIO by the caller) and an
 * argv array, builds the seL4 environment from orch_vka()/etc., and
 * calls lucas_run_l1.
 *
 * lucas_run_l1 blocks the calling thread in the fault loop until the
 * client exits.  Multi-sotBox concurrency (T7+) introduces a multi-
 * client fault loop.  For now (L3a-T6) one sotBox at a time is fine.
 *
 * The orchestrator is a child process spawned by sel4utils, NOT the
 * root task.  It does NOT have a bootinfo frame.  Its CSpace is laid
 * out per the sel4utils enum:
 *   SEL4UTILS_CNODE_SLOT      = 1 (root CNode)
 *   SEL4UTILS_ENDPOINT_SLOT   = 2 (listen EP)
 *   SEL4UTILS_PD_SLOT         = 3 (own VSpace root / PML4)
 *   SEL4UTILS_ASID_POOL_SLOT  = 4 (ASID pool delegated from root)
 *   SEL4UTILS_TCB_SLOT        = 5 (own TCB)
 *   SEL4UTILS_FIRST_FREE      = 8 (start of allocman's free range)
 *
 * The orch allocman pool is 64 KiB.  We must NOT call
 * sel4utils_bootstrap_vspace_leaky (it creates many paging-structure
 * objects and exhausts the metadata pool).  Instead we build a
 * minimal orch_vspace_t whose new_pages directly allocates frames
 * from the VKA and maps them into orch's own PML4 via sel4utils_map_page.
 * This consumes just ~10 allocman entries per frame, keeping metadata
 * usage well within 64 KiB for the ~30 frames a typical LUCAS L2 run
 * needs for bookkeeping.
 */

#include <orch/sotbox.h>
#include <orch/proto.h>
#include <orch/arena.h>
#include <lucas/pledge.h>
#include <lucas/functor.h>
#include <sotos/random.h>
#include <sotos/pidrand.h>   /* C2 #10 · deterministic display_pid (ASLR-independent) */
#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include <simple/simple.h>
#include <sel4utils/vspace.h>
#include <sel4utils/vspace_internal.h>
#include <sel4utils/process.h>   /* SEL4UTILS_* slot constants */
#include <sel4utils/mapping.h>   /* sel4utils_map_page */
#include <vka/vka.h>
#include <vka/object.h>
#include <vspace/vspace.h>
#include <lucas_l1.h>   /* from sotOs-lucas PUBLIC include dir (src/lucas/) */

/* From bootstrap.c. */
extern vka_t *orch_vka(void);

/* Storage for the "primary" (first-spawned) sotBox.
 * L3b: lucas_run_l1 allocates its state on the stack, so we need a place
 * for it to live for the lifetime of orch_fault_loop.  We use a static
 * here; a future multi-spawn extension would use a table. */
static lucas_state_t g_primary_st;
static int           g_primary_inited = 0;

/* ---------------------------------------------------------------------------
 * Minimal simple_t for orch (child process · no bootinfo).
 *
 * The orchestrator's CSpace was built by sel4utils_configure_process_custom
 * with 14 bits.  sel4utils always places caps at the fixed offsets defined
 * in SEL4UTILS_* above.
 *
 * The only simple callback that lucas_run_l1 actually invokes:
 *   init_cap(seL4_CapInitThreadASIDPool) → SEL4UTILS_ASID_POOL_SLOT = 4
 * ---------------------------------------------------------------------------*/

static seL4_CPtr orch_simple_init_cap(void *data, seL4_CPtr cap_pos)
{
    (void)data;
    switch (cap_pos) {
        case seL4_CapInitThreadASIDPool:  return SEL4UTILS_ASID_POOL_SLOT;
        case seL4_CapInitThreadVSpace:    return SEL4UTILS_PD_SLOT;
        case seL4_CapInitThreadCNode:     return SEL4UTILS_CNODE_SLOT;
        case seL4_CapInitThreadTCB:       return SEL4UTILS_TCB_SLOT;
        default:                          return cap_pos;
    }
}

static seL4_Error orch_simple_asid_assign(void *data, seL4_CPtr vspace)
{
    (void)data;
    return seL4_X86_ASIDPool_Assign(SEL4UTILS_ASID_POOL_SLOT, vspace);
}

static int      orch_simple_cap_count(void *d)    { (void)d; return 0; }
static seL4_CPtr orch_simple_nth_cap(void *d, int n) { (void)d; (void)n; return seL4_CapNull; }
static uint8_t  orch_simple_cnode_size(void *d)   { (void)d; return 18; /* 17->18 · apt pkgCache cslots · matches root/bootstrap.c */ }
static int      orch_simple_untyped_count(void *d){ (void)d; return 0; }
static seL4_CPtr orch_simple_nth_untyped(void *d, int n, size_t *sb, uintptr_t *pa, bool *dev)
    { (void)d; (void)n; (void)sb; (void)pa; (void)dev; return seL4_CapNull; }
static int      orch_simple_userimage_count(void *d) { (void)d; return 0; }
static seL4_CPtr orch_simple_nth_userimage(void *d, int n) { (void)d; (void)n; return seL4_CapNull; }
static int      orch_simple_core_count(void *d)  { (void)d; return 1; }
static void     orch_simple_print(void *d)        { (void)d; }

static void orch_simple_init(simple_t *s)
{
    memset(s, 0, sizeof(*s));
    s->data            = NULL;
    s->init_cap        = orch_simple_init_cap;
    s->ASID_assign     = orch_simple_asid_assign;
    s->cap_count       = orch_simple_cap_count;
    s->nth_cap         = orch_simple_nth_cap;
    s->cnode_size      = orch_simple_cnode_size;
    s->untyped_count   = orch_simple_untyped_count;
    s->nth_untyped     = orch_simple_nth_untyped;
    s->userimage_count = orch_simple_userimage_count;
    s->nth_userimage   = orch_simple_nth_userimage;
    s->core_count      = orch_simple_core_count;
    s->print           = orch_simple_print;
}

/* ---------------------------------------------------------------------------
 * Minimal vspace_t for orch (parent_vspace passed to lucas_run_l1).
 *
 * lucas_run_l1 uses parent_vspace in two ways:
 *
 *   (A) new_pages — called by sel4utils_get_vspace to allocate the bookkeeping
 *       tree for the client vspace.  We bump-allocate frames from orch_vka()
 *       and map them into orch's PML4 (slot SEL4UTILS_PD_SLOT=3).
 *
 *   (B) map_pages / unmap_pages — called by sel4utils_elf_load (via
 *       load_segment in libsel4utils/src/elf.c) to temporarily map each
 *       client page into the loader (=orch) address space so the ELF data
 *       can be memcpy'd.  The caller already has a valid frame cap in orch's
 *       CSpace; we just need to map it at a temporary vaddr and return that.
 *       unmap_pages with VSPACE_PRESERVE = NULL just unmaps without freeing.
 *
 * The bump range is 32 MB starting at 0x20000000 (well above orch's image
 * which is loaded at 0x400000-0x9e8000, and below the LUCAS mmap base
 * at 0x40000000).  32 MB = 8192 pages which is more than enough.
 *
 * We share the same bump allocator for (A) and (B).  Temporary loader
 * pages from (B) are never freed from the bump; they are just unmapped and
 * the vaddr is reused by the next call (we reset the bump back after each
 * unmap).  Because elf.c does exactly one map/unmap at a time we only ever
 * need one "active" loader slot.
 * ---------------------------------------------------------------------------*/

#define ORCH_PARENT_VSPACE_BASE  0x20000000UL
#define ORCH_PARENT_VSPACE_LIMIT 0x28000000UL   /* 128 MiB range · supports 5+ vspaces */

/* ZERO-LEAK (client-vspace bookkeeping) · per-sotbox PT-aligned windows.
 * The client-vspace bookkeeping (sel4utils data pages, allocated by
 * orch_parent_new_pages) used to come from orch_vka + a single global bump and
 * was NEVER freed (arena-revoke only reclaims the sotbox's OWN objects) → a
 * ~7.3 frame/spawn leak. Fix: give each sotbox slot its own 2 MiB (= one x86 PT)
 * window so NO page-table is shared between slots, and back the leaf bookkeeping
 * FRAMES from the owning sotbox's ARENA (so arena-revoke frees + unmaps them
 * wholesale). The window's paging structs (the PT) stay on orch_vka — allocated
 * once per slot, reused across that slot's spawns (the window bump resets on
 * teardown). The global bump (loader dup_and_map · orch_parent_map_pages) lives
 * ABOVE the windows so the two allocators never collide. */
#define ORCH_BK_WINDOW_BYTES     0x200000UL                       /* 2 MiB = 1 PT */
#define ORCH_BK_WINDOWS_END      (ORCH_PARENT_VSPACE_BASE + (unsigned long)SOTBOX_MAX_SLOTS * ORCH_BK_WINDOW_BYTES)

static uintptr_t g_parent_vspace_bump = ORCH_BK_WINDOWS_END;  /* loader/dup path · above the windows */
static size_t    g_bk_window_used[SOTBOX_MAX_SLOTS];          /* leaf pages live in each slot's window */

/* The sotbox currently being charged for client-vspace bookkeeping. Set around
 * create_client_vspace + ELF load (spawn/fork) and around fault dispatch (lazy
 * mmap growth); NULL → fall back to the legacy global-bump + orch_vka path. */
static lucas_state_t *g_vspace_owner = NULL;
void orch_set_vspace_owner(lucas_state_t *st) { g_vspace_owner = st; }

/* NET count of leaf client-vspace bookkeeping pages currently live (++ on alloc,
 * -= a slot's window on teardown). Was a cumulative-no-decrement leak gauge; now
 * NET so a soak slope of ~0 proves the bookkeeping is reclaimed. */
static long g_root_pages_total = 0;
long orch_root_pages_total(void) { return g_root_pages_total; }

/* Teardown hook · the arena-revoke already freed + unmapped this slot's leaf
 * bookkeeping frames; reset the window bump so the next spawn into this slot
 * reuses the same address range (and its already-allocated PT), and drop the
 * net page count. Safe to call for a slot that never allocated (used==0). */
void orch_vspace_window_release(int slot) {
    if (slot < 0 || slot >= SOTBOX_MAX_SLOTS) return;
    g_root_pages_total -= (long)g_bk_window_used[slot];
    g_bk_window_used[slot] = 0;
}

/* One-slot loader-page tracking (elf.c uses at most one at a time). */
#define LOADER_SLOTS 4
static struct {
    uintptr_t  vaddr;
    seL4_CPtr  cap;
    bool       active;
} g_loader_pages[LOADER_SLOTS];

/* ---------------------------------------------------------------------------
 * orch_parent_new_pages — (A) allocate frames owned by orch and map them.
 * ---------------------------------------------------------------------------*/
static void *orch_parent_new_pages(vspace_t *vs, seL4_CapRights_t rights,
                                    size_t num_pages, size_t size_bits)
{
    (void)rights;
    if (size_bits != seL4_PageBits) {
        printf("[orch] orch_parent_new_pages: unsupported size_bits=%zu\n", size_bits);
        return NULL;
    }

    /* ZERO-LEAK · client-vspace bookkeeping (vs != NULL) for a sotbox that has
     * an arena uses that sotbox's PT-aligned window + arena-backed leaf frames,
     * so arena-revoke reclaims them. orch's own staging (vs == NULL) and the
     * no-owner fallback keep the legacy global-bump + orch_vka path. */
    lucas_state_t *owner = (vs != NULL) ? g_vspace_owner : NULL;
    int use_window = (owner && owner->arena &&
                      owner->slot_index >= 0 && owner->slot_index < SOTBOX_MAX_SLOTS);
    int       slot      = -1;
    uintptr_t vaddr, end;
    vka_t    *frame_vka = orch_vka();

    if (use_window) {
        slot = owner->slot_index;
        uintptr_t wbase = ORCH_PARENT_VSPACE_BASE + (uintptr_t)slot * ORCH_BK_WINDOW_BYTES;
        vaddr = wbase + (uintptr_t)g_bk_window_used[slot] * PAGE_SIZE_4K;
        end   = vaddr + num_pages * (1ul << size_bits);
        if (end > wbase + ORCH_BK_WINDOW_BYTES) {
            printf("[orch] new_pages: slot=%d bookkeeping window full · orch_vka fallback\n", slot);
            use_window = 0;                       /* degrade to legacy path below */
        } else {
            frame_vka = &owner->arena->vka;       /* arena-backed → freed by revoke */
        }
    }
    if (!use_window) {
        vaddr = g_parent_vspace_bump;
        end   = vaddr + num_pages * (1ul << size_bits);
        if (end > ORCH_PARENT_VSPACE_LIMIT) {
            printf("[orch] orch_parent_new_pages: bump range exhausted\n");
            return NULL;
        }
        g_parent_vspace_bump = end;
    }

    for (size_t i = 0; i < num_pages; ++i) {
        uintptr_t page_vaddr = vaddr + i * PAGE_SIZE_4K;

        vka_object_t frame;
        int err = vka_alloc_frame(frame_vka, size_bits, &frame);
        if (err) {
            printf("[orch] orch_parent_new_pages: vka_alloc_frame failed (err=%d)\n", err);
            return NULL;
        }

        /* Map the frame into orch's PML4 at page_vaddr.  The PAGING structs
         * (PDPT/PD/PT) always come from orch_vka — for a window they are
         * allocated once for that slot's 2 MiB PT and reused across the slot's
         * spawns (the leaf frame is arena-backed + freed by revoke; the PT is
         * not, so it persists for reuse). */
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        err = sel4utils_map_page(orch_vka(),
                                  SEL4UTILS_PD_SLOT,
                                  frame.cptr,
                                  (void *)page_vaddr,
                                  seL4_AllRights,
                                  1 /* cacheable */,
                                  paging, &npaging);
        if (err) {
            printf("[orch] orch_parent_new_pages: sel4utils_map_page @0x%lx failed (err=%d)\n",
                   page_vaddr, err);
            return NULL;
        }

        if (vs) ++g_root_pages_total;             /* NET leaf bookkeeping pages */
        if (use_window) g_bk_window_used[slot]++;

        /* Zero the newly mapped page so bookkeeping structs are clean. */
        memset((void *)page_vaddr, 0, PAGE_SIZE_4K);
    }

    return (void *)vaddr;
}

/* SP2-migración · reusable staging region for loading LARGE binaries from
 * binstore/sotfs.  The CPIO path is zero-copy (pointer into orch's archive),
 * but binstore/sotfs binaries must be read into a contiguous RAM buffer for
 * the ELF loader (elf_newFile needs random access).  python3.12-static is
 * 24.4 MB — far past the 1 MiB static buffer.  We lazily map ORCH_STAGE_MAX
 * bytes from orch's parent vspace ON FIRST USE (i.e. the first >2 MiB spawn,
 * which happens post-boot), so orch's boot footprint is unaffected — the
 * whole point of moving python out of the CPIO.  Reused across spawns
 * (orch is single-threaded · spawns are sequential). */
#define ORCH_STAGE_MAX_BYTES (28u * 1024u * 1024u)   /* >= python3.12-static (24.4 MB) */
static uint8_t *g_stage_base = NULL;

void *orch_spawn_stage(size_t bytes)
{
    if (bytes > ORCH_STAGE_MAX_BYTES) {
        printf("[orch] stage: %zu bytes exceeds ORCH_STAGE_MAX_BYTES (%u)\n",
               bytes, ORCH_STAGE_MAX_BYTES);
        return NULL;
    }
    if (g_stage_base == NULL) {
        size_t npages = ORCH_STAGE_MAX_BYTES / PAGE_SIZE_4K;
        g_stage_base = (uint8_t *)orch_parent_new_pages(NULL, seL4_AllRights,
                                                        npages, seL4_PageBits);
        if (g_stage_base == NULL) {
            printf("[orch] stage: failed to map %zu pages (%u MiB)\n",
                   npages, ORCH_STAGE_MAX_BYTES / (1024 * 1024));
            return NULL;
        }
        printf("[orch] stage: mapped %u MiB staging region @ %p\n",
               ORCH_STAGE_MAX_BYTES / (1024 * 1024), (void *)g_stage_base);
    }
    return g_stage_base;
}

/* ---------------------------------------------------------------------------
 * orch_parent_map_pages — (B) map caller-provided caps into orch's address space.
 *
 * Called by load_segment in libsel4utils/src/elf.c:
 *   vspace_map_pages(loader_vspace, &loader_frame_cap.capPtr, NULL,
 *                    seL4_AllRights, 1, seL4_PageBits, 1);
 *
 * The caps[] array contains already-valid frame caps in orch's CSpace.
 * We allocate a virtual address from our bump range, map each cap there,
 * record the vaddr→cap pair in g_loader_pages, and return the base vaddr.
 * ---------------------------------------------------------------------------*/
static void *orch_parent_map_pages(vspace_t *vs, seL4_CPtr caps[],
                                    uintptr_t cookies[], seL4_CapRights_t rights,
                                    size_t num_pages, size_t size_bits, int cacheable)
{
    (void)vs; (void)cookies;
    if (size_bits != seL4_PageBits) {
        printf("[orch] orch_parent_map_pages: unsupported size_bits=%zu\n", size_bits);
        return NULL;
    }

    uintptr_t vaddr = g_parent_vspace_bump;
    uintptr_t end   = vaddr + num_pages * (1ul << size_bits);
    if (end > ORCH_PARENT_VSPACE_LIMIT) {
        printf("[orch] orch_parent_map_pages: bump range exhausted\n");
        return NULL;
    }
    g_parent_vspace_bump = end;

    vka_t *vka = orch_vka();
    for (size_t i = 0; i < num_pages; ++i) {
        uintptr_t page_vaddr = vaddr + i * PAGE_SIZE_4K;
        seL4_CPtr cap = caps[i];

        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        int err = sel4utils_map_page(vka,
                                      SEL4UTILS_PD_SLOT,
                                      cap,
                                      (void *)page_vaddr,
                                      rights,
                                      cacheable,
                                      paging, &npaging);
        if (err) {
            printf("[orch] orch_parent_map_pages: sel4utils_map_page @0x%lx cap=%lu failed (err=%d)\n",
                   page_vaddr, (unsigned long)cap, err);
            return NULL;
        }

        /* Record vaddr→cap so unmap_pages can call seL4_X86_Page_Unmap. */
        bool recorded = false;
        for (int s = 0; s < LOADER_SLOTS; ++s) {
            if (!g_loader_pages[s].active) {
                g_loader_pages[s].vaddr  = page_vaddr;
                g_loader_pages[s].cap    = cap;
                g_loader_pages[s].active = true;
                recorded = true;
                break;
            }
        }
        if (!recorded) {
            printf("[orch] orch_parent_map_pages: loader slot table full!\n");
            /* Still mapped; caller will unmap and we just won't find it in the table. */
        }
    }

    return (void *)vaddr;
}

/* ---------------------------------------------------------------------------
 * orch_parent_get_cap — return the cap used to map a given loader vaddr.
 *
 * Called by sel4utils_unmap_dup (via vspace_get_cap) before unmapping
 * so it can delete the cap copy after the unmap.
 * ---------------------------------------------------------------------------*/
static seL4_CPtr orch_parent_get_cap(vspace_t *vs, void *vaddr_p)
{
    (void)vs;
    uintptr_t vaddr = (uintptr_t)vaddr_p;
    for (int s = 0; s < LOADER_SLOTS; ++s) {
        if (g_loader_pages[s].active && g_loader_pages[s].vaddr == vaddr) {
            return g_loader_pages[s].cap;
        }
    }
    return seL4_CapNull;
}

/* ---------------------------------------------------------------------------
 * orch_parent_unmap_pages — (B) unmap previously-mapped loader pages.
 *
 * Called by load_segment immediately after the memcpy:
 *   vspace_unmap_pages(loader_vspace, loader_vaddr, 1, seL4_PageBits, VSPACE_PRESERVE);
 *
 * VSPACE_PRESERVE (= NULL vka) means: unmap but do NOT free the frame or cslot.
 * The caller (elf.c) frees the cslot separately with vka_cnode_delete.
 *
 * We roll the bump pointer back by num_pages pages so the virtual address
 * range is immediately reusable.  This is safe because elf.c does exactly
 * one map/unmap pair at a time.
 * ---------------------------------------------------------------------------*/
static void orch_parent_unmap_pages(vspace_t *vs, void *vaddr_p,
                                     size_t num_pages, size_t size_bits, vka_t *free_vka)
{
    (void)vs; (void)free_vka; /* VSPACE_PRESERVE — do not free */
    uintptr_t base = (uintptr_t)vaddr_p;

    for (size_t i = 0; i < num_pages; ++i) {
        uintptr_t page_vaddr = base + i * (1ul << size_bits);

        /* Find the cap for this vaddr. */
        seL4_CPtr cap = seL4_CapNull;
        for (int s = 0; s < LOADER_SLOTS; ++s) {
            if (g_loader_pages[s].active && g_loader_pages[s].vaddr == page_vaddr) {
                cap = g_loader_pages[s].cap;
                g_loader_pages[s].active = false;
                break;
            }
        }

        if (cap != seL4_CapNull) {
            seL4_X86_Page_Unmap(cap);
        } else {
            printf("[orch] orch_parent_unmap_pages: cap not found for vaddr=0x%lx\n", page_vaddr);
        }
    }

    /* Roll the bump pointer back so the range is reusable. */
    uintptr_t unmap_size = num_pages * (1ul << size_bits);
    if (g_parent_vspace_bump >= base + unmap_size &&
        g_parent_vspace_bump == base + unmap_size) {
        g_parent_vspace_bump = base;
    }
}

/* ---------------------------------------------------------------------------
 * Environment singletons — lazily initialised once.
 * ---------------------------------------------------------------------------*/

static simple_t   g_simple;
static vspace_t   g_parent_vspace;   /* minimal vspace; only new_pages is used */
static int        g_env_initialised = 0;

int orch_env_init(void) {
    if (g_env_initialised) return 0;

    orch_simple_init(&g_simple);

    /* Build a minimal vspace_t that implements new_pages, map_pages, and
     * unmap_pages.  lucas_run_l1 uses parent_vspace in two ways:
     *   (A) new_pages  — allocate bookkeeping memory for the client vspace.
     *   (B) map_pages / unmap_pages — temporarily map client frames into orch
     *       during ELF loading so load_segment can memcpy segment data.
     * All other vspace methods remain NULL. */
    memset(&g_parent_vspace, 0, sizeof(g_parent_vspace));
    g_parent_vspace.new_pages   = orch_parent_new_pages;
    g_parent_vspace.map_pages   = orch_parent_map_pages;
    g_parent_vspace.unmap_pages = orch_parent_unmap_pages;
    g_parent_vspace.get_cap     = orch_parent_get_cap;

    g_env_initialised = 1;
    printf("[orch] env_init: simple + parent_vspace ready\n");
    return 0;
}

/* ---------------------------------------------------------------------------
 * P2a · orch_reclaim_client_vspace — safely tear down a sotbox's client vspace.
 *
 * vspace_tear_down() does two things: (1) walks the client vspace's own levels
 * and frees every mapped frame + leaf page-table via the client vspace's REAL
 * sel4utils unmap (correct — returns the untyped to the vka), then (2) a FINAL
 * vspace_unmap_pages(data->bootstrap, top_level, VSPACE_FREE) to drop the
 * client's bookkeeping, which it routes through the BOOTSTRAP vspace — here that
 * is orch's hand-rolled g_parent_vspace, whose unmap callback
 * (orch_parent_unmap_pages) can't find the bookkeeping cap, ignores free_vka,
 * and does a bump-pointer ROLLBACK never designed for teardown → allocman
 * corruption + an eventual abort.
 *
 * Fix: swap g_parent_vspace.unmap_pages to a benign no-op for the duration of
 * the tear-down.  Step (1) — the bulk frame reclaim — still runs correctly;
 * step (2) becomes a no-op, leaking only the small per-vspace bookkeeping frame
 * (a few KiB) instead of corrupting the pool.  Restore the real callback after.
 * ---------------------------------------------------------------------------*/
static void orch_parent_unmap_noop(vspace_t *vs, void *vaddr_p,
                                    size_t num_pages, size_t size_bits, vka_t *free_vka)
{
    (void)vs; (void)vaddr_p; (void)num_pages; (void)size_bits; (void)free_vka;
    /* Intentionally empty — do NOT run orch_parent_unmap_pages' bump rollback
     * during a client-vspace teardown. */
}

void orch_reclaim_client_vspace(vspace_t *client_abs)
{
    void *saved = (void *)g_parent_vspace.unmap_pages;
    g_parent_vspace.unmap_pages = orch_parent_unmap_noop;
    vspace_tear_down(client_abs, VSPACE_FREE);
    g_parent_vspace.unmap_pages = (typeof(g_parent_vspace.unmap_pages))saved;
}

/* ---------------------------------------------------------------------------
 * sotbox_init — L3b-T1: set up the primary sotBox WITHOUT entering the fault
 * loop.  The caller (main.c SPAWN handler) must call orch_fault_loop()
 * separately AFTER replying to root.
 *
 * Internally this calls the lucas_run_l1 infrastructure up to (and including)
 * lucas_client_resume, but NOT lucas_fault_loop.  We achieve this by calling
 * the individual steps rather than the monolithic lucas_run_l1.
 * ---------------------------------------------------------------------------*/

/* Forward declarations for the steps inside lucas_l1.c / client_setup.c. */
extern int create_client_vspace(lucas_state_t *st);
extern int lucas_elf_validate(const void *elf_bytes, unsigned long elf_size);
extern uintptr_t lucas_elf_entry(const void *elf_bytes);
extern uint64_t lucas_elf_load_end(const void *elf_bytes);
extern int lucas_elf_load_into_client(lucas_state_t *st,
                                       const void *elf_bytes,
                                       unsigned long elf_size);
/* N3/D1 · static-or-dynamic program loader (honours PT_INTERP via ld-musl). */
extern int lucas_elf_load_program(lucas_state_t *st,
                                  const void *elf_bytes,
                                  unsigned long elf_size);
extern int lucas_stack_setup(lucas_state_t *st,
                              const char *const argv[],
                              const char *const envp[]);
extern int lucas_client_setup(lucas_state_t *st);
extern int lucas_client_resume(lucas_state_t *st);
extern void vfs_install_defaults(lucas_state_t *st);
extern int  sotbox_alloc_slot(lucas_state_t *st);
extern void lucas_fault_loop_reset_slot(int slot);

/* v2.4 · one-shot "route the NEXT spawn to the heavy (64 MiB) arena" request.
 * For a small ELF with a large runtime footprint (e.g. gtkspike.bin: 14 KiB but
 * a ~20 MiB GTK3 closure + big heap) that the ELF-size heavy heuristic misses.
 * Consumed + cleared inside the next sotbox_spawn_into. */
static int s_force_heavy_next = 0;
void sotbox_request_heavy_next(void) { s_force_heavy_next = 1; }
/* Like request_heavy, but the spawn ABORTS (-2) instead of silently falling back to
 * a regular arena if the heavy pool is busy — for boxes (a Go binary like micro)
 * that are GUARANTEED to OOM in a 32 MiB regular arena.  The caller retries. */
static int s_require_heavy_next = 0;
void sotbox_require_heavy_next(void) { s_force_heavy_next = 1; s_require_heavy_next = 1; }

/* v2.x · one-shot envp override for the next spawn (see the envp note in
 * sotbox_spawn_into).  Set by a handler that launches an unmodified app needing
 * a launcher-provided environment; consumed + cleared by the next spawn. */
static const char *const *s_spawn_envp_next = NULL;
void sotbox_spawn_set_envp_next(const char *const envp[]) { s_spawn_envp_next = envp; }
const char *const *orch_spawn_take_envp_override(void) {
    const char *const *e = s_spawn_envp_next; s_spawn_envp_next = NULL; return e;
}

/* The real init — parameterized on the state storage so multiple independent
 * sotboxes can coexist (P4a).  Behavior-identical to the old sotbox_init body
 * (operates on the caller-provided st; the g_primary_inited guard + set move
 * to the sotbox_init wrapper below). */
int sotbox_spawn_into(lucas_state_t *st, const void *elf_bytes, unsigned long elf_size,
                      const char *const argv[], int initial_tier,
                      uint64_t pledge_mask, bool trusted) {
    if (orch_env_init() != 0) return -1;

    memset(st, 0, sizeof(*st));
    st->simple        = &g_simple;
    st->vka           = orch_vka();
    st->parent_vspace = &g_parent_vspace;
    st->tier          = initial_tier;       /* L6: Tier 1 = Silenced Mode */
    st->trusted       = trusted;             /* SP1: operator-trusted · tier-pinned by lucas_set_tier */
    st->functor       = lucas_functor_for_tier(initial_tier); /* sotFS-ι: silent init */
    st->silenced_write_count = 0;
    st->cwd[0] = '\0';   /* fidelity · fresh cwd ("/") per spawn · no cross-session bleed */
    /* obsd-δ: propagate pledge from spawn message; 0 means use default PLEDGE_ALL. */
    st->pledge = (pledge_mask == 0) ? PLEDGE_ALL : pledge_mask;
    st->pledge_violations = 0;

    int slot = sotbox_alloc_slot(st);
    if (slot < 0) {
        printf("[orch] sotbox_spawn_into: sotbox_alloc_slot failed\n");
        return -1;
    }
    st->slot_index = slot;
    st->parent_slot = -1;
    st->child_storage_idx = -1;
    st->text_owner_slot = -1;   /* v1.0-rc1 · primary spawn owns its own TEXT */
    st->synthetic_pid   = slot + 1;
    /* OBSD-ζ PID-DISPLAY · sotbox-visible pid · C2 #10 · reproducible-by-design
     * (deterministic in synthetic_pid · never 0) · drawn from a SEPARATE stateless
     * PRNG so the entropy-seeded arc4random/ASLR stream is untouched.
     * synthetic_pid stays sequential for internal LUCAS/anomaly state indexing. */
    st->display_pid = sotos_pid_display((uint32_t)st->synthetic_pid);
    /* v0.10-fix: each fresh sotBox gets a clean non-syscall-fault budget. */
    lucas_fault_loop_reset_slot(slot);
    printf("[orch] sotbox_spawn_into: slot=%d pid=%d display_pid=%u\n",
           slot, st->synthetic_pid, (unsigned int)st->display_pid);

    /* P2a · all this sotbox's OWN objects (PML4/TCB/CNode/IPC frame + ELF/stack
     * frames + client-side page-tables) come from a dedicated arena untyped, so
     * sotbox_destroy reclaims them wholesale via revoke.  orch's parent-vspace
     * bookkeeping + staging stay on orch_vka() (NOT routed — see arena.h note). */
    /* A large guest (CPython · python3.12-static is 24 MiB ≈ 6000+ frame-cslots
     * + heap + 2.6 MiB stdlib) exceeds a regular arena (8192 cslots / 32 MiB) →
     * route it to the HEAVY arena (borrows cslots + a 64 MiB untyped from the
     * allocman on demand). Threshold 16 MiB: only python crosses it (busybox 1.1,
     * chocodoom 2.2, doom 0.5). One heavy box at a time.
     *
     * v2.4 · a SMALL ELF can still have a HUGE runtime footprint: gtkspike.bin is
     * 14 KiB but drags a 57-lib GTK3 closure (~20 MiB eagerly-seeded) + a big
     * heap (pango/cairo/GObject) → it OOM'd in a regular arena (GLib-ERROR
     * "failed to allocate 131072 bytes" → G_BREAKPOINT/int3).  An explicit
     * one-shot request (sotbox_request_heavy_next) routes such a box to heavy. */
    if (elf_size > (16u * 1024u * 1024u) || s_force_heavy_next) {
        int require = s_require_heavy_next;   /* heavy-exec respawn: MUST be heavy or abort */
        s_force_heavy_next = 0; s_require_heavy_next = 0;
        st->arena = sotbox_heavy_acquire();
        if (!st->arena) {
            if (require) {
                /* A regular arena is guaranteed too small for this box (a Go binary's
                 * runtime OOMs) — better to abort + let the caller retry once a heavy
                 * slot frees than to silently degrade into a doomed regular arena. */
                printf("[orch] sotbox_spawn_into: heavy REQUIRED but pool busy · abort (caller retries)\n");
                sotbox_free_slot(slot);
                return -2;   /* distinct from -1 · heavy-unavailable, retryable */
            }
            printf("[orch] sotbox_spawn_into: heavy arena unavailable · regular fallback (likely too small)\n");
        }
    } else {
        st->arena = NULL;
    }
    if (!st->arena) st->arena = sotbox_arena_acquire();
    if (!st->arena) {
        printf("[orch] sotbox_spawn_into: no free arena · teardown pool exhausted\n");
        sotbox_free_slot(slot);
        return -1;
    }
    st->vka = &st->arena->vka;   /* overrides the default st->vka for this sotbox */
    orch_set_vspace_owner(st);   /* zero-leak · charge client-vspace bookkeeping to st's window+arena */

    if (!lucas_elf_validate(elf_bytes, elf_size)) {
        printf("[orch] sotbox_spawn_into: ELF validation failed\n");
        goto fail;
    }
    st->entry_point = lucas_elf_entry(elf_bytes);
    /* Initialise brk_base from ELF load end so the heap doesn't alias
     * the stack (which sits at LUCAS_MMAP_BASE / vspace_new_sized_stack). */
    st->brk_base        = (uintptr_t)lucas_elf_load_end(elf_bytes);
    st->brk_top         = st->brk_base;
    st->mmap_high_water = 0x40000000UL;   /* canonical mmap area */

    /* OBSD-ζ HEAP-BASE-RANDOM (kbind-equivalent) · per-spawn jitter
     * of brk_base so cross-sotbox heap layout is unpredictable.
     * 1 MiB aligned · keeps brk pages aligned for sotnet/sotfs I/O.
     * Max offset 256 MiB · keeps heap_top < mmap_base (0x40000000). */
    uint32_t heap_jitter_mb = sotos_arc4random_uniform(256);
    st->brk_base += ((uintptr_t)heap_jitter_mb) << 20;
    st->brk_top = st->brk_base;  /* reset top to new base */
    printf("[orch] sotbox slot=%d brk_base jittered by %u MiB -> 0x%lx\n",
           slot, (unsigned int)heap_jitter_mb,
           (unsigned long)st->brk_base);

    if (create_client_vspace(st) != 0) {
        printf("[orch] sotbox_spawn_into: create_client_vspace failed\n");
        goto fail;
    }

    /* vDSO arc · Task 4 · map [vvar][vdso] at SOTOS_VDSO_BASE into the fresh
     * guest vspace (non-fatal · libc falls back to the syscall path on miss). */
    if (lucas_map_vdso(st) != 0)
        printf("[orch] sotbox_spawn_into: vDSO map failed · syscall fallback\n");

    /* N3/D1 · dynamic-aware load (PT_INTERP → ld-musl at a PIE base).  For
     * dynamic binaries this overrides st->entry_point (→ ld-musl entry) and
     * brk_base (→ above the high load bases); static binaries are unchanged. */
    if (lucas_elf_load_program(st, elf_bytes, elf_size) != 0) {
        printf("[orch] sotbox_spawn_into: elf_load failed\n");
        goto fail;
    }

    /* envp · default minimal Linux env, OR a caller-supplied override for the
     * next spawn (v2.x · an unmodified off-the-shelf app — e.g. gtk3-demo —
     * expects the LAUNCHER to set GDK_BACKEND, WAYLAND_DISPLAY, the XDG dirs and
     * fontconfig, unlike our fixtures that self-setenv in main).  One-shot. */
    static const char *def_envp[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm", NULL };
    extern const char *const *orch_spawn_take_envp_override(void);
    const char *const *envp = orch_spawn_take_envp_override();
    if (!envp) envp = def_envp;
    if (lucas_stack_setup(st, argv, envp) != 0) {
        printf("[orch] sotbox_spawn_into: stack_setup failed\n");
        goto fail;
    }

    /* DOOM-DBG · pin which setup step clobbers a client text frame (large
     * static binaries only). Verify-only after stack_setup. */
    if (st->trusted) {
        extern int lucas_verify_text_pages(lucas_state_t *, const void *, int, const char *);
        lucas_verify_text_pages(st, elf_bytes, 0, "post-stack");
    }

    if (lucas_client_setup(st) != 0) {
        printf("[orch] sotbox_spawn_into: client_setup failed\n");
        goto fail;
    }

    vfs_install_defaults(st);

    /* Pre-install stdin/stdout/stderr. */
    for (int i = 0; i < 3; ++i) {
        st->fds[i].kind   = LUCAS_FD_STDIO;
        st->fds[i].is_std = true;
        st->fds[i].mount  = NULL;
        st->fds[i].handle = NULL;
        st->fds[i].cursor = 0;
        st->fds[i].flags  = 0;
        st->fds[i].pipe   = NULL;
    }

    /* DOOM-DBG · verify+repair the client text immediately before resume —
     * heals any frame clobbered during stack/client setup so the box executes
     * the real code (vs. foreign frame content). */
    if (st->trusted) {
        extern int lucas_verify_text_pages(lucas_state_t *, const void *, int, const char *);
        lucas_verify_text_pages(st, elf_bytes, 1, "pre-resume");
    }

    if (lucas_client_resume(st) != 0) {
        printf("[orch] sotbox_spawn_into: client_resume failed\n");
        goto fail;
    }

    /* DOOM-DBG · probe the victim text page the instant Resume returns — the
     * box has NOT been scheduled yet (orch is still on-CPU), so this reads the
     * exact handoff state.  Corrupt here => the corruption is at/before Resume
     * (verify-vs-real-PTE divergence or the resume path); clean here => the box
     * (or a concurrent orch thread) corrupts it once it runs. */
    {
        extern void lucas_doom_probe(const char *tag);
        lucas_doom_probe("spawn:post-resume(handoff)");
    }

    /* P2a · the client's seL4 objects (vspace/TCB/CNode/IPC frame/fault EP)
     * are now fully built and the child is resumed.  Mark this sotbox as the
     * owner so sotbox_destroy() reclaims them at reap.  Failure paths above
     * returned early, so the flag stays 0 and destroy is a no-op for them. */
    st->seL4_objects_owned = 1;
    st->forked             = 0;

    orch_set_vspace_owner(NULL);   /* spawn-time bookkeeping done */
    printf("[orch] sotbox_spawn_into done · slot=%d\n", slot);
    return 0;

fail:
    orch_set_vspace_owner(NULL);
    if (st->arena) { sotbox_arena_revoke(st->arena); st->arena = NULL; }
    orch_vspace_window_release(slot);   /* reset window used-count for the freed slot */
    sotbox_free_slot(slot);
    return -1;
}

/* The primary single-spawn path keeps its exact old semantics: a thin wrapper
 * around sotbox_spawn_into on g_primary_st, gated by g_primary_inited. */
int sotbox_init(const void *elf_bytes, unsigned long elf_size,
                const char *const argv[], int initial_tier,
                uint64_t pledge_mask, bool trusted) {
    if (g_primary_inited) {
        printf("[orch] sotbox_init: already initialised (use ORCH_OP_VALIDATE for multi-spawn)\n");
        return -1;
    }
    int rc = sotbox_spawn_into(&g_primary_st, elf_bytes, elf_size, argv,
                               initial_tier, pledge_mask, trusted);
    if (rc == 0) g_primary_inited = 1;
    return rc;
}

/* ---------------------------------------------------------------------------
 * sotbox_reset_primary — called after orch_fault_loop() returns (all sotBoxes
 * from the previous spawn have exited and their slots have been freed).
 * Clears g_primary_inited so sotbox_init() can service the next ORCH_OP_SPAWN.
 *
 * NOTE: we do NOT reset g_parent_vspace_bump because the pages allocated in
 * the bump range are owned by orch's VKA and remain mapped in orch's PML4.
 * Reusing the same bump range would double-map frames that are still tracked
 * by the VKA.  The bump range (0x20000000-0x28000000, 128 MiB VA) has room
 * for many sequential spawns before it can be exhausted.
 * ---------------------------------------------------------------------------*/
void sotbox_reset_primary(void)
{
    g_primary_inited = 0;
    memset(&g_primary_st, 0, sizeof(g_primary_st));
    printf("[orch] sotbox_reset_primary · ready for next spawn\n");
}

/*
 * sotbox_spawn — legacy shim for callers that still want the blocking model.
 * For L3b this is no longer used directly by main.c; kept for compilation.
 */
int sotbox_spawn(const void *elf_bytes, unsigned long elf_size,
                  const char *const argv[]) {
    if (orch_env_init() != 0) return -1;
    return lucas_run_l1(&g_simple, orch_vka(), &g_parent_vspace,
                         elf_bytes, elf_size, argv);
}

/* ---------------------------------------------------------------------------
 * L4-T3: accessors for orch's env singletons, used by spawn_native.c.
 * ---------------------------------------------------------------------------*/
simple_t  *orch_simple(void) {
    orch_env_init();
    return &g_simple;
}

vspace_t  *orch_parent_vspace_ptr(void) {
    orch_env_init();
    return &g_parent_vspace;
}
