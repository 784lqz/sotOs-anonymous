#include <orch/arena.h>
#include <orch/sotbox.h>
#include <vka/capops.h>
#include <vka/object.h>   /* kobject_get_type · frame-type match for the arena reclaim */
#include <sel4/sel4.h>
#include <stdio.h>
#include <string.h>

extern vka_t *orch_vka(void);   /* global allocman vka — used only for path-building + revoke */

#define SOTBOX_ARENA_MAX  SOTBOX_MAX_SLOTS

static sotbox_arena_t g_arenas[SOTBOX_ARENA_MAX];
static int            g_arena_count = 0;

/* --- the custom vka function table (data = sotbox_arena_t*) --- */

static int arena_cspace_alloc(void *data, seL4_CPtr *res)
{
    sotbox_arena_t *a = data;
    /* Reuse a reclaimed slot first (in-life churn from dup_and_map etc.). */
    if (a->cslot_free_n > 0) {
        *res = a->cslot_base + a->cslot_free[--a->cslot_free_n];
        return 0;
    }
    if (a->cslot_bump >= a->cslot_n) {
        printf("[arena] cspace exhausted (%lu/%lu)\n",
               (unsigned long)a->cslot_bump, (unsigned long)a->cslot_n);
        return -1;
    }
    *res = a->cslot_base + a->cslot_bump;
    a->cslot_bump++;
    return 0;
}

static void arena_cspace_make_path(void *data, seL4_CPtr slot, cspacepath_t *res)
{
    (void)data;
    /* cslots live in orch's CNode — delegate path construction to the global vka
     * so root/depth/guard match exactly. */
    vka_cspace_make_path(orch_vka(), slot, res);
}

static void arena_cspace_free(void *data, seL4_CPtr slot)
{
    sotbox_arena_t *a = data;
    /* Ignore slots outside this arena's range (defensive). */
    if (slot < a->cslot_base || slot >= a->cslot_base + a->cslot_n) return;
    /* Delete whatever cap occupies the slot BEFORE reclaiming it, so a future
     * SaveCaller/CNode_Copy/retype into the reused slot always lands empty.
     * Delete on an already-empty slot is a harmless no-op, so this is correct
     * for callers that delete-then-free AND callers that relied on the old
     * no-op (which leaked the cap until the wholesale revoke). */
    cspacepath_t cp;
    vka_cspace_make_path(orch_vka(), slot, &cp);
    seL4_CNode_Delete(cp.root, cp.capPtr, cp.capDepth);
    /* Reclaim the slot for in-life reuse (LIFO of offsets). */
    if (a->cslot_free_n < a->cslot_n)
        a->cslot_free[a->cslot_free_n++] = (uint16_t)(slot - a->cslot_base);
}

/* ARENA-DBG · per-box trace of retyped FRAME paddrs to catch a physical frame
 * being handed out twice within one sotbox's life (the suspected chocodoom
 * text-clobber root cause). Reset on acquire; one box loads at a time. */
#define ARENA_TRACE_MAX 4096
static uint64_t g_atrace_pa[ARENA_TRACE_MAX];
static seL4_Word g_atrace_cslot[ARENA_TRACE_MAX];
static int g_atrace_n = 0;
static int g_atrace_on = 0;
void sotbox_arena_trace(int on) { g_atrace_on = on; g_atrace_n = 0; }

static int arena_utspace_alloc(void *data, const cspacepath_t *dest,
                               seL4_Word type, seL4_Word size_bits, seL4_Word *res)
{
    sotbox_arena_t *a = data;
    /* In-life FRAME REUSE: a 4 KiB-frame request reuses a recycled (already-zeroed)
     * frame from the free-list instead of retyping fresh from the untyped — the
     * arena reclaim.  Only exact 4 KiB FRAMES (not page-tables, which are also
     * size_bits==12 but a different type) qualify.  Move the recycled cap into the
     * vspace-provided dest slot, free the now-empty source cslot back to the arena. */
    if (size_bits == seL4_PageBits &&
        type == kobject_get_type(KOBJECT_FRAME, size_bits) &&
        a->frame_free_n > 0) {
        seL4_CPtr fc = a->frame_free[--a->frame_free_n];
        cspacepath_t src;
        vka_cspace_make_path(orch_vka(), fc, &src);
        int me = seL4_CNode_Move(dest->root, dest->capPtr, dest->capDepth,
                                 src.root, src.capPtr, src.capDepth);
        if (me == seL4_NoError) {
            a->vka.cspace_free(a, fc);            /* fc is now empty · reclaim it */
            a->reused_frames++;                   /* DIAG · watermark NOT advanced */
            if (res) *res = (seL4_Word)(a->cslot_bump);
            return 0;
        }
        /* Move failed (shouldn't happen) · drop this recycled cap, fall through to
         * a fresh retype so the alloc still succeeds. */
        printf("[arena] frame reuse CNode_Move failed err=%d · retype fresh\n", me);
    }
    int e = seL4_Untyped_Retype(a->ut, type, size_bits,
                                dest->root, dest->dest, dest->destDepth,
                                dest->offset, 1);
    if (e != seL4_NoError) {
        /* DIAG · the exhaustion point: how much of the arena's untyped was retyped
         * (live watermark = retyped*4 KiB), how big the arena is, and how many
         * frames the free-list reused (would-be churn leak if low). */
        printf("[arena] retype failed type=%lu szbits=%lu err=%d · EXHAUSTED heavy=%d "
               "ut=%zuMiB retyped=%u (=%uMiB) reused=%u freelist=%d cslot_bump=%lu/%lu\n",
               (unsigned long)type, (unsigned long)size_bits, e, a->is_heavy,
               ((size_t)1 << a->ut_size_bits) >> 20,
               a->retyped_frames, (a->retyped_frames * 4u) / 1024u,
               a->reused_frames, a->frame_free_n,
               (unsigned long)a->cslot_bump, (unsigned long)a->cslot_n);
        return -1;
    }
    if (size_bits == seL4_PageBits &&
        type == kobject_get_type(KOBJECT_FRAME, size_bits))
        a->retyped_frames++;             /* DIAG · fresh frame · watermark advanced */
    /* cookie: any non-zero token (free is a no-op, so its value is irrelevant). */
    if (res) *res = (seL4_Word)(a->cslot_bump);

    if (g_atrace_on) {
        seL4_X86_Page_GetAddress_t pa = seL4_X86_Page_GetAddress(dest->capPtr);
        if (!pa.error) {   /* only page/frame caps answer; PT/TCB/etc error out */
            for (int i = 0; i < g_atrace_n; ++i) {
                if (g_atrace_pa[i] == (uint64_t)pa.paddr) {
                    printf("[arena-dbg] DUP paddr=0x%lx · new cslot=%lu prev cslot=%lu\n",
                           (unsigned long)pa.paddr,
                           (unsigned long)dest->capPtr,
                           (unsigned long)g_atrace_cslot[i]);
                }
            }
            if (g_atrace_n < ARENA_TRACE_MAX) {
                g_atrace_pa[g_atrace_n]    = (uint64_t)pa.paddr;
                g_atrace_cslot[g_atrace_n] = dest->capPtr;
                g_atrace_n++;
            }
        }
    }
    return 0;
}

static int arena_utspace_alloc_maybe_device(void *data, const cspacepath_t *dest,
                                            seL4_Word type, seL4_Word size_bits,
                                            bool can_use_dev, seL4_Word *res)
{
    (void)can_use_dev;   /* sotboxes never need device untyped */
    return arena_utspace_alloc(data, dest, type, size_bits, res);
}

static int arena_utspace_alloc_at(void *data, const cspacepath_t *dest,
                                  seL4_Word type, seL4_Word size_bits,
                                  uintptr_t paddr, seL4_Word *cookie)
{
    (void)data; (void)dest; (void)type; (void)size_bits; (void)paddr; (void)cookie;
    printf("[arena] utspace_alloc_at unsupported (sotbox needs no fixed paddr)\n");
    return -1;
}

static void arena_utspace_free(void *data, seL4_Word type, seL4_Word size_bits,
                               seL4_Word target)
{
    (void)data; (void)type; (void)size_bits; (void)target;   /* no-op · revoke reclaims */
}

static uintptr_t arena_utspace_paddr(void *data, seL4_Word target, seL4_Word type,
                                     seL4_Word size_bits)
{
    (void)data; (void)target; (void)type; (void)size_bits;
    return 0;   /* unsupported · sotbox objects don't query paddr */
}

static void arena_vka_init(sotbox_arena_t *a)
{
    a->vka.data                       = a;
    a->vka.cspace_alloc               = arena_cspace_alloc;
    a->vka.cspace_make_path           = arena_cspace_make_path;
    a->vka.cspace_free                = arena_cspace_free;
    a->vka.utspace_alloc              = arena_utspace_alloc;
    a->vka.utspace_alloc_maybe_device = arena_utspace_alloc_maybe_device;
    a->vka.utspace_alloc_at           = arena_utspace_alloc_at;
    a->vka.utspace_free               = arena_utspace_free;
    a->vka.utspace_paddr              = arena_utspace_paddr;
}

/* --- pool management --- */

void sotbox_arena_pool_add(seL4_CPtr ut, size_t ut_size_bits, seL4_CPtr cslot_base)
{
    if (g_arena_count >= SOTBOX_ARENA_MAX) return;
    sotbox_arena_t *a = &g_arenas[g_arena_count++];
    memset(a, 0, sizeof(*a));
    a->ut           = ut;
    a->ut_size_bits = ut_size_bits;
    a->cslot_base   = cslot_base;
    a->cslot_n      = SOTBOX_ARENA_CSLOTS;
    a->cslot_bump   = 0;
    a->in_use       = false;
    arena_vka_init(a);
    printf("[arena] pool+ ut=%lu szbits=%zu cslots=[%lu..%lu)\n",
           (unsigned long)ut, ut_size_bits,
           (unsigned long)cslot_base, (unsigned long)(cslot_base + SOTBOX_ARENA_CSLOTS));
}

sotbox_arena_t *sotbox_arena_acquire(void)
{
    for (int i = 0; i < g_arena_count; ++i) {
        if (!g_arenas[i].in_use) {
            g_arenas[i].in_use       = true;
            g_arenas[i].cslot_bump   = 0;
            g_arenas[i].cslot_free_n = 0;   /* fresh life · no reclaimed slots yet */
            g_arenas[i].frame_free_n = 0;   /* recycled frames belonged to the prior life */
            g_arenas[i].retyped_frames = 0; /* DIAG */
            g_arenas[i].reused_frames  = 0;
            return &g_arenas[i];
        }
    }
    printf("[arena] acquire FAILED · pool exhausted (%d arenas all in use)\n", g_arena_count);
    return NULL;
}

/* --- heavy arena · ONE large guest (CPython) at a time ---
 * Unlike regular arenas (bump over a bootstrap-reserved contiguous cslot
 * range), the heavy arena BORROWS cslots from orch's allocman ON DEMAND, so it
 * needs NO bootstrap reservation (which would permanently shrink orch's budget)
 * and NO CNode growth (a 4 MiB CNode breaks the root's untyped delegation). The
 * borrowed slots are tracked in g_heavy_alloc[] and returned to the allocman at
 * revoke; the 64 MiB untyped is allocman-allocated + freed too. orch keeps its
 * full cslot budget except transiently while python runs (never concurrent with
 * the demo). */
#include <vka/object.h>

/* WINE-M1 · heavy arena POOL.  Wine's wineboot bootstrap is MULTI-PROCESS: the
 * launcher → wineboot → services.exe (the SCM) → its children (rpcss, plugplay…)
 * each fully load ntdll+kernel32+kernelbase and so each needs a heavy arena.  A
 * single heavy box (the old g_heavy) meant only the FIRST deep wine process got
 * heavy; the rest fell back to a regular 8192-cslot arena and ran OUT loading
 * ntdll ("cspace exhausted 8192/8192" → STATUS_NO_MEMORY → services.exe exit 1 →
 * wineboot "error 1359").  A small pool lets the concurrent deep wine processes
 * coexist.  Each box = 128 MiB untyped; the pool tops out at 4 (512 MiB, well
 * inside the ~1.9 GiB delegated to orch).  The borrowed-cslot bookkeeping is now
 * PER-box, indexed by the arena's position in g_heavy[] (the vka callbacks
 * recover the index from their `data` = &g_heavy[i]). */
#define SOTBOX_HEAVY_POOL 4

static sotbox_arena_t g_heavy[SOTBOX_HEAVY_POOL];
static vka_object_t   g_heavy_ut[SOTBOX_HEAVY_POOL];                    /* on-demand 128 MiB untyped per box */
static seL4_CPtr      g_heavy_alloc[SOTBOX_HEAVY_POOL][SOTBOX_HEAVY_CSLOTS]; /* live borrowed allocman cslots */
static int            g_heavy_nalloc[SOTBOX_HEAVY_POOL];

/* Recover the pool index from a heavy arena pointer (vka `data` = &g_heavy[i]). */
static int heavy_idx(const void *data)
{
    long i = (const sotbox_arena_t *)data - g_heavy;
    return (i >= 0 && i < SOTBOX_HEAVY_POOL) ? (int)i : 0;
}

static int heavy_cspace_alloc(void *data, seL4_CPtr *res)
{
    int idx = heavy_idx(data);
    int e = vka_cspace_alloc(orch_vka(), res);
    if (e) {
        printf("[arena] heavy cspace_alloc failed err=%d (allocman cslots exhausted)\n", e);
        return -1;
    }
    if (g_heavy_nalloc[idx] < SOTBOX_HEAVY_CSLOTS) g_heavy_alloc[idx][g_heavy_nalloc[idx]++] = *res;
    return 0;
}

static void heavy_cspace_free(void *data, seL4_CPtr slot)
{
    int idx = heavy_idx(data);
    cspacepath_t cp;
    vka_cspace_make_path(orch_vka(), slot, &cp);
    seL4_CNode_Delete(cp.root, cp.capPtr, cp.capDepth);
    vka_cspace_free(orch_vka(), slot);          /* return the borrowed slot to the allocman */
    for (int i = 0; i < g_heavy_nalloc[idx]; ++i) {  /* drop from the live list (swap-with-last) */
        if (g_heavy_alloc[idx][i] == slot) { g_heavy_alloc[idx][i] = g_heavy_alloc[idx][--g_heavy_nalloc[idx]]; break; }
    }
}

static void heavy_vka_init(sotbox_arena_t *a)
{
    a->vka.data                       = a;
    a->vka.cspace_alloc               = heavy_cspace_alloc;
    a->vka.cspace_make_path           = arena_cspace_make_path;   /* shared · orch CNode */
    a->vka.cspace_free                = heavy_cspace_free;
    a->vka.utspace_alloc              = arena_utspace_alloc;       /* retype from a->ut */
    a->vka.utspace_alloc_maybe_device = arena_utspace_alloc_maybe_device;
    a->vka.utspace_alloc_at           = arena_utspace_alloc_at;
    a->vka.utspace_free               = arena_utspace_free;
    a->vka.utspace_paddr              = arena_utspace_paddr;
}

sotbox_arena_t *sotbox_heavy_acquire(void)
{
    for (int i = 0; i < SOTBOX_HEAVY_POOL; ++i) {
        if (g_heavy[i].in_use) continue;
        /* Prefer a full 128 MiB untyped (the GTK/wine consumers genuinely need
         * it).  Under memory pressure — e.g. a third heavy box already carved
         * out, leaving no contiguous 128 MiB region — fall back to a smaller
         * untyped (64 MiB · 16384 cslots, still 2× a regular arena) so a
         * mid-weight consumer like apt's gpgv method (which overflows the 8192-
         * cslot regular arena loading its libgcrypt closure) still gets a
         * workable arena instead of OOMing the regular fallback.  Floor at
         * 64 MiB: below that there is no win over the regular arena. */
        uint8_t bits = 0;
        int e = -1;
        for (uint8_t b = SOTBOX_HEAVY_MIN_BITS; b >= 26; --b) {
            e = vka_alloc_untyped(orch_vka(), b, &g_heavy_ut[i]);
            if (!e) { bits = b; break; }
        }
        if (e) {
            printf("[arena] heavy acquire FAILED · vka_alloc_untyped(128..64MiB) err=%d (pool slot %d)\n", e, i);
            return NULL;
        }
        memset(&g_heavy[i], 0, sizeof(g_heavy[i]));
        g_heavy[i].ut           = g_heavy_ut[i].cptr;
        g_heavy[i].ut_size_bits = bits;
        g_heavy[i].in_use       = true;
        g_heavy[i].is_heavy     = true;
        g_heavy_nalloc[i]       = 0;
        heavy_vka_init(&g_heavy[i]);
        printf("[arena] heavy acquire · pool slot %d/%d · ut=%lu (%u MiB) · cslots borrowed on-demand\n",
               i, SOTBOX_HEAVY_POOL, (unsigned long)g_heavy[i].ut, 1u << (bits - 20));
        return &g_heavy[i];
    }
    printf("[arena] heavy acquire FAILED · all %d heavy boxes in use\n", SOTBOX_HEAVY_POOL);
    return NULL;
}

void sotbox_arena_revoke(sotbox_arena_t *a)
{
    if (!a) return;
    cspacepath_t p;
    vka_cspace_make_path(orch_vka(), a->ut, &p);
    int e = seL4_CNode_Revoke(p.root, p.capPtr, p.capDepth);   /* delete untyped children + reset freeIndex */
    if (e != seL4_NoError) {
        printf("[arena] FATAL revoke ut=%lu FAILED err=%d · arena NOT returned to pool\n",
               (unsigned long)a->ut, e);
        return;   /* leave in_use=true so the corrupt arena is never re-acquired */
    }
    /* Heavy arena · its cslots are BORROWED allocman slots (not a contiguous
     * reserved range), tracked in g_heavy_alloc[]. The Revoke above already
     * deleted the frame/object caps; return each borrowed slot + the 64 MiB
     * untyped to the allocman. */
    if (a->is_heavy) {
        int idx = heavy_idx(a);
        for (int i = 0; i < g_heavy_nalloc[idx]; ++i)
            vka_cspace_free(orch_vka(), g_heavy_alloc[idx][i]);
        int freed = g_heavy_nalloc[idx];
        g_heavy_nalloc[idx] = 0;
        a->in_use = false;
        vka_free_object(orch_vka(), &g_heavy_ut[idx]);   /* return the 128 MiB to the allocman */
        printf("[arena] heavy revoke · pool slot %d · ut=%lu · freed %d borrowed cslots + 128 MiB ut "
               "· DIAG peak retyped=%u (=%uMiB) reused=%u\n",
               idx, (unsigned long)a->ut, freed,
               a->retyped_frames, (a->retyped_frames * 4u) / 1024u, a->reused_frames);
        return;
    }
    /* P2b · SWEEP the cslot range: delete any FOREIGN cap left behind — caps that are
     * NOT children of this untyped and so survive the Revoke: the badged-EP mint
     * (client_setup), parked kernel reply caps, and a fork child's shared-TEXT cap-copies
     * (share_region_ro). seL4_CNode_Delete on an already-empty (revoked) slot is a harmless
     * no-op. This makes revoke uniformly correct for primary + forked sotboxes. */
    seL4_Word n = a->cslot_bump;
    for (seL4_Word i = 0; i < n; ++i) {
        cspacepath_t cp;
        vka_cspace_make_path(orch_vka(), a->cslot_base + i, &cp);
        seL4_CNode_Delete(cp.root, cp.capPtr, cp.capDepth);
    }
    a->cslot_bump   = 0;
    a->cslot_free_n = 0;   /* drop reclaimed-slot list · whole range is fresh post-revoke */
    a->frame_free_n = 0;   /* recycled frame caps are gone with the revoke */
    a->in_use       = false;
    printf("[arena] revoke ut=%lu · reclaimed (+swept %lu cslots) · DIAG peak retyped=%u (=%uMiB) reused=%u\n",
           (unsigned long)a->ut, (unsigned long)n,
           a->retyped_frames, (a->retyped_frames * 4u) / 1024u, a->reused_frames);
    a->retyped_frames = 0;
    a->reused_frames  = 0;
}

int sotbox_arena_pool_count_free(void)
{
    int n = 0;
    for (int i = 0; i < g_arena_count; ++i) if (!g_arenas[i].in_use) ++n;
    return n;
}

/* Recover the sotbox_arena_t a vka belongs to (data points to one of ours), or
 * NULL if vka is not an arena vka.  Validated by pointer-range so a stray vka
 * never gets its ->data mis-cast. */
static sotbox_arena_t *arena_from_vka(vka_t *vka)
{
    if (!vka || !vka->data) return NULL;
    sotbox_arena_t *a = (sotbox_arena_t *)vka->data;
    if (a >= &g_arenas[0] && a < &g_arenas[SOTBOX_ARENA_MAX]) return a;
    if (a >= &g_heavy[0]  && a < &g_heavy[SOTBOX_HEAVY_POOL]) return a;
    return NULL;
}

/* The arena reclaim entry point · munmap (handlers_mem.c) hands back a 4 KiB frame
 * cap it has UNMAPPED + ZEROED.  Push it onto the arena's frame free-list for
 * arena_utspace_alloc to reuse.  Returns 1 if recycled, 0 if not (no arena resolved,
 * or the free-list is full → the caller must NOT have unmapped/lost the frame).
 * Serves BOTH heavy AND regular ("light") arenas: arena_from_vka resolves g_arenas[]
 * and g_heavy[] alike and the free-list is arena-generic, so regular boxes (busybox
 * `ls`, the canary shell) recycle their churned frames instead of leaking them to the
 * 8192-cslot ceiling.  The reclaim's safety is the CALLER's address-range clamp (the
 * private anon window only · handlers_mem.c), NOT the arena class — heavy-gating was a
 * conservative blast-radius choice, never a correctness requirement. */
int sotbox_arena_recycle_frame(vka_t *vka, seL4_CPtr frame_cap)
{
    sotbox_arena_t *a = arena_from_vka(vka);
    if (!a) return 0;
    if (a->frame_free_n >= (int)(sizeof(a->frame_free) / sizeof(a->frame_free[0]))) return 0;
    a->frame_free[a->frame_free_n++] = frame_cap;
    return 1;
}

/* Is this vka a heavy arena? · fork (fork.c) checks parent-is-heavy to route a heavy
 * guest's fork children into the heavy pool too (e.g. apt's transport method, whose
 * lib closure would exhaust a regular arena).  It NO LONGER gates the munmap reclaim
 * — that now serves all arenas, bounded by the caller's address-range clamp. */
int sotbox_arena_vka_is_heavy(vka_t *vka)
{
    sotbox_arena_t *a = arena_from_vka(vka);
    return (a && a->is_heavy) ? 1 : 0;
}
