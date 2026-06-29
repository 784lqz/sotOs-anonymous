/* sotOs · orch · Wayland L13 shared-memory pixel pool.
 *
 * A single seL4 Page (frame) capability can be mapped into AT MOST ONE
 * address space.  To share one physical frame between two vspaces (the guest
 * client and the compositor) we allocate a SECOND, read-only capability to the
 * same frame (vka_cspace_alloc_path + vka_cnode_copy with seL4_CanRead) and map
 * that copy into the second space.  Both caps back the same physical frame, so
 * the compositor sees the client's pixels with zero copies.
 *
 * Originals  → guest vspace, read-write (the client draws here).
 * RO copies  → compositor PD, read-only  (the compositor scans-out from here).
 *
 * Precedents matched exactly: src/root/procd_shm_map.c (cap-copy + two-PD map),
 * src/orch/fork.c (cap-copy before vspace_map_pages_at_vaddr into a child),
 * src/orch/spawn.c:orch_parent_new_pages (vka_alloc_frame + sel4utils_map_page).
 */
#include "shm_pool.h"
#include <stdio.h>
#include <string.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>          /* vka_cnode_copy */
#include <sel4utils/mapping.h>
#include <sel4utils/vspace.h>

extern vka_t *orch_vka(void);
#define PAGE_4K 4096u
#define SHM_BUF_WIRE_MAX 8   /* live wl_buffers tracked per pool (M4 refcount) */

/* M4 · pool lifetime/refcount.  A pool's backing (frames + RO copies + the two
 * mappings) must outlive every reference to it.  References, counted in
 * `refcount`, are WAYLAND-PROTOCOL refs only: the wl_shm_pool object (alloc→
 * pool.destroy) and each wl_buffer (create_buffer→buffer.destroy).  These arrive
 * as forwarded wire requests, so libwayland's flush orders them correctly.  The
 * memfd fd is NOT counted — close() is an immediate syscall that races ahead of
 * the BUFFERED wl_buffer.destroy, so it can't gate the free.  refcount starts at
 * 1 at alloc (the pending pool object, released by pool.destroy).  At 0 freed:
 * guest unmap + reservation, compositor unmap, frames + copy caps.  A sotbox
 * exit force-frees its still-referenced pools (orch_shm_pool_free_owner). */
struct shm_pool {
    int          used;
    int          refcount;
    uint32_t     owner;            /* synthetic_pid of the client sotbox */
    size_t       size, nframes;
    vka_object_t frames[ORCH_SHM_MAX_FRAMES];   /* originals (RW → guest) */
    seL4_CPtr    copies[ORCH_SHM_MAX_FRAMES];    /* RO copies (→ compositor) */
    /* mapping state for clean teardown */
    vspace_t    *gvs; uintptr_t gbase; reservation_t gres; int gmapped;
    seL4_CPtr    cpd; uintptr_t cbase; int cmapped;
    /* wl wire-object ids for refcount events.  Wire ids are per-CONNECTION, so a
     * sotbox with >1 wayland fd would collide on (owner) alone → events keyed on
     * (owner, conn_fd) to disambiguate (a hostile guest could open 2 conns). */
    uint32_t     owner_has_conn;                 /* 1 once attached (conn_fd valid) */
    uint64_t     conn_fd;                        /* the wayland socket fd that owns it */
    uint32_t     pool_wire_id;                   /* wl_shm_pool object id (0 = none) */
    uint32_t     buf_wire_ids[SHM_BUF_WIRE_MAX]; /* live wl_buffer ids */
};
static struct shm_pool g_pools[ORCH_SHM_MAX_POOLS];

static void orch_shm_pool_free(int id);   /* fwd */

/* Delete + free the first `n` RO copy caps made so far (alloc error paths).
 * At alloc time the copies exist but are NOT yet mapped (map_compositor runs
 * later), so a plain cnode_delete + cspace_free reclaims them — no unmap. */
static void shm_free_copies(vka_t *vka, struct shm_pool *p, size_t n)
{
    for (size_t j = 0; j < n; ++j) {
        if (!p->copies[j]) continue;
        cspacepath_t cp;
        vka_cspace_make_path(vka, p->copies[j], &cp);
        vka_cnode_delete(&cp);
        vka_cspace_free_path(vka, cp);
        p->copies[j] = 0;
    }
}

int orch_shm_pool_alloc(size_t size, uint32_t owner)
{
    if (size == 0) return -1;
    size_t nframes = (size + PAGE_4K - 1) / PAGE_4K;
    if (nframes > ORCH_SHM_MAX_FRAMES) {
        printf("[orch-shm] %zu B (%zu frames) > cap %u\n", size, nframes, ORCH_SHM_MAX_FRAMES);
        return -1;
    }
    int id = -1;
    for (int i = 0; i < ORCH_SHM_MAX_POOLS; ++i) if (!g_pools[i].used) { id = i; break; }
    if (id < 0) { printf("[orch-shm] no free pool slot\n"); return -1; }

    vka_t *vka = orch_vka();
    struct shm_pool *p = &g_pools[id];
    memset(p, 0, sizeof(*p));
    for (size_t i = 0; i < nframes; ++i) {
        if (vka_alloc_frame(vka, seL4_PageBits, &p->frames[i])) {
            printf("[orch-shm] vka_alloc_frame %zu failed\n", i);
            shm_free_copies(vka, p, i);   /* copies[0..i) made so far */
            for (size_t j = 0; j < i; ++j) vka_free_object(vka, &p->frames[j]);
            return -1;
        }
        cspacepath_t src, dst;
        vka_cspace_make_path(vka, p->frames[i].cptr, &src);
        if (vka_cspace_alloc_path(vka, &dst)) {
            printf("[orch-shm] cspace_alloc %zu failed\n", i);
            shm_free_copies(vka, p, i);   /* copies[0..i) */
            for (size_t j = 0; j <= i; ++j) vka_free_object(vka, &p->frames[j]);
            return -1;
        }
        if (vka_cnode_copy(&dst, &src, seL4_CanRead)) {
            printf("[orch-shm] cnode_copy %zu failed\n", i);
            vka_cspace_free_path(vka, dst);
            shm_free_copies(vka, p, i);   /* copies[0..i) */
            for (size_t j = 0; j <= i; ++j) vka_free_object(vka, &p->frames[j]);
            return -1;
        }
        p->copies[i] = dst.capPtr;
    }
    p->used = 1; p->size = size; p->nframes = nframes;
    p->refcount = 1;          /* the pending pool object (released by pool.destroy) */
    p->owner = owner;
    printf("[orch-shm] pool id=%d size=%zu frames=%zu owner=%u (orig+RO copy each, rc=1)\n",
           id, size, nframes, owner);
    return id;
}

/* Free frames + RO copies for indices [from,to) (a failed/partial grow range). */
static void shm_free_range(vka_t *vka, struct shm_pool *p, size_t from, size_t to)
{
    for (size_t i = from; i < to; ++i) {
        if (p->copies[i]) {
            cspacepath_t cp; vka_cspace_make_path(vka, p->copies[i], &cp);
            vka_cnode_delete(&cp); vka_cspace_free_path(vka, cp); p->copies[i] = 0;
        }
        vka_free_object(vka, &p->frames[i]);
    }
}

/* Alloc frame + RO copy for each index in [from,to).  On any failure, frees the
 * range it allocated and returns -1 (mirrors the orch_shm_pool_alloc loop). */
static int shm_alloc_range(vka_t *vka, struct shm_pool *p, size_t from, size_t to)
{
    for (size_t i = from; i < to; ++i) {
        if (vka_alloc_frame(vka, seL4_PageBits, &p->frames[i])) {
            shm_free_range(vka, p, from, i); return -1;
        }
        cspacepath_t src, dst;
        vka_cspace_make_path(vka, p->frames[i].cptr, &src);
        if (vka_cspace_alloc_path(vka, &dst)) {
            vka_free_object(vka, &p->frames[i]); shm_free_range(vka, p, from, i); return -1;
        }
        if (vka_cnode_copy(&dst, &src, seL4_CanRead)) {
            vka_cspace_free_path(vka, dst); vka_free_object(vka, &p->frames[i]);
            shm_free_range(vka, p, from, i); return -1;
        }
        p->copies[i] = dst.capPtr;
    }
    return 0;
}

/* Grow a pool to cover new_size bytes (alloc the extra frames + extend any live
 * mappings).  No-op if it already fits.  A client re-sizes its memfd
 * (libwayland-cursor grows the shared cursor pool per image; a toolkit may
 * ftruncate its framebuffer larger) → the pool must follow or the guest faults
 * past the mapping.  The guest reservation is sized to the actual frames (so
 * teardown is clean + the slot is reusable); since sel4utils can't grow a
 * reservation, an already-mapped pool is RE-reserved at the SAME base and
 * remapped — the base is unchanged (guest pointers stay valid) and the frames'
 * physical memory persists across unmap+remap (the guest is blocked in the
 * syscall, so there is no concurrent access).  Returns 0 on success/no-op, -1 on
 * failure (frames added in this call are rolled back). */
int orch_shm_pool_grow(int id, size_t new_size)
{
    if (id < 0 || id >= ORCH_SHM_MAX_POOLS || !g_pools[id].used) return -1;
    struct shm_pool *p = &g_pools[id];
    size_t need = (new_size + PAGE_4K - 1) / PAGE_4K;
    if (need <= p->nframes) { if (new_size > p->size) p->size = new_size; return 0; }
    if (need > ORCH_SHM_MAX_FRAMES) {
        printf("[orch-shm] grow id=%d %zu B (%zu frames) > cap %u\n", id, new_size, need, ORCH_SHM_MAX_FRAMES);
        return -1;
    }
    vka_t *vka = orch_vka();
    size_t old = p->nframes;
    if (shm_alloc_range(vka, p, old, need)) {
        printf("[orch-shm] grow id=%d alloc %zu->%zu failed\n", id, old, need);
        return -1;
    }
    /* extend the live GUEST mapping: re-reserve a bigger window at the SAME base. */
    if (p->gmapped && p->gvs) {
        vspace_unmap_pages(p->gvs, (void *)p->gbase, old, seL4_PageBits, NULL);
        vspace_free_reservation(p->gvs, p->gres);
        reservation_t r = vspace_reserve_range_at(p->gvs, (void *)p->gbase, need * PAGE_4K,
                                                  seL4_AllRights, 1);
        if (!r.res) { printf("[orch-shm] grow re-reserve @0x%lx failed\n", p->gbase);
                      shm_free_range(vka, p, old, need); p->gmapped = 0; return -1; }
        seL4_CPtr caps[ORCH_SHM_MAX_FRAMES];
        for (size_t i = 0; i < need; ++i) caps[i] = p->frames[i].cptr;
        int err = vspace_map_pages_at_vaddr(p->gvs, caps, NULL, (void *)p->gbase, need, seL4_PageBits, r);
        if (err) { printf("[orch-shm] grow remap @0x%lx err=%d\n", p->gbase, err);
                   vspace_free_reservation(p->gvs, r); shm_free_range(vka, p, old, need); p->gmapped = 0; return -1; }
        p->gres = r;
    }
    /* extend the live COMPOSITOR mapping (raw per-page · no reservation): the old
     * RO copies stay mapped, so just map the new ones after them. */
    if (p->cmapped && p->cpd) {
        for (size_t i = old; i < need; ++i) {
            vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int npaging = VSPACE_MAP_PAGING_OBJECTS;
            sel4utils_map_page(vka, p->cpd, p->copies[i], (void *)(p->cbase + i * PAGE_4K),
                               seL4_CanRead, 1, paging, &npaging);
        }
    }
    p->nframes = need; p->size = new_size;
    printf("[orch-shm] pool id=%d grew %zu->%zu frames (%zu B)\n", id, old, need, new_size);
    return 0;
}

uintptr_t orch_shm_pool_map_guest(int id, vspace_t *gv, uintptr_t base, size_t want_size)
{
    if (id < 0 || id >= ORCH_SHM_MAX_POOLS || !g_pools[id].used || !gv) return 0;
    struct shm_pool *p = &g_pools[id];
    /* The guest's mmap length is the source of truth: grow the pool to cover it
     * (libwayland-cursor mmaps the cursor pool larger than its first fallocate). */
    size_t need = (want_size + PAGE_4K - 1) / PAGE_4K;
    if (need > p->nframes && orch_shm_pool_grow(id, want_size)) return 0;
    /* Idempotent re-map: a client may mmap the SAME pool more than once (munmap is
     * a no-op so the mapping stays live).  grow() above already extended it, so
     * return the existing window instead of re-reserving an occupied vaddr (which
     * floods "guest reserve failed" and makes cursor images fail to load). */
    if (p->gmapped && p->gvs == gv) return p->gbase;
    /* Stride each pool to its own guest window (mirrors map_compositor) so a
     * client with >1 live pool never re-reserves an occupied guest vaddr.  The
     * reservation is sized to the actual frames so teardown frees it cleanly and
     * the strided slot is reusable by a later pool; a grow re-reserves bigger. */
    base += (uintptr_t)id * ORCH_SHM_MAX_FRAMES * PAGE_4K;
    reservation_t r = vspace_reserve_range_at(gv, (void *)base, p->nframes * PAGE_4K,
                                              seL4_AllRights, 1);
    if (!r.res) { printf("[orch-shm] guest reserve @0x%lx failed\n", base); return 0; }
    seL4_CPtr caps[ORCH_SHM_MAX_FRAMES];
    for (size_t i = 0; i < p->nframes; ++i) caps[i] = p->frames[i].cptr;
    int err = vspace_map_pages_at_vaddr(gv, caps, NULL, (void *)base, p->nframes, seL4_PageBits, r);
    if (err) { printf("[orch-shm] guest map @0x%lx err=%d\n", base, err); vspace_free_reservation(gv, r); return 0; }
    p->gvs = gv; p->gbase = base; p->gres = r; p->gmapped = 1;   /* M4 · for clean free */
    return base;
}

uintptr_t orch_shm_pool_map_compositor(int id, seL4_CPtr comp_pd, uintptr_t base)
{
    if (id < 0 || id >= ORCH_SHM_MAX_POOLS || !g_pools[id].used || comp_pd == 0) return 0;
    struct shm_pool *p = &g_pools[id];
    vka_t *vka = orch_vka();
    /* Stride each pool to its own window so a 2nd create_pool (multi-pool client)
     * never re-maps an occupied compositor vaddr. base is the caller's window
     * start; each pool id gets ORCH_SHM_MAX_FRAMES*4K. Returns the strided vaddr. */
    uintptr_t eff_base = base + (uintptr_t)id * ORCH_SHM_MAX_FRAMES * PAGE_4K;
    base = eff_base;
    for (size_t i = 0; i < p->nframes; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS]; int npaging = VSPACE_MAP_PAGING_OBJECTS;
        int err = sel4utils_map_page(vka, comp_pd, p->copies[i], (void *)(base + i*PAGE_4K),
                                     seL4_CanRead, 1, paging, &npaging);
        if (err) { printf("[orch-shm] comp map frame=%zu @0x%lx err=%d\n", i, base+i*PAGE_4K, err); return 0; }
    }
    p->cpd = comp_pd; p->cbase = base; p->cmapped = 1;   /* M4 · for clean free */
    return base;
}

size_t orch_shm_pool_size(int id){ return (id>=0&&id<ORCH_SHM_MAX_POOLS&&g_pools[id].used)?g_pools[id].size:0; }
size_t orch_shm_pool_nframes(int id){ return (id>=0&&id<ORCH_SHM_MAX_POOLS&&g_pools[id].used)?g_pools[id].nframes:0; }

/* M4 · release ALL of a pool's backing: guest unmap + reservation, compositor
 * unmap, original frames, RO copy caps.  Called only when refcount hits 0 (or
 * forced at owner teardown).  Idempotent via the `used` guard. */
static void orch_shm_pool_free(int id)
{
    if (id < 0 || id >= ORCH_SHM_MAX_POOLS || !g_pools[id].used) return;
    struct shm_pool *p = &g_pools[id];
    vka_t *vka = orch_vka();
    /* 1) guest: unmap the RW originals (NULL vka = unmap only, don't free the
     *    frame objects — we free them below) + drop the reservation. */
    if (p->gmapped && p->gvs) {
        vspace_unmap_pages(p->gvs, (void *)p->gbase, p->nframes, seL4_PageBits, NULL);
        vspace_free_reservation(p->gvs, p->gres);
    }
    /* 2) compositor: unmap the RO copies (raw sel4utils_map_page mappings), then
     *    delete the copy caps + free their cslots. */
    for (size_t i = 0; i < p->nframes; ++i) {
        if (!p->copies[i]) continue;
        if (p->cmapped) seL4_X86_Page_Unmap(p->copies[i]);
        cspacepath_t cp;
        vka_cspace_make_path(vka, p->copies[i], &cp);
        vka_cnode_delete(&cp);
        vka_cspace_free_path(vka, cp);
        p->copies[i] = 0;
    }
    /* 3) free the original frame objects (already unmapped from the guest). */
    for (size_t i = 0; i < p->nframes; ++i) vka_free_object(vka, &p->frames[i]);
    printf("[orch-shm] pool id=%d freed (owner=%u nframes=%zu)\n",
           id, p->owner, p->nframes);
    memset(p, 0, sizeof(*p));   /* used = 0 */
}

static void shm_unref(int id, const char *why)
{
    if (id < 0 || id >= ORCH_SHM_MAX_POOLS || !g_pools[id].used) return;
    struct shm_pool *p = &g_pools[id];
    if (p->refcount > 0) p->refcount--;
    if (p->refcount <= 0) orch_shm_pool_free(id);
}

/* create_pool seen: bind the wl_shm_pool wire id to this pool.  No refcount
 * change — alloc's rc=1 already represents the pool object (released by
 * pool.destroy); this just records the wire id for the destroy/create_buffer
 * events that follow. */
void orch_shm_pool_attach(int id, uint32_t owner, uint64_t conn_fd, uint32_t pool_wire_id)
{
    if (id < 0 || id >= ORCH_SHM_MAX_POOLS || !g_pools[id].used) return;
    struct shm_pool *p = &g_pools[id];
    p->owner = owner;
    p->conn_fd = conn_fd;
    p->owner_has_conn = 1;
    p->pool_wire_id = pool_wire_id;
}

/* Force-free every pool owned by a sotbox that is being torn down (its objects
 * may still be "live" — exit-with-live-objects).  Run while the guest vspace is
 * still valid (early in sotbox_destroy). */
void orch_shm_pool_free_owner(uint32_t owner)
{
    for (int i = 0; i < ORCH_SHM_MAX_POOLS; ++i)
        if (g_pools[i].used && g_pools[i].owner == owner) {
            printf("[orch-shm] pool id=%d force-free on owner=%u teardown (rc=%d)\n",
                   i, owner, g_pools[i].refcount);
            orch_shm_pool_free(i);
        }
}

/* Observe a forwarded wl request and maintain the buffer/pool refcount.
 * Matches ONLY tracked wire-ids keyed by (owner, conn_fd) — wire ids are
 * per-connection, so a sotbox with >1 wayland fd can't cross-collide (and
 * wl_surface/xdg ids never match a tracked pool/buffer id within a connection).
 * obj=request target, opcode, new_id=arg0 (for create_buffer). */
void orch_shm_pool_wire_event(uint32_t owner, uint64_t conn_fd, uint32_t obj, uint32_t opcode, uint32_t new_id)
{
    if (obj == 0) return;
    for (int i = 0; i < ORCH_SHM_MAX_POOLS; ++i) {
        struct shm_pool *p = &g_pools[i];
        if (!p->used || !p->owner_has_conn || p->owner != owner || p->conn_fd != conn_fd) continue;
        if (p->pool_wire_id && p->pool_wire_id == obj) {
            if (opcode == 0) {            /* wl_shm_pool.create_buffer(new_id,...) */
                int stored = 0;
                for (int b = 0; b < SHM_BUF_WIRE_MAX; ++b)
                    if (p->buf_wire_ids[b] == 0) { p->buf_wire_ids[b] = new_id; stored = 1; break; }
                /* Only count a ref we can later DROP — if the tracking table is
                 * full the buffer is untracked, so counting it would pin the pool
                 * until teardown (its destroy can't find the id to decrement). */
                if (stored) p->refcount++;   /* ref B */
                else printf("[orch-shm] pool id=%d buf table full · buffer %u untracked\n", i, new_id);
            } else if (opcode == 1) {     /* wl_shm_pool.destroy */
                p->pool_wire_id = 0;
                shm_unref(i, "pool.destroy");   /* drop ref C (may free) */
            }
            return;
        }
        for (int b = 0; b < SHM_BUF_WIRE_MAX; ++b) {
            if (p->buf_wire_ids[b] && p->buf_wire_ids[b] == obj) {
                if (opcode == 0) {        /* wl_buffer.destroy */
                    p->buf_wire_ids[b] = 0;
                    shm_unref(i, "buffer.destroy");   /* drop ref B (may free) */
                }
                return;
            }
        }
    }
}
