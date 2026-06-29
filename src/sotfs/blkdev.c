/* sotfs_blkdev · disk-backed block store over a sotfs_storage_t.
 *
 * Layout within the region (all 4 KiB aligned):
 *   [ block 0      ] superblock (magic/version/total_blocks/bitmap_bytes)
 *   [ bitmap_off.. ] free bitmap, round_up(bitmap_bytes,4096) long
 *   [ heap_off..   ] g_total_blocks data blocks, id 1..g_total_blocks
 *
 * Pure host-testable: depends only on <string.h>/<stdint.h> + the storage
 * vtable.  No seL4.  Allocation is lowest-clear-bit (1-based ids); reads/writes
 * go through a fixed-size LRU RAM buffer cache with write-back on eviction/flush.
 */
#include <stdint.h>
#include <string.h>
#include "sotfs/blkdev.h"

/* Max region we support: 256 MiB / 4096 = 64 K blocks = 64 K bits = 8 KiB of
 * bitmap.  Declare 16 KiB to be safe. */
#define BLKDEV_BITMAP_MAX 16384u

static sotfs_storage_t g_st;
static uint64_t g_region_off;
static uint64_t g_total_blocks;
static uint64_t g_bitmap_off;
static uint64_t g_bitmap_bytes;     /* logical (#blocks/8, rounded up) */
static uint64_t g_heap_off;
static uint64_t g_used;
static int      g_bitmap_dirty;

static uint8_t  g_bitmap[BLKDEV_BITMAP_MAX];

typedef struct {
    int      id;        /* 0 == empty slot */
    int      dirty;
    uint64_t lru;
    uint8_t  data[SOTFS_BLKDEV_BLOCK_SIZE];
} cache_slot_t;

static cache_slot_t g_cache[SOTFS_BLKDEV_CACHE_SLOTS];
static uint64_t     g_lru_tick;

/* ---- backend helpers ---------------------------------------------------- */

static int st_write(uint64_t off, const void *buf, size_t len) {
    int r = g_st.ops->write_block(g_st.backend_state, off, buf, len);
    return (r == (int)len) ? 0 : (r < 0 ? r : -5);
}
static int st_read(uint64_t off, void *buf, size_t len) {
    int r = g_st.ops->read_block(g_st.backend_state, off, buf, len);
    return (r == (int)len) ? 0 : (r < 0 ? r : -5);
}

static uint64_t round_up_4k(uint64_t v) {
    return (v + (SOTFS_BLKDEV_BLOCK_SIZE - 1)) & ~(uint64_t)(SOTFS_BLKDEV_BLOCK_SIZE - 1);
}

/* ---- superblock --------------------------------------------------------- */

struct sb {
    uint32_t magic;
    uint32_t version;
    uint64_t total_blocks;
    uint64_t bitmap_bytes;
};

/* ---- geometry ----------------------------------------------------------- */

static void compute_geometry(uint64_t region_off, uint64_t region_bytes) {
    g_region_off  = region_off;
    g_bitmap_off  = region_off + SOTFS_BLKDEV_BLOCK_SIZE;   /* superblock is block 0 */

    /* First pass: assume the whole region (minus superblock+bitmap) is data,
     * then size the bitmap to cover those blocks.  Iterate once: the bitmap
     * shrinks the data area only marginally, so a single fixpoint pass with a
     * conservative estimate is exact for the rounded geometry. */
    uint64_t avail = (region_bytes > SOTFS_BLKDEV_BLOCK_SIZE)
                       ? region_bytes - SOTFS_BLKDEV_BLOCK_SIZE : 0;
    /* Solve blocks where: blocks*4096 + round_up(ceil(blocks/8),4096) <= avail */
    uint64_t blocks = avail / SOTFS_BLKDEV_BLOCK_SIZE;
    for (;;) {
        uint64_t bm = round_up_4k((blocks + 7) / 8);
        uint64_t need = blocks * SOTFS_BLKDEV_BLOCK_SIZE + bm;
        if (need <= avail || blocks == 0) {
            g_bitmap_bytes = (blocks + 7) / 8;
            g_total_blocks = blocks;
            g_heap_off     = g_bitmap_off + bm;
            break;
        }
        blocks--;
    }
    if (g_total_blocks > (uint64_t)BLKDEV_BITMAP_MAX * 8)
        g_total_blocks = (uint64_t)BLKDEV_BITMAP_MAX * 8;   /* clamp to RAM bitmap */
}

/* ---- bitmap ------------------------------------------------------------- */

static int bit_get(uint64_t i) { return (g_bitmap[i >> 3] >> (i & 7)) & 1; }
static void bit_set(uint64_t i) { g_bitmap[i >> 3] |= (uint8_t)(1u << (i & 7)); }
static void bit_clr(uint64_t i) { g_bitmap[i >> 3] &= (uint8_t)~(1u << (i & 7)); }

static uint64_t bitmap_popcount(void) {
    uint64_t n = 0;
    for (uint64_t i = 0; i < g_total_blocks; ++i) n += (uint64_t)bit_get(i);
    return n;
}

static int bitmap_flush(void) {
    uint64_t bm_phys = round_up_4k(g_bitmap_bytes);
    if (bm_phys == 0) bm_phys = SOTFS_BLKDEV_BLOCK_SIZE;
    if (bm_phys > BLKDEV_BITMAP_MAX) bm_phys = BLKDEV_BITMAP_MAX;
    int r = st_write(g_bitmap_off, g_bitmap, (size_t)bm_phys);
    if (r == 0) g_bitmap_dirty = 0;
    return r;
}

/* ---- cache -------------------------------------------------------------- */

static uint64_t block_off(int id) {
    return g_heap_off + (uint64_t)(id - 1) * SOTFS_BLKDEV_BLOCK_SIZE;
}

static int slot_writeback(cache_slot_t *s) {
    if (!s->dirty || s->id == 0) { s->dirty = 0; return 0; }
    int r = st_write(block_off(s->id), s->data, SOTFS_BLKDEV_BLOCK_SIZE);
    if (r == 0) s->dirty = 0;
    return r;
}

/* Find the slot caching `id`, or NULL. */
static cache_slot_t *cache_find(int id) {
    for (int i = 0; i < SOTFS_BLKDEV_CACHE_SLOTS; ++i)
        if (g_cache[i].id == id) return &g_cache[i];
    return NULL;
}

/* Acquire a slot for `id`: returns the existing slot if cached, else evicts the
 * LRU/empty slot (writing it back if dirty) and returns it without filling. */
static cache_slot_t *cache_acquire(int id, int *was_present) {
    cache_slot_t *hit = cache_find(id);
    if (hit) { *was_present = 1; return hit; }
    *was_present = 0;

    cache_slot_t *victim = &g_cache[0];
    for (int i = 0; i < SOTFS_BLKDEV_CACHE_SLOTS; ++i) {
        if (g_cache[i].id == 0) { victim = &g_cache[i]; break; }
        if (g_cache[i].lru < victim->lru) victim = &g_cache[i];
    }
    slot_writeback(victim);
    victim->id = id;
    victim->dirty = 0;
    return victim;
}

/* ---- public API --------------------------------------------------------- */

int sotfs_blkdev_init(sotfs_storage_t *storage, uint64_t region_off,
                      uint64_t region_bytes, int fresh) {
    if (!storage || !storage->ops) return -22;
    g_st = *storage;
    compute_geometry(region_off, region_bytes);
    if (g_total_blocks == 0) return -28;

    /* reset cache */
    memset(g_cache, 0, sizeof(g_cache));
    g_lru_tick = 0;
    g_bitmap_dirty = 0;

    uint64_t bm_phys = round_up_4k(g_bitmap_bytes);
    if (bm_phys == 0) bm_phys = SOTFS_BLKDEV_BLOCK_SIZE;
    if (bm_phys > BLKDEV_BITMAP_MAX) bm_phys = BLKDEV_BITMAP_MAX;

    /* Phase 1b · self-format-on-fresh: read the data superblock first; if its
     * magic is absent (a zeroed / brand-new region) force a format regardless
     * of the caller's hint.  A new image self-formats on first boot, an
     * existing one re-attaches.  (A valid magic but version/geometry mismatch
     * still rejects below — that's a genuinely incompatible region, not fresh.) */
    if (!fresh) {
        uint8_t probe[SOTFS_BLKDEV_BLOCK_SIZE];
        int pr = st_read(region_off, probe, sizeof(probe));
        if (pr == 0) {
            struct sb psb;
            memcpy(&psb, probe, sizeof(psb));
            if (psb.magic != SOTFS_BLKDEV_MAGIC)
                fresh = 1;   /* no valid superblock → self-format */
        } else {
            /* device unreadable here — fall through; the read below reports it */
        }
    }

    if (fresh) {
        memset(g_bitmap, 0, sizeof(g_bitmap));
        g_used = 0;
        struct sb sb;
        memset(&sb, 0, sizeof(sb));
        sb.magic = SOTFS_BLKDEV_MAGIC;
        sb.version = SOTFS_BLKDEV_VERSION;
        sb.total_blocks = g_total_blocks;
        sb.bitmap_bytes = g_bitmap_bytes;
        uint8_t sbblk[SOTFS_BLKDEV_BLOCK_SIZE];
        memset(sbblk, 0, sizeof(sbblk));
        memcpy(sbblk, &sb, sizeof(sb));
        int r = st_write(region_off, sbblk, sizeof(sbblk));
        if (r) return r;
        r = st_write(g_bitmap_off, g_bitmap, (size_t)bm_phys);
        if (r) return r;
        return 0;
    }

    /* read existing layout */
    uint8_t sbblk[SOTFS_BLKDEV_BLOCK_SIZE];
    int r = st_read(region_off, sbblk, sizeof(sbblk));
    if (r) return r;
    struct sb sb;
    memcpy(&sb, sbblk, sizeof(sb));
    if (sb.magic != SOTFS_BLKDEV_MAGIC || sb.version != SOTFS_BLKDEV_VERSION)
        return -22;
    /* trust persisted counts (geometry is deterministic from region size, but
     * a mismatch would indicate a different region — reject). */
    if (sb.total_blocks != g_total_blocks) return -22;

    memset(g_bitmap, 0, sizeof(g_bitmap));
    r = st_read(g_bitmap_off, g_bitmap, (size_t)bm_phys);
    if (r) return r;
    g_used = bitmap_popcount();
    return 0;
}

int sotfs_blk_alloc(void) {
    for (uint64_t i = 0; i < g_total_blocks; ++i) {
        if (!bit_get(i)) {
            bit_set(i);
            g_used++;
            g_bitmap_dirty = 1;
            return (int)(i + 1);   /* 1-based id */
        }
    }
    return 0;   /* ENOSPC */
}

void sotfs_blk_free(int blk) {
    if (blk <= 0 || (uint64_t)blk > g_total_blocks) return;
    uint64_t i = (uint64_t)blk - 1;
    if (!bit_get(i)) return;       /* already free */
    bit_clr(i);
    if (g_used) g_used--;
    g_bitmap_dirty = 1;
    /* drop any cached copy so a future alloc of the same id starts clean */
    cache_slot_t *s = cache_find(blk);
    if (s) { s->id = 0; s->dirty = 0; }
}

int sotfs_blk_read(int blk, void *buf) {
    if (blk <= 0 || (uint64_t)blk > g_total_blocks || !buf) return -22;
    int present;
    cache_slot_t *s = cache_acquire(blk, &present);
    if (!present) {
        int r = st_read(block_off(blk), s->data, SOTFS_BLKDEV_BLOCK_SIZE);
        if (r) { s->id = 0; return r; }
    }
    s->lru = ++g_lru_tick;
    memcpy(buf, s->data, SOTFS_BLKDEV_BLOCK_SIZE);
    return 0;
}

int sotfs_blk_write(int blk, const void *buf) {
    if (blk <= 0 || (uint64_t)blk > g_total_blocks || !buf) return -22;
    int present;
    cache_slot_t *s = cache_acquire(blk, &present);
    (void)present;   /* full-block overwrite: no need to read-before-write */
    memcpy(s->data, buf, SOTFS_BLKDEV_BLOCK_SIZE);
    s->dirty = 1;
    s->lru = ++g_lru_tick;
    return 0;
}

void sotfs_blk_flush(void) {
    for (int i = 0; i < SOTFS_BLKDEV_CACHE_SLOTS; ++i)
        slot_writeback(&g_cache[i]);
    if (g_bitmap_dirty) bitmap_flush();
    if (g_st.ops && g_st.ops->flush) g_st.ops->flush(g_st.backend_state);
}

uint64_t sotfs_blk_total(void) { return g_total_blocks; }
uint64_t sotfs_blk_used(void)  { return g_used; }
