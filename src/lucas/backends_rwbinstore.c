/*
 * sotOs · LUCAS · rwbinstore backend (A2) · WRITABLE on-disk binary store.
 * Mirrors backends_binstore.c (read path) + adds a write path. A fresh image
 * has no RWBN magic → empty store (count=0), so spawn_load_elf falls through
 * to the read-only binstore cleanly.
 */
#include <sotfs/rwbinstore.h>
#include <sotfs/layout.h>
#include <sotfs/storage_virtio_blk.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

static sotfs_rwbin_header_t g_rw;
static int g_rw_init  = 0;
static int g_rw_ready = 0;

/* Initialise g_rw as a deterministic empty store (in-memory only; the empty
 * header is not persisted until the first rwbinstore_write). */
static void rwbin_init_empty(const char *why)
{
    memset(&g_rw, 0, sizeof(g_rw));
    g_rw.magic     = SOTFS_RWBIN_MAGIC;
    g_rw.version   = SOTFS_RWBIN_VERSION;
    g_rw.count     = 0;
    g_rw.reserved  = 0;
    g_rw.next_free = (uint64_t)SOTFS_RWBIN_DATA_OFFSET;
    g_rw_ready     = 1;
    printf("[rwbinstore] ready · 0 entries (empty · %s)\n", why);
}

static int rwbin_lazy_init(void)
{
    if (g_rw_init) return g_rw_ready ? 0 : -2;
    g_rw_init = 1;
    /* Read the header (covers magic+counts+entries) sector-by-sector. */
    _Static_assert(sizeof(sotfs_rwbin_header_t) <= 8u * 512u, "rwbin header fits");
    uint8_t buf[8u * 512u];
    memset(buf, 0, sizeof(buf));
    uint64_t base = (uint64_t)SOTFS_RWBIN_HEADER_OFFSET / 512u;
    size_t nsect = (sizeof(g_rw) + 511u) / 512u;
    for (size_t s = 0; s < nsect; ++s) {
        if (virtio_blk_read_sector(base + s, buf + s * 512u) != 0) {
            /* Read failure → treat as a fresh/empty store deterministically
             * (do NOT fall through to memcpy uninitialised stack garbage). */
            rwbin_init_empty("read failed · assuming fresh region");
            return 0;
        }
    }
    memcpy(&g_rw, buf, sizeof(g_rw));
    if (g_rw.magic != SOTFS_RWBIN_MAGIC) {
        /* Fresh / unpopulated region → empty store. */
        rwbin_init_empty("fresh region");
        return 0;
    }
    /* Defend against a corrupt/crafted on-disk header: count must fit the
     * fixed-size entries[] table, else lookup/write would read OOB. */
    if (g_rw.count > SOTFS_RWBIN_MAX_ENTRIES) {
        printf("[rwbinstore] invalid on-disk count=%u (max %u) · resetting to empty\n",
               g_rw.count, (unsigned)SOTFS_RWBIN_MAX_ENTRIES);
        rwbin_init_empty("corrupt header · count out of range");
        return 0;
    }
    g_rw_ready = 1;
    printf("[rwbinstore] ready · %u entries · next_free=%lu\n",
           g_rw.count, (unsigned long)g_rw.next_free);
    return 0;
}

long rwbinstore_lookup(const char *name, uint64_t *offset_out)
{
    if (rwbin_lazy_init() != 0) return -2;
    if (!name) return -22;
    for (uint32_t i = 0; i < g_rw.count; ++i)
        if (strncmp(g_rw.entries[i].name, name, SOTFS_RWBIN_NAME_BYTES) == 0) {
            if (offset_out) *offset_out = g_rw.entries[i].offset;
            return (long)g_rw.entries[i].size;
        }
    return -2; /* ENOENT */
}

long rwbinstore_read(const char *name, void *buf, size_t cap)
{
    if (!buf || cap == 0) return -22;
    uint64_t off = 0;
    long size = rwbinstore_lookup(name, &off);
    if (size < 0) return size;
    uint64_t want = (uint64_t)size; if (want > cap) want = cap;
    uint64_t disk = off; size_t copied = 0; static uint8_t sec[512];
    while (copied < want) {
        uint64_t s = disk / 512u; size_t inner = (size_t)(disk % 512u);
        if (virtio_blk_read_sector(s, sec) != 0) return -5;
        size_t chunk = 512 - inner; if (chunk > want - copied) chunk = want - copied;
        memcpy((uint8_t *)buf + copied, sec + inner, chunk);
        copied += chunk; disk += chunk;
    }
    return (long)copied;
}

/* vblk write helper (sector-aligned RMW) lives in storage_virtio_blk.c. */
extern int vblk_write_block(void *backend, uint64_t offset, const void *buf, size_t len);

int rwbinstore_write(const char *name, const void *bytes, size_t len)
{
    if (rwbin_lazy_init() != 0) return -5; /* EIO · store not initialised */
    if (!name || !bytes || len == 0) return -22;

    /* Find an existing entry (replace) or claim a new slot. */
    int idx = -1;
    for (uint32_t i = 0; i < g_rw.count; ++i)
        if (strncmp(g_rw.entries[i].name, name, SOTFS_RWBIN_NAME_BYTES) == 0) { idx = (int)i; break; }
    if (idx < 0) {
        if (g_rw.count >= SOTFS_RWBIN_MAX_ENTRIES) return -28; /* ENOSPC */
        idx = (int)g_rw.count++;
    }

    /* Bump-allocate the bytes (4 KiB-aligned). Replacing leaks the old slot —
     * acceptable for a demo store (12 MiB · a few binaries). */
    uint64_t data_off = (g_rw.next_free + 4095u) & ~((uint64_t)4095u);
    if (data_off + len > (uint64_t)SOTFS_RWBIN_OFFSET + SOTFS_RWBIN_REGION_BYTES)
        return -28; /* ENOSPC */
    if (vblk_write_block(NULL, data_off, bytes, len) < 0) return -5;
    g_rw.next_free = data_off + len;

    memset(g_rw.entries[idx].name, 0, SOTFS_RWBIN_NAME_BYTES);
    strncpy(g_rw.entries[idx].name, name, SOTFS_RWBIN_NAME_BYTES - 1);
    g_rw.entries[idx].offset = data_off;
    g_rw.entries[idx].size   = (uint64_t)len;

    /* Persist the header+table to disk so the index survives reboot. */
    if (vblk_write_block(NULL, (uint64_t)SOTFS_RWBIN_HEADER_OFFSET, &g_rw, sizeof(g_rw)) < 0)
        return -5;
    printf("[rwbinstore] write '%s' · %zu bytes @ off=%lu · count=%u\n",
           name, len, (unsigned long)data_off, g_rw.count);
    return 0;
}

void rwbinstore_reinit(void)
{
    /* Drop the cached index and force a fresh read from virtio-blk on the
     * next access. This is the writable-store analogue of the WAL replay in
     * simreboot Phase 5: it proves the on-disk index (and the binaries it
     * points at) survived the reset, not just the in-RAM copy. */
    g_rw_init  = 0;
    g_rw_ready = 0;
    rwbin_lazy_init();
}
