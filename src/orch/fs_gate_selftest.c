/*
 * sotOs · orch · Phase 1b fs-gate self-test (compile-gated).
 *
 * This whole translation unit is a NO-OP unless the build defines
 * SOTOS_FS_GATE.  Only tools/fs-gate.sh builds with that define set
 * (via `SOTOS_FS_GATE=1 just build`, which CMake forwards as a compile
 * definition on orch — see src/orch/CMakeLists.txt).  Every other gate's
 * boot is therefore UNAFFECTED: fs_gate_selftest() compiles to an empty
 * function and the linker drops it.
 *
 * What it proves (when enabled, on the Tier-0/operator/orch path — NOT a
 * Tier-2 guest):
 *   1. SCALE   · write a 50 MiB file to /tmp/bigfile through the sotfs VFS
 *      block-write path (64 KiB chunks of a known pattern), checksum what we
 *      wrote, read it back, recompute, compare → MATCH/MISMATCH marker.
 *      Then a `df` line from the real blkdev geometry, then UNLINK the file
 *      so the data region/WAL is not left full for the persist leg + other
 *      gates.
 *   2. PERSIST · write /tmp/persist-probe = "SOTFS-PERSIST-OK" (WAL-logged),
 *      flush, trigger the simreboot cascade (Phase 1 checkpoint … Phase 5 WAL
 *      replay), then re-read the probe after replay → read-back marker.
 *
 * The scale leg deliberately uses the low-level sotfs_file_write/_read on the
 * live graph (NOT lucas_sotfs_write_at) so it does NOT emit ~800 WAL records
 * for a throwaway 50 MiB file.  The persist leg DOES go through the WAL-logged
 * path, because WAL replay is exactly what it is testing.
 */

#ifdef SOTOS_FS_GATE

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <sotfs/graph.h>
#include <sotfs/rewrite.h>
#include <sotfs/blkdev.h>

/* From src/lucas/backends_sotfs.c — the live, lazy-inited sotfs graph and the
 * path-based WAL-logged write/read used by the persist leg. */
extern sotfs_graph_t *backends_sotfs_get_graph(void);
extern int lucas_sotfs_write_at(const char *path, uint32_t off,
                                const uint8_t *data, uint32_t len, int truncate);
extern int lucas_sotfs_read_at(const char *path, uint32_t off,
                               uint8_t *out, uint32_t max);
extern int lucas_sotfs_unlink(const char *path);
extern int lucas_sotfs_read_file(const char *path, void *buf, size_t max);

/* The persist leg drives the existing 5-phase userspace reset. */
extern int orch_simreboot_cascade(void);

#define FSG_TOTAL_BYTES   (50u * 1024u * 1024u)   /* 50 MiB */
#define FSG_CHUNK_BYTES   (64u * 1024u)           /* 64 KiB write/read unit */

/* fnv1a-64 rolling checksum. */
static uint64_t fsg_fnv1a(uint64_t h, const uint8_t *p, uint32_t n)
{
    for (uint32_t i = 0; i < n; ++i) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }
    return h;
}

/* One reusable 64 KiB scratch buffer (static · keeps it off the boot stack). */
static uint8_t fsg_buf[FSG_CHUNK_BYTES];

void fs_gate_selftest(void)
{
    /* Force the lazy sotfs bring-up (graph + disk-backed blkdev + WAL replay)
     * before we grab the graph handle.  lucas_sotfs_read_file() calls the
     * internal lazy_init(); /welcome is a seeded honey file so this also
     * confirms the VFS resolves. */
    {
        char probe[8];
        (void)lucas_sotfs_read_file("/welcome", probe, sizeof(probe));
    }

    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) { printf("[fs-gate] ABORT · no sotfs graph\n"); return; }

    printf("[fs-gate] Phase 1b self-test START · 50 MiB scale + persist\n");
    printf("[fs-gate] blkdev geometry · total=%lu used=%lu\n",
           (unsigned long)sotfs_blk_total(), (unsigned long)sotfs_blk_used());

    /* ── SCALE leg ────────────────────────────────────────────────────────
     * Create /tmp/bigfile (== /bigfile in the sotfs root) and write 50 MiB. */
    const char *leaf = "bigfile";
    int root_id = g->root_id;
    if (sotfs_find_edge(g, root_id, leaf) != 0)
        sotfs_rewrite_unlink(g, root_id, leaf);              /* stale carry-over */
    int rc = sotfs_rewrite_create_file(g, root_id, leaf, 0644);
    if (rc <= 0) { printf("[fs-gate] scale ABORT · create rc=%d\n", rc); return; }
    int file_id = sotfs_find_edge(g, root_id, leaf);
    if (file_id <= 0) { printf("[fs-gate] scale ABORT · resolve failed\n"); return; }

    uint64_t wsum = 1469598103934665603ULL;   /* fnv1a offset basis */
    uint32_t off  = 0;
    int short_w   = 0;
    while (off < FSG_TOTAL_BYTES) {
        uint32_t chunk = FSG_TOTAL_BYTES - off;
        if (chunk > FSG_CHUNK_BYTES) chunk = FSG_CHUNK_BYTES;
        /* pattern: byte = (absolute_offset / 4096) & 0xFF */
        for (uint32_t i = 0; i < chunk; ++i)
            fsg_buf[i] = (uint8_t)(((off + i) / 4096u) & 0xFFu);
        wsum = fsg_fnv1a(wsum, fsg_buf, chunk);
        int w = sotfs_file_write(g, file_id, off, fsg_buf, chunk);
        if (w != (int)chunk) {
            printf("[fs-gate] scale write SHORT at off=%u w=%d (expected %u)\n",
                   off, w, chunk);
            short_w = 1;
            break;
        }
        off += chunk;
        if ((off & (4u * 1024u * 1024u - 1u)) == 0)   /* heartbeat each 4 MiB */
            printf("[fs-gate] scale · wrote %u MiB\n", off / (1024u * 1024u));
    }

    if (!short_w) {
        /* Read it back and recompute the checksum. */
        uint64_t rsum = 1469598103934665603ULL;
        uint32_t roff = 0;
        int short_r = 0;
        while (roff < FSG_TOTAL_BYTES) {
            uint32_t chunk = FSG_TOTAL_BYTES - roff;
            if (chunk > FSG_CHUNK_BYTES) chunk = FSG_CHUNK_BYTES;
            int r = sotfs_file_read(g, file_id, roff, fsg_buf, chunk);
            if (r != (int)chunk) {
                printf("[fs-gate] scale read SHORT at off=%u r=%d (expected %u)\n",
                       roff, r, chunk);
                short_r = 1;
                break;
            }
            rsum = fsg_fnv1a(rsum, fsg_buf, chunk);
            roff += chunk;
        }
        if (!short_r) {
            if (rsum == wsum)
                printf("[fs-gate] scale 50MB write+read checksum=0x%016lx MATCH\n",
                       (unsigned long)rsum);
            else
                printf("[fs-gate] scale 50MB write+read checksum=0x%016lx MISMATCH (wrote 0x%016lx)\n",
                       (unsigned long)rsum, (unsigned long)wsum);
        }
    }

    /* df line · real blkdev geometry while the 50 MiB file is still resident. */
    {
        uint64_t total = sotfs_blk_total();
        uint64_t used  = sotfs_blk_used();
        uint64_t freeb = (total > used) ? (total - used) : 0;
        printf("[fs-gate] df blocks=%lu free=%lu used=%lu\n",
               (unsigned long)total, (unsigned long)freeb, (unsigned long)used);
    }

    /* UNLINK · free the 50 MiB so the data region isn't left full. */
    sotfs_rewrite_unlink(g, root_id, leaf);
    printf("[fs-gate] scale · /tmp/bigfile unlinked · used now=%lu blocks\n",
           (unsigned long)sotfs_blk_used());

    /* ── PERSIST leg ──────────────────────────────────────────────────────
     * Write a small known marker (WAL-logged), flush, simreboot, re-read. */
    {
        static const char marker[] = "SOTFS-PERSIST-OK";
        const uint32_t mlen = (uint32_t)(sizeof(marker) - 1);
        int pw = lucas_sotfs_write_at("/tmp/persist-probe", 0,
                                      (const uint8_t *)marker, mlen, /*truncate=*/1);
        if (pw != (int)mlen) {
            printf("[fs-gate] persist ABORT · write rc=%d\n", pw);
        } else {
            sotfs_blk_flush();
            printf("[fs-gate] persist · wrote marker · triggering simreboot\n");
            int sr = orch_simreboot_cascade();
            printf("[fs-gate] persist · simreboot rc=%d · re-reading marker\n", sr);

            char rb[64];
            memset(rb, 0, sizeof(rb));
            int rr = lucas_sotfs_read_file("/tmp/persist-probe", rb, sizeof(rb) - 1);
            if (rr >= (int)mlen && memcmp(rb, marker, mlen) == 0)
                printf("[fs-gate] persist read-back: %.*s\n", (int)mlen, rb);
            else
                printf("[fs-gate] persist read-back FAILED rc=%d got='%.*s'\n",
                       rr, (rr > 0 ? rr : 0), rb);
        }
    }

    printf("[fs-gate] Phase 1b self-test DONE\n");
}

#else  /* !SOTOS_FS_GATE */

void fs_gate_selftest(void) { /* compiled out · zero cost to other gates */ }

#endif
