/* Host unit · `cc -I include src/test/blkdev_unit/blkdev_unit.c src/sotfs/blkdev.c -o /tmp/blkdev_unit && /tmp/blkdev_unit`
 * A malloc'd fake backend implements sotfs_storage_ops_t so the bitmap +
 * LRU logic runs with no seL4/virtio.  Ops member names/signatures match the
 * real `sotfs_storage_ops_t` in include/sotfs/wal.h:
 *   write_block(backend, off, buf, len) / read_block(backend, off, buf, len)
 *   flush(backend) / capacity_bytes(backend). */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sotfs/blkdev.h"

static uint8_t *g_disk; static uint64_t g_disk_bytes;
static int fake_w(void *b,uint64_t off,const void *p,size_t n){ (void)b; if(off+n>g_disk_bytes) return -28; memcpy(g_disk+off,p,n); return (int)n; }
static int fake_r(void *b,uint64_t off,void *p,size_t n){ (void)b; if(off+n>g_disk_bytes) return -22; memcpy(p,g_disk+off,n); return (int)n; }
static int fake_f(void *b){ (void)b; return 0; }
static uint64_t fake_c(void *b){ (void)b; return g_disk_bytes; }
static const sotfs_storage_ops_t FAKE = {
    .write_block = fake_w, .read_block = fake_r, .flush = fake_f, .capacity_bytes = fake_c,
};

int main(void){
    g_disk_bytes = 16u*1024u*1024u;          /* 16 MiB fake region = ~4096 blocks */
    g_disk = calloc(1, g_disk_bytes); assert(g_disk);
    sotfs_storage_t st = { &FAKE, NULL };

    /* fresh format */
    assert(sotfs_blkdev_init(&st, 0, g_disk_bytes, 1) == 0);
    assert(sotfs_blk_used() == 0);

    /* alloc returns distinct, non-zero ids; used count tracks */
    int a = sotfs_blk_alloc(), b = sotfs_blk_alloc();
    assert(a > 0 && b > 0 && a != b);
    assert(sotfs_blk_used() == 2);

    /* write-then-read round-trips through the cache */
    uint8_t out[4096], in[4096];
    memset(in, 0xAB, sizeof(in)); in[0] = 0x42;
    assert(sotfs_blk_write(a, in) == 0);
    memset(out, 0, sizeof(out));
    assert(sotfs_blk_read(a, out) == 0);
    assert(memcmp(in, out, 4096) == 0);

    /* free reclaims · a re-alloc reuses the slot, used count drops then rises */
    sotfs_blk_free(a);
    assert(sotfs_blk_used() == 1);
    int c = sotfs_blk_alloc();
    assert(c == a);                          /* lowest-free reuse */

    /* flush + re-init (fresh=0) must read the persisted bitmap back */
    sotfs_blk_write(b, in);
    sotfs_blk_flush();
    assert(sotfs_blkdev_init(&st, 0, g_disk_bytes, 0) == 0);
    assert(sotfs_blk_used() == 2);           /* a(reused as c) + b survive */
    memset(out, 0, sizeof(out));
    assert(sotfs_blk_read(b, out) == 0 && memcmp(in, out, 4096) == 0);

    /* eviction: force more distinct blocks than cache slots, read the first back */
    int first = sotfs_blk_alloc();
    sotfs_blk_write(first, in);
    for (int i = 0; i < SOTFS_BLKDEV_CACHE_SLOTS + 4; ++i){
        int x = sotfs_blk_alloc(); if (x <= 0) break;
        uint8_t t[4096]; memset(t, i & 0xFF, sizeof(t));
        sotfs_blk_write(x, t);               /* evicts `first` from cache → must write-back */
    }
    memset(out, 0, sizeof(out));
    assert(sotfs_blk_read(first, out) == 0 && memcmp(in, out, 4096) == 0);

    /* Phase 1b · self-format-on-fresh: a zeroed region (magic absent) with the
     * caller passing fresh=0 must self-format (NOT reject), so a brand-new image
     * comes up writable on first boot.  Wipe the disk and init with fresh=0. */
    memset(g_disk, 0, g_disk_bytes);
    assert(sotfs_blkdev_init(&st, 0, g_disk_bytes, 0) == 0);  /* forced format */
    assert(sotfs_blk_used() == 0);                            /* empty bitmap */
    assert(sotfs_blk_total() > 0);
    int z = sotfs_blk_alloc();
    assert(z > 0);
    /* re-attach (fresh=0) over the now-formatted region must read the bitmap */
    sotfs_blk_flush();
    assert(sotfs_blkdev_init(&st, 0, g_disk_bytes, 0) == 0);
    assert(sotfs_blk_used() == 1);                            /* the z alloc persisted */

    printf("[blkdev-unit] ALL PASS\n");
    return 0;
}
