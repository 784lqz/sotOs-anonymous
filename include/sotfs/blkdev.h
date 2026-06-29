#ifndef SOTFS_BLKDEV_H
#define SOTFS_BLKDEV_H
#include <stdint.h>
#include <stddef.h>
#include "sotfs/wal.h"   /* sotfs_storage_t */

#define SOTFS_BLKDEV_MAGIC      0x53464442u   /* 'SFDB' */
#define SOTFS_BLKDEV_VERSION    1u
#define SOTFS_BLKDEV_BLOCK_SIZE 4096u
#define SOTFS_BLKDEV_CACHE_SLOTS 256           /* 256 * 4 KiB = 1 MiB RAM buffer cache · MUST stay
                                                * small: this is a static BSS array linked into the
                                                * freestanding orch process — 8 MiB blew orch's budget
                                                * and wedged bootstrap.  Write-back-on-evict streams a
                                                * 50 MB file correctly through 1 MiB. */

/* Init over a storage backend at base byte-offset `region_off`, `region_bytes` long.
 * Reads/initialises the superblock + free bitmap.  `fresh != 0` formats (zeroes
 * the bitmap, stamps the superblock); `fresh == 0` reads an existing layout.
 * Returns 0 on success, negative on error. */
int sotfs_blkdev_init(sotfs_storage_t *storage, uint64_t region_off,
                      uint64_t region_bytes, int fresh);

/* Allocate a free data block · returns a 1-based disk block-id, or 0 on ENOSPC. */
int  sotfs_blk_alloc(void);
/* Free a previously-allocated block-id (no-op on 0/out-of-range). */
void sotfs_blk_free(int blk);
/* Read/write one 4 KiB block by id, through the LRU cache.  buf is 4096 bytes.
 * Return 0 on success, negative on error. */
int  sotfs_blk_read(int blk, void *buf);
int  sotfs_blk_write(int blk, const void *buf);
/* Flush all dirty cache slots + the bitmap to the backend. */
void sotfs_blk_flush(void);

/* Counts for statfs/df (no scan). */
uint64_t sotfs_blk_total(void);
uint64_t sotfs_blk_used(void);

#endif
