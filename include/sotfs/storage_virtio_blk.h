#ifndef SOTFS_STORAGE_VIRTIO_BLK_H
#define SOTFS_STORAGE_VIRTIO_BLK_H

#include <stdint.h>
#include <sotfs/wal.h>   /* sotfs_storage_t */

/* PCI discovery. */
int      virtio_blk_probe(void);
int      virtio_blk_present(void);
uint32_t virtio_blk_bar0(void);

/* Virtqueue init (Phase 2c). */
int virtio_blk_init_queue(void);

/* Block I/O (Phase 2c/2d). */
int virtio_blk_read_sector (uint64_t sector, void       *out_buf);
int virtio_blk_write_sector(uint64_t sector, const void *buf);

/* A2 · sector-aligned RMW byte-write helper (same one the WAL uses · the
 * rwbinstore backend writes binaries + its on-disk index through this). */
int vblk_write_block(void *backend, uint64_t offset, const void *buf, size_t len);

/* Storage vtable constructor + readiness query (Phase 2d). */
sotfs_storage_t sotfs_storage_virtio_blk(void);
int             sotfs_storage_virtio_blk_ready(void);

#endif
