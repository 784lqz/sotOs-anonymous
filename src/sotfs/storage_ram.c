/*
 * sotOs · sotFS-γ Phase 1 · RAM-backed storage for the WAL.
 *
 * Fixed-size buffer.  No persistence across reboot.  Phase 2 swaps
 * this for virtio-blk via the same sotfs_storage_ops_t vtable.
 */
#include <sotfs/wal.h>
#include <string.h>

#define SOTFS_RAM_STORAGE_BYTES  (64 * 1024)   /* 64 KiB log buffer */

static uint8_t  g_ram_buffer[SOTFS_RAM_STORAGE_BYTES];

static int ram_write_block(void *backend, uint64_t offset, const void *buf, size_t len) {
    (void)backend;
    if (offset + len > SOTFS_RAM_STORAGE_BYTES) return -28; /* ENOSPC */
    memcpy(g_ram_buffer + offset, buf, len);
    return (int)len;
}

static int ram_read_block(void *backend, uint64_t offset, void *buf, size_t len) {
    (void)backend;
    if (offset + len > SOTFS_RAM_STORAGE_BYTES) return -22; /* EINVAL */
    memcpy(buf, g_ram_buffer + offset, len);
    return (int)len;
}

static int ram_flush(void *backend) {
    (void)backend;
    return 0;   /* RAM has no flush semantics; durability is the
                 * point of Phase 2 (virtio-blk). */
}

static uint64_t ram_capacity_bytes(void *backend) {
    (void)backend;
    return SOTFS_RAM_STORAGE_BYTES;
}

static const sotfs_storage_ops_t ram_ops = {
    .write_block    = ram_write_block,
    .read_block     = ram_read_block,
    .flush          = ram_flush,
    .capacity_bytes = ram_capacity_bytes,
};

sotfs_storage_t sotfs_storage_ram(void) {
    return (sotfs_storage_t) {
        .ops           = &ram_ops,
        .backend_state = NULL,
    };
}
