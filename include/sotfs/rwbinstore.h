#ifndef SOTFS_RWBINSTORE_H
#define SOTFS_RWBINSTORE_H
/*
 * sotOs · writable on-disk binary store (A2).
 * Region [112,124 MiB) of sotfs.img: a mutable indexed archive of binaries
 * written via virtio_blk_write_sector. Mirrors the read-only binstore format
 * but is writable + persisted on disk (the disk IS the persistence). A fresh
 * image has no 'RWBN' magic → treated as an EMPTY store (count=0).
 */
#include <stdint.h>
#include <stddef.h>

#define SOTFS_RWBIN_MAGIC        0x4e425752u   /* "RWBN" on disk (bytes 52 57 42 4e) */
#define SOTFS_RWBIN_VERSION      1u
#define SOTFS_RWBIN_MAX_ENTRIES  16
#define SOTFS_RWBIN_NAME_BYTES   64

typedef struct sotfs_rwbin_entry {
    char     name[SOTFS_RWBIN_NAME_BYTES];
    uint64_t offset;   /* absolute byte offset in sotfs.img */
    uint64_t size;
} sotfs_rwbin_entry_t;

typedef struct sotfs_rwbin_header {
    uint32_t magic;        /* SOTFS_RWBIN_MAGIC */
    uint32_t version;
    uint32_t count;
    uint32_t reserved;
    uint64_t next_free;    /* bump allocator cursor (absolute offset) */
    sotfs_rwbin_entry_t entries[SOTFS_RWBIN_MAX_ENTRIES];
} sotfs_rwbin_header_t;

/* Read up to `cap` bytes of the named binary; returns bytes read or -errno. */
long rwbinstore_read(const char *name, void *buf, size_t cap);
/* Lookup-only: returns size (>0) and writes *offset_out, or -errno. */
long rwbinstore_lookup(const char *name, uint64_t *offset_out);
/* Install/replace a binary: write bytes + persist the index. Returns 0 or -errno. */
int  rwbinstore_write(const char *name, const void *bytes, size_t len);
/* A2 · persistence proof · drop the in-RAM index and re-read it from disk
 * (re-prints "[rwbinstore] ready · N entries"). Called by the simreboot
 * cascade to demonstrate installed binaries survive a userspace reset. */
void rwbinstore_reinit(void);

#endif /* SOTFS_RWBINSTORE_H */
