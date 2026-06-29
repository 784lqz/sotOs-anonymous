#ifndef SOTFS_BINSTORE_H
#define SOTFS_BINSTORE_H

/*
 * sotOs · sotfs.img binary blob region (binstore · SP2).
 *
 * A read-only, build-time-baked indexed archive of binaries, living in the
 * [28 MiB, 64 MiB) region of sotfs.img (see include/sotfs/layout.h).  Mirrors
 * the python-stdlib backend pattern (ADR-010): a header at the region base
 * plus binaries laid out sector-aligned after it.  Read at runtime via
 * virtio_blk_read_sector.  No DPO-graph involvement · large binaries never
 * enter the in-RAM deception graph.
 *
 * On-disk layout (offsets from include/sotfs/layout.h):
 *   [SOTFS_BINSTORE_HEADER_OFFSET .. +4 KiB)   struct sotfs_binstore_header
 *   [SOTFS_BINSTORE_DATA_OFFSET   .. )         binary bytes, each 4 KiB-aligned
 */

#include <stdint.h>
#include <stddef.h>

#define SOTFS_BINSTORE_MAGIC       0x4e494253u  /* "SBIN" on disk (bytes 53 42 49 4e) */
#define SOTFS_BINSTORE_VERSION     1u
#define SOTFS_BINSTORE_MAX_ENTRIES 96  /* 32->48->51->64->96 · the header region grew
                                        * 4 KiB->8 KiB (egress P2 openssl was the 52nd
                                        * binary · 51 was the 4 KiB ceiling).  header =
                                        * 16 + 96*80 = 7696 B, STILL fits the 8 KiB region
                                        * (≤16 sectors · the _Static_assert in
                                        * backends_binstore.c validates it) so DATA_OFFSET
                                        * stays +8192 · no reader change.  96 absorbs the
                                        * Debian-persona GNU coreutils set (debian-* glibc).
                                        * KEEP in sync with build-binstore.sh MAX_ENTRIES. */
#define SOTFS_BINSTORE_NAME_BYTES  64

typedef struct sotfs_binstore_entry {
    char     name[SOTFS_BINSTORE_NAME_BYTES];  /* basename of the binary */
    uint64_t offset;   /* absolute byte offset of the bytes in sotfs.img */
    uint64_t size;     /* byte length of the binary */
} sotfs_binstore_entry_t;

typedef struct sotfs_binstore_header {
    uint32_t magic;     /* SOTFS_BINSTORE_MAGIC */
    uint32_t version;   /* SOTFS_BINSTORE_VERSION */
    uint32_t count;     /* number of valid entries */
    uint32_t reserved;
    sotfs_binstore_entry_t entries[SOTFS_BINSTORE_MAX_ENTRIES];
} sotfs_binstore_header_t;

/* Look up a binary by name. Returns size (>0) and writes *offset_out, or a
 * negative errno (-2 ENOENT, -5 EIO). */
long binstore_lookup(const char *name, uint64_t *offset_out);

/* Read up to `cap` bytes of the named binary (from its start) into `buf`.
 * Returns bytes read (>0) or a negative errno. */
long binstore_read(const char *name, void *buf, size_t cap);

/* Boot-time self-test · logs region contents + a round-trip read of tcc.bin. */
void binstore_selftest(void);

#endif /* SOTFS_BINSTORE_H */
