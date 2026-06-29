#ifndef SOTFS_SYSROOT_H
#define SOTFS_SYSROOT_H
/*
 * sotOs · musl sysroot region format (tcc-libc).
 * Read-only directory tree baked into sotfs.img [64,112 MiB), mounted at /usr.
 * Header at SOTFS_SYSROOT_HEADER_OFFSET, entry table immediately after, file
 * data 4-KiB-aligned from SOTFS_SYSROOT_DATA_OFFSET.  One entry per directory,
 * per file, or per symlink; the tree is implicit in the `path` strings (parent
 * = path minus its last component).
 */
#include <stdint.h>
#include <sotfs/layout.h>   /* SOTFS_SYSROOT_{DATA,HEADER}_OFFSET · table-fit assert */

#define SOTFS_SYSROOT_MAGIC        0x52535953u   /* "SYSR" on disk */
#define SOTFS_SYSROOT_VERSION      1u
#define SOTFS_SYSROOT_MAX_ENTRIES  2048           /* real recursive lib tree (was 384) */
#define SOTFS_SYSROOT_PATH_BYTES   192            /* deep real trees exceed 128 (was 128) */

#define SOTFS_SYSROOT_TYPE_DIR  0u
#define SOTFS_SYSROOT_TYPE_FILE 1u
#define SOTFS_SYSROOT_TYPE_LNK  2u               /* symlink · offset/size point at target-path bytes */

typedef struct sotfs_sysroot_entry {
    char     path[SOTFS_SYSROOT_PATH_BYTES];  /* relative to /usr, e.g. "include/sys/stat.h" */
    uint32_t type;                            /* DIR, FILE, or LNK */
    uint32_t _pad;
    uint64_t offset;                          /* absolute image byte offset (0 for dir) */
    uint64_t size;                            /* file size (0 for dir) */
} sotfs_sysroot_entry_t;   /* 216 bytes */

typedef struct sotfs_sysroot_header {
    uint32_t magic;     /* SOTFS_SYSROOT_MAGIC */
    uint32_t version;
    uint32_t count;     /* number of valid entries */
    uint32_t _pad;
} sotfs_sysroot_header_t;

/* ── wire-format invariants ──────────────────────────────────────────────────
 * The on-disk entry is `path[PATH_BYTES]` + (type,_pad,offset,size) = +24 bytes,
 * with no trailing padding.  scripts/build-sysroot.sh packs the SAME shape
 * (path.ljust(NAME) + struct.pack('<IIQQ', ...)); if this assert ever fires, the
 * packer and the C reader have diverged and the entry table will be misparsed. */
_Static_assert(sizeof(sotfs_sysroot_entry_t) == SOTFS_SYSROOT_PATH_BYTES + 24u,
               "sysroot entry must be PATH_BYTES + 24 with no padding (packer must match)");
/* The full entry table (worst case: MAX_ENTRIES) plus the 16-byte header must
 * fit in the reserved header area [HEADER_OFFSET, DATA_OFFSET) before file data. */
_Static_assert(sizeof(sotfs_sysroot_header_t)
                 + (uint64_t)SOTFS_SYSROOT_MAX_ENTRIES * sizeof(sotfs_sysroot_entry_t)
               <= (uint64_t)(SOTFS_SYSROOT_DATA_OFFSET - SOTFS_SYSROOT_HEADER_OFFSET),
               "sysroot header + full entry table must fit before the file-data region");

#endif /* SOTFS_SYSROOT_H */
