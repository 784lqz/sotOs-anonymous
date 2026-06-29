/*
 * sotOs · sotfs.img on-disk layout constants (L11-γ).
 *
 * The single 528 MiB sotfs.img backing store is partitioned into:
 *
 *   [0..4 KiB)        · stdlib header
 *   [4 KiB..28 MiB)   · python312.zip + free space
 *   [28 MiB..96 MiB)  · binary blob region (binstore · read-only)
 *   [96 MiB..256 MiB) · musl sysroot tree (read-only · mounted /usr)
 *   [256 MiB..268 MiB)· writable binary store (rwbinstore)
 *   [268 MiB..272 MiB)· sotFS WAL region
 *   [272 MiB..528 MiB)· writable data heap (sotfs_blkdev)
 *
 * The packer (scripts/build-python-stdlib-zip.sh) writes the header + zip at
 * build time.  The VFS backend (src/lucas/backends_python_stdlib.c) reads
 * them at runtime.  The WAL code (src/sotfs/wal.c) starts its cursor at
 * SOTFS_WAL_OFFSET so the two regions don't collide.
 */

#ifndef SOTFS_LAYOUT_H
#define SOTFS_LAYOUT_H

#include <stdint.h>

#define SOTFS_IMG_TOTAL_BYTES        ((272u + 256u) * 1024u * 1024u)  /* 96 -> 128 -> 144 (v2.6) -> 168 (binstore +8 / sysroot +16) -> 216 (sysroot 80->128 · Wine builtin .exe + DLL closure for new_process/wineboot) -> 220 (binstore +4 · A5 less/nano/vim editors) -> 476 (Phase-1b · +256 MiB writable data heap) -> 484 (binstore 48->56 · install-arc P0.1 dpkg toolchain incl. 1.4 MiB zstd) -> 488 (binstore 56->60 · 2nd-persona Debian GNU coreutils file-op set + grep) -> 496 (binstore +8 · apt arc P0) -> 528 (sysroot 128->160 · Wine M1 subset · DATA_OFFSET 240->272) */
#define SOTFS_STDLIB_HEADER_OFFSET   0u
#define SOTFS_STDLIB_ZIP_OFFSET      4096u
#define SOTFS_STDLIB_REGION_BYTES    (28u * 1024u * 1024u)
#define SOTFS_STDLIB_MAX_BYTES       (SOTFS_STDLIB_REGION_BYTES - SOTFS_STDLIB_ZIP_OFFSET)
/* SP2 · read-only binary blob region (binstore) · [28 MiB, 64 MiB).
 * GROWN 32 -> 36 MiB (round-11 fix): chocodoom.bin (2.2 MiB) pushed the binstore
 * data past the old 60 MiB end INTO the sysroot region, whose packer then
 * overwrote chocodoom's tail with sysroot files (mtio.h) → the long-hunted
 * "chocolate text corruption". The sysroot start moves 60 -> 64 MiB to match. */
#define SOTFS_BINARIES_OFFSET        (28u * 1024u * 1024u)
#define SOTFS_BINARIES_REGION_BYTES  (68u * 1024u * 1024u)  /* 32 -> 36 -> 44 (v2.x · room for off-the-shelf app binaries, e.g. gtk3-demo) -> 48 (A5 · less/nano/vim editors) -> 56 (install-arc P0.1 · dpkg/dpkg-deb/dpkg-split/tar/xz/gzip/zstd · zstd alone is 1.4 MiB) -> 60 (2nd-persona · the Debian GNU coreutils file-op set + grep) -> 68 (apt arc P0 · apt/apt-get/apt-cache frontends) */
#define SOTFS_BINSTORE_HEADER_OFFSET SOTFS_BINARIES_OFFSET
#define SOTFS_BINSTORE_DATA_OFFSET   (SOTFS_BINARIES_OFFSET + 4096u)
/* read-only musl sysroot tree · [76 MiB, 204 MiB). */
#define SOTFS_SYSROOT_OFFSET         (96u * 1024u * 1024u)   /* 60 -> 64 -> 72 (binstore +8) -> 76 (binstore +4 · A5) -> 84 (binstore +8 · install-arc P0.1 dpkg) -> 88 (binstore +4 · 2nd-persona coreutils) -> 96 (binstore +8 · apt arc P0) */
#define SOTFS_SYSROOT_REGION_BYTES   (160u * 1024u * 1024u)  /* 16 -> 48 -> 64 -> 80 -> 128 (v2.x · the wine builtin .exe + windows DLL closure that wineboot --init pulls in overflowed 80 MiB → truncated the tail PE → INVALID_IMAGE_FORMAT) -> 160 (Wine M1 · tools/wine-stage.sh ships the full x86_64-windows PE + x86_64-unix .so subset, ~137 MiB packed, overflowed 128 MiB) */
#define SOTFS_SYSROOT_HEADER_OFFSET  SOTFS_SYSROOT_OFFSET
#define SOTFS_SYSROOT_DATA_OFFSET    (SOTFS_SYSROOT_OFFSET + 512u * 1024u)  /* 64K -> 512K header+table area */
/* writable on-disk binary store (rwbinstore) · [152 MiB, 164 MiB). */
#define SOTFS_RWBIN_OFFSET           (256u * 1024u * 1024u)  /* 80 -> 112 -> 128 -> 152 -> 200 (sysroot 80->128) -> 204 (binstore +4 · A5) -> 212 (binstore +8 · install-arc P0.1 dpkg) -> 216 (binstore +4 · 2nd-persona coreutils) -> 224 (binstore +8 · apt arc P0) -> 256 (sysroot 128->160 · Wine M1 subset) */
#define SOTFS_RWBIN_REGION_BYTES     (12u * 1024u * 1024u)
#define SOTFS_RWBIN_HEADER_OFFSET    SOTFS_RWBIN_OFFSET
#define SOTFS_RWBIN_DATA_OFFSET      (SOTFS_RWBIN_OFFSET + 4096u)
#define SOTFS_WAL_OFFSET             (268u * 1024u * 1024u)  /* 92 -> 124 -> 140 -> 164 -> 212 (sysroot 80->128) -> 216 (binstore +4 · A5) -> 224 (binstore +8 · install-arc P0.1 dpkg) -> 228 (binstore +4 · 2nd-persona coreutils) -> 236 (binstore +8 · apt arc P0) -> 268 (sysroot 128->160 · Wine M1 subset) */
#define SOTFS_WAL_REGION_BYTES       (4u * 1024u * 1024u)
/* writable data heap (sotfs_blkdev · disk block store) · after the WAL. */
#define SOTFS_DATA_OFFSET            (SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES)  /* 232 MiB */
#define SOTFS_DATA_REGION_BYTES      (256u * 1024u * 1024u)  /* 256 MiB writable heap · ~65536 4 KiB blocks */
#define SOTFS_STDLIB_MAGIC           0x53544c42u   /* 'STLB' */
#define SOTFS_STDLIB_VERSION         1u

struct sotfs_stdlib_header {
    uint32_t magic;       /* SOTFS_STDLIB_MAGIC */
    uint32_t version;     /* SOTFS_STDLIB_VERSION */
    uint64_t zip_size;    /* size of python312.zip in bytes */
    uint8_t  reserved[16];
} __attribute__((packed));

/* ── layout invariants · the five regions must tile [0, IMG_TOTAL_BYTES) with
 *    no gap and no overlap.  Any region resize that forgets to shift the ones
 *    after it trips one of these at compile time. ───────────────────────────── */
_Static_assert(SOTFS_STDLIB_REGION_BYTES == SOTFS_BINARIES_OFFSET,
               "stdlib region must end exactly at binstore start");
_Static_assert(SOTFS_BINARIES_OFFSET + SOTFS_BINARIES_REGION_BYTES == SOTFS_SYSROOT_OFFSET,
               "binstore region must end exactly at sysroot start");
_Static_assert(SOTFS_SYSROOT_OFFSET + SOTFS_SYSROOT_REGION_BYTES == SOTFS_RWBIN_OFFSET,
               "sysroot region must end exactly at rwbinstore start");
_Static_assert(SOTFS_RWBIN_OFFSET + SOTFS_RWBIN_REGION_BYTES == SOTFS_WAL_OFFSET,
               "rwbinstore region must end exactly at WAL start");
_Static_assert(SOTFS_WAL_OFFSET + SOTFS_WAL_REGION_BYTES == SOTFS_DATA_OFFSET,
               "WAL region must end exactly at the data-heap start");
_Static_assert(SOTFS_DATA_OFFSET + SOTFS_DATA_REGION_BYTES == SOTFS_IMG_TOTAL_BYTES,
               "data-heap region must end exactly at the image total size");
_Static_assert(SOTFS_SYSROOT_DATA_OFFSET > SOTFS_SYSROOT_HEADER_OFFSET
                 && SOTFS_SYSROOT_DATA_OFFSET < SOTFS_SYSROOT_OFFSET + SOTFS_SYSROOT_REGION_BYTES,
               "sysroot data offset must lie inside the sysroot region, past its header");

#endif /* SOTFS_LAYOUT_H */
