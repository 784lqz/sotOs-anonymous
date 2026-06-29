#ifndef SOTFS_GRAPH_H
#define SOTFS_GRAPH_H

#include <stdint.h>
#include <stddef.h>

#define SOTFS_MAX_INODES   1024 /* 256 -> 1024 · install-arc: `dpkg -i hello` creates ~120 nodes (~30 locale trees /usr/share/locale/<lang>/LC_MESSAGES/hello.mo + doc/info/man) on top of the ~176 boot baseline (Wine prefix + honey + dpkg DB) → 256 overflowed ("No space left on device" mid-unpack).  56 B each → ~57 KiB BSS. */
#define SOTFS_MAX_EDGES    2048 /* 512 -> 2048 · ~one edge per node (the locale dir tree).  76 B each → ~156 KiB BSS. */
#define SOTFS_MAX_BLOCKS   49152 /* 16384->49152 · mapping entries (20 B ≈ 960 KiB BSS) · disk
                                  * DATA region is 256 MiB = 65536 blocks.  apt-get update's full
                                  * trixie working set is ~154 MiB (54 Packages + 50 srcpkgcache +
                                  * 50 pkgcache); 16384 (64 MiB) hit SOTFS_ERR_NOSPACE mid cache-
                                  * save.  Append-fast-path in sotfs_file_write keeps alloc O(1). */
#define SOTFS_MAX_NAME     128 /* 32 -> 64 -> 128 · real software needs long leaf names:
                                * git loose objects = 38 hex chars, pack-<40>.pack = 50;
                                * apt list filenames URL-encode the full archive path —
                                * deb.debian.org_debian_dists_trixie_main_binary-amd64_Packages.xz
                                * is 64 chars (exactly hit the old 64 limit → NAMETOOLONG,
                                * mislabeled ENOSPC → "No space left on device" on the Packages
                                * fetch), and security/component repos run longer still.  The
                                * runtime graph is a BSS global (g_sotfs); +64 B × 1024 inodes =
                                * 64 KiB (the on-stack selftest graph does not run at boot). */
#define SOTFS_BLOCK_SIZE   4096 /* 512 -> 4096 · the baked system.reg is 3 MiB; 512-byte blocks made it ~6144 blocks (O(n²) write).  4 KiB blocks: ~768 blocks. */

typedef enum {
    SOTFS_KIND_FREE    = 0,
    SOTFS_KIND_FILE    = 1,
    SOTFS_KIND_DIR     = 2,
    SOTFS_KIND_SYMLINK = 3,
} sotfs_inode_kind_t;

typedef struct sotfs_inode {
    int                 id;            /* 0 = free */
    sotfs_inode_kind_t  kind;
    uint32_t            mode;
    uint32_t            size;
    uint32_t            generation;
    int                 nlink;
    uint8_t             functor_persistence;  /* γ · 0 = identity, 1 = F_persistence */
    uint8_t             orphan;               /* POSIX delete-on-last-close: unlinked
                                               * (nlink==0) but a handle is still open;
                                               * freed when open_count drops to 0. */
    uint8_t             open_count;           /* # of open backend handles on this inode */
    uint8_t             _pad[1];              /* explicit pad for 4-byte alignment */
    int64_t             mtime_sec;   /* wall-clock seconds · stamped by the lucas layer */
    int64_t             atime_sec;   /* wall-clock seconds · stamped by the lucas layer */
    int64_t             ctime_sec;   /* wall-clock seconds · stamped by the lucas layer */
} sotfs_inode_t;

/* 28 -> 56 in the clock-fidelity arc: +4 alignment pad (int64 wants 8-byte
 * alignment; the struct ended at offset 28) + 3*8 = 24 for mtime/atime/ctime. */
_Static_assert(sizeof(sotfs_inode_t) == 56, "sotfs_inode_t size · 28->56 (clock-fidelity: +mtime/atime/ctime)");

typedef struct sotfs_edge {
    int    id;
    int    parent_id;
    int    child_id;
    char   name[SOTFS_MAX_NAME];
    double curvature;   /* sotFS-η · Forman-Ricci · 0 = unmeasured */
} sotfs_edge_t;

typedef struct sotfs_block {
    int      id;        /* 0 = free slot */
    int      file_id;
    uint32_t offset;    /* file byte-offset this block covers (4 KiB aligned) */
    uint32_t length;    /* valid bytes within the block */
    int      disk_blk;  /* sotfs_blkdev block-id holding this block's 4 KiB · 0 = unallocated */
} sotfs_block_t;

typedef struct sotfs_graph {
    sotfs_inode_t inodes[SOTFS_MAX_INODES];
    sotfs_edge_t  edges[SOTFS_MAX_EDGES];
    sotfs_block_t blocks[SOTFS_MAX_BLOCKS];
    int           next_inode_hint;
    int           next_edge_hint;
    int           next_block_hint;
    int           root_id;
} sotfs_graph_t;

void sotfs_graph_init(sotfs_graph_t *g);
int  sotfs_alloc_inode(sotfs_graph_t *g, sotfs_inode_kind_t kind, uint32_t mode);
int  sotfs_alloc_edge(sotfs_graph_t *g, int parent_id, int child_id, const char *name);
int  sotfs_alloc_block(sotfs_graph_t *g, int file_id, uint32_t offset);
void sotfs_free_inode(sotfs_graph_t *g, int id);
/* POSIX delete-on-last-close support (defined in rewrite.c). */
void sotfs_free_file_storage(sotfs_graph_t *g, int file_id);  /* free inode + blocks */
void sotfs_inode_open (sotfs_graph_t *g, int file_id);        /* op_open  · ref++ */
void sotfs_inode_close(sotfs_graph_t *g, int file_id);        /* op_close · ref-- + orphan free */
void sotfs_free_edge(sotfs_graph_t *g, int id);
void sotfs_free_block(sotfs_graph_t *g, int id);
int  sotfs_find_edge(const sotfs_graph_t *g, int parent_id, const char *name);
int  sotfs_resolve_path(const sotfs_graph_t *g, const char *path);
/* Install-arc · resolve from an EXPLICIT root inode (per-mount roots: one
 * graph, distinct /tmp + /var + /usr-upper subtrees).  root_id<=0 → g->root_id. */
int  sotfs_resolve_path_from(const sotfs_graph_t *g, int root_id, const char *path);

#endif /* SOTFS_GRAPH_H */
