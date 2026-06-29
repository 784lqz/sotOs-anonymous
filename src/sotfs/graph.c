/*
 * sotOs · sotFS-α Phase 1 · DPO graph primitives
 *
 * Manages the in-memory DPO graph: Inodes, Edges, and Blocks.
 * Sizes per graph instance:
 *   - SOTFS_MAX_INODES  =  64 inodes
 *   - SOTFS_MAX_EDGES   = 128 edges
 *   - SOTFS_MAX_BLOCKS  =  16 blocks  (16 × 4096 = 64 KiB data)
 *
 * NOTE: sotfs_graph_t contains 64 KiB of block data.  Callers MUST
 * declare sotfs_graph_t as a local variable (NOT static / file-scope)
 * unless they explicitly accept the BSS/stack cost.
 */

#include <sotfs/graph.h>
#include <sotfs/blkdev.h>
#include <sotos/string.h>
#include <stddef.h>
#include <string.h>

/* ── helpers ──────────────────────────────────────────────────────────── */

static inline int
_inode_slot(const sotfs_graph_t *g, int id)
{
    /* id == slot index + 1 (0 is reserved for "free") */
    if (id <= 0 || id > SOTFS_MAX_INODES)
        return -1;
    return id - 1;
}

static inline int
_edge_slot(const sotfs_graph_t *g, int id)
{
    if (id <= 0 || id > SOTFS_MAX_EDGES)
        return -1;
    return id - 1;
}

static inline int
_block_slot(const sotfs_graph_t *g, int id)
{
    if (id <= 0 || id > SOTFS_MAX_BLOCKS)
        return -1;
    return id - 1;
}

/* ── graph_init ───────────────────────────────────────────────────────── */

void
sotfs_graph_init(sotfs_graph_t *g)
{
    int i;

    memset(g, 0, sizeof(*g));

    /* Mark all inodes free (id == 0 ↔ free) */
    for (i = 0; i < SOTFS_MAX_INODES; i++)
        g->inodes[i].id = 0;

    /* Mark all edges free */
    for (i = 0; i < SOTFS_MAX_EDGES; i++)
        g->edges[i].id = 0;

    /* Mark all blocks free */
    for (i = 0; i < SOTFS_MAX_BLOCKS; i++)
        g->blocks[i].id = 0;

    g->next_inode_hint = 0;
    g->next_edge_hint  = 0;
    g->next_block_hint = 0;

    /* Create the root directory inode (id = 1) */
    g->root_id = sotfs_alloc_inode(g, SOTFS_KIND_DIR, 0755);
}

/* ── sotfs_alloc_inode ───────────────────────────────────────────────── */

int
sotfs_alloc_inode(sotfs_graph_t *g, sotfs_inode_kind_t kind, uint32_t mode)
{
    int i, slot;

    for (i = 0; i < SOTFS_MAX_INODES; i++) {
        slot = (g->next_inode_hint + i) % SOTFS_MAX_INODES;
        if (g->inodes[slot].id == 0) {
            g->inodes[slot].id         = slot + 1;  /* 1-based id */
            g->inodes[slot].kind       = kind;
            g->inodes[slot].mode       = mode;
            g->inodes[slot].size       = 0;
            g->inodes[slot].generation = 0;
            g->inodes[slot].nlink      = (kind == SOTFS_KIND_DIR) ? 2 : 1;
            g->next_inode_hint = (slot + 1) % SOTFS_MAX_INODES;
            return g->inodes[slot].id;
        }
    }
    return 0;  /* 0 == no space */
}

/* ── sotfs_alloc_edge ────────────────────────────────────────────────── */

int
sotfs_alloc_edge(sotfs_graph_t *g, int parent_id, int child_id,
                 const char *name)
{
    int i, slot;

    for (i = 0; i < SOTFS_MAX_EDGES; i++) {
        slot = (g->next_edge_hint + i) % SOTFS_MAX_EDGES;
        if (g->edges[slot].id == 0) {
            g->edges[slot].id        = slot + 1;  /* 1-based id */
            g->edges[slot].parent_id = parent_id;
            g->edges[slot].child_id  = child_id;
            sotos_strlcpy(g->edges[slot].name, name, SOTFS_MAX_NAME);
            g->next_edge_hint = (slot + 1) % SOTFS_MAX_EDGES;
            return g->edges[slot].id;
        }
    }
    return 0;
}

/* ── sotfs_alloc_block ───────────────────────────────────────────────── */

int
sotfs_alloc_block(sotfs_graph_t *g, int file_id, uint32_t offset)
{
    int i, slot;

    for (i = 0; i < SOTFS_MAX_BLOCKS; i++) {
        slot = (g->next_block_hint + i) % SOTFS_MAX_BLOCKS;
        if (g->blocks[slot].id == 0) {
            int disk_blk = 0;

            /* Allocate the backing 4 KiB on the disk-backed store.  The store
             * is the data path now (blocks[].data is gone).  GUARD: if the
             * blkdev is uninitialised (sotfs_blk_total()==0 — a pre-init access
             * or a degraded boot, e.g. the on-stack selftest graph that never
             * inits the store), do NOT call sotfs_blk_alloc() into a dead store.
             * The mapping slot is claimed with disk_blk==0; io.c treats a
             * disk_blk==0 block as a sparse hole (reads zero, writes drop). */
            if (sotfs_blk_total() != 0) {
                disk_blk = sotfs_blk_alloc();   /* 0 on ENOSPC */
                if (disk_blk == 0)
                    return 0;                   /* ENOSPC · roll back: slot left free */
            }

            g->blocks[slot].id       = slot + 1;  /* 1-based id */
            g->blocks[slot].file_id  = file_id;
            g->blocks[slot].offset   = offset;
            g->blocks[slot].length   = 0;
            g->blocks[slot].disk_blk = disk_blk;
            g->next_block_hint = (slot + 1) % SOTFS_MAX_BLOCKS;
            return g->blocks[slot].id;
        }
    }
    return 0;
}

/* ── free helpers ────────────────────────────────────────────────────── */

void
sotfs_free_inode(sotfs_graph_t *g, int id)
{
    int slot = _inode_slot(g, id);
    if (slot >= 0)
        memset(&g->inodes[slot], 0, sizeof(sotfs_inode_t));
}

void
sotfs_free_edge(sotfs_graph_t *g, int id)
{
    int slot = _edge_slot(g, id);
    if (slot >= 0)
        memset(&g->edges[slot], 0, sizeof(sotfs_edge_t));
}

void
sotfs_free_block(sotfs_graph_t *g, int id)
{
    int slot = _block_slot(g, id);
    if (slot >= 0) {
        /* Release the backing disk block before clearing the mapping slot.
         * sotfs_blk_free is a no-op on 0/out-of-range, so an unbacked
         * (store-down) block frees cleanly too. */
        sotfs_blk_free(g->blocks[slot].disk_blk);
        memset(&g->blocks[slot], 0, sizeof(sotfs_block_t));
    }
}

/* ── sotfs_find_edge ─────────────────────────────────────────────────── */

int
sotfs_find_edge(const sotfs_graph_t *g, int parent_id, const char *name)
{
    int i;

    for (i = 0; i < SOTFS_MAX_EDGES; i++) {
        const sotfs_edge_t *e = &g->edges[i];
        if (e->id != 0 && e->parent_id == parent_id) {
            /* Compare using sotos_strlcpy semantics: names must match exactly */
            const char *en = e->name;
            const char *n  = name;
            /* simple strcmp-equivalent: compare up to SOTFS_MAX_NAME chars */
            int j = 0;
            while (j < SOTFS_MAX_NAME && en[j] == n[j] && en[j] != '\0')
                j++;
            if (j < SOTFS_MAX_NAME && en[j] == n[j])
                return e->id;
        }
    }
    return 0;  /* not found */
}

/* ── sotfs_resolve_path ──────────────────────────────────────────────── */

/*
 * Walks an absolute path (must start with '/') through the edge graph,
 * starting from an EXPLICIT root inode (install-arc · per-mount roots: one
 * shared graph, distinct top-level subtrees for /tmp, /var, the /usr upper).
 * Returns the inode id of the final component, or 0 on error.
 * Only handles absolute paths.  No symlink resolution.
 */
int
sotfs_resolve_path_from(const sotfs_graph_t *g, int root_id, const char *path)
{
    char component[SOTFS_MAX_NAME];
    int cur_id;
    const char *p;
    int edge_id, slot;

    if (!path || path[0] != '/')
        return 0;

    cur_id = (root_id > 0) ? root_id : g->root_id;
    p      = path + 1;  /* skip leading '/' */

    while (*p) {
        /* Extract next path component */
        int len = 0;
        while (p[len] != '/' && p[len] != '\0' && len < SOTFS_MAX_NAME - 1)
            len++;
        if (len == 0) {
            /* trailing slash or double slash: skip */
            if (*p == '/')
                p++;
            continue;
        }
        memcpy(component, p, (size_t)len);
        component[len] = '\0';
        p += len;
        if (*p == '/')
            p++;

        /* Look up component under cur_id */
        edge_id = sotfs_find_edge(g, cur_id, component);
        if (edge_id == 0)
            return 0;

        slot = _edge_slot(g, edge_id);
        if (slot < 0)
            return 0;
        cur_id = g->edges[slot].child_id;
    }

    return cur_id;
}

/* Resolve from the graph's default root (legacy callers).  Thin wrapper over
 * sotfs_resolve_path_from(g, g->root_id, path). */
int
sotfs_resolve_path(const sotfs_graph_t *g, const char *path)
{
    return sotfs_resolve_path_from(g, g ? g->root_id : 0, path);
}
