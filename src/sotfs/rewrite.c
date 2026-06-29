/*
 * sotOs · sotFS-α Phase 1 · DPO rewrite rules
 *
 * Each function implements one DPO rewrite rule.  Function header
 * comments document the rule as a span L←K→R + NACs (Negative
 * Application Conditions).
 *
 * All rewrites are all-or-nothing: if any allocation after the
 * first fails, the prior allocations are freed before returning
 * an error code.
 */

#include <sotfs/graph.h>
#include <sotfs/rewrite.h>
#include <sotos/string.h>
#include <stddef.h>
#include <string.h>

/* ── internal helpers ────────────────────────────────────────────────── */

/* Return the inode slot index for id, or -1 on invalid id. */
static inline int
_inode_slot(int id)
{
    if (id <= 0 || id > SOTFS_MAX_INODES)
        return -1;
    return id - 1;
}

/* Return the edge slot index for id, or -1 on invalid id. */
static inline int
_edge_slot(int id)
{
    if (id <= 0 || id > SOTFS_MAX_EDGES)
        return -1;
    return id - 1;
}

/* Check whether a directory inode has any children (for rmdir). */
static int
_dir_has_children(const sotfs_graph_t *g, int dir_id)
{
    int i;
    for (i = 0; i < SOTFS_MAX_EDGES; i++) {
        if (g->edges[i].id != 0 && g->edges[i].parent_id == dir_id)
            return 1;
    }
    return 0;
}

/* ── sotfs_rewrite_create_file ───────────────────────────────────────── */

/* DPO: create_file(p, name, mode)
 *   L = { p: Inode(kind=dir) }
 *   K = { p }
 *   R = { p, f: Inode(kind=file, mode), e: child(p, name, f) }
 *   NAC: no existing child(p, name, _).
 */
int
sotfs_rewrite_create_file(sotfs_graph_t *g, int parent_id,
                            const char *name, uint32_t mode)
{
    int parent_slot;
    int file_id, edge_id;

    /* Validate name length */
    if (!name || name[0] == '\0')
        return SOTFS_ERR_INVAL;
    if (strlen(name) >= SOTFS_MAX_NAME)
        return SOTFS_ERR_NAMETOOLONG;

    /* L: parent must be a directory */
    parent_slot = _inode_slot(parent_id);
    if (parent_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* NAC: no existing child with this name */
    if (sotfs_find_edge(g, parent_id, name) != 0)
        return SOTFS_ERR_EXISTS;

    /* R: allocate inode for the new file */
    file_id = sotfs_alloc_inode(g, SOTFS_KIND_FILE, mode);
    if (file_id == 0)
        return SOTFS_ERR_NOSPACE;

    /* R: allocate edge child(p, name, f) */
    edge_id = sotfs_alloc_edge(g, parent_id, file_id, name);
    if (edge_id == 0) {
        /* all-or-nothing: roll back inode */
        sotfs_free_inode(g, file_id);
        return SOTFS_ERR_NOSPACE;
    }

    return file_id;  /* positive: new inode id */
}

/* ── sotfs_rewrite_mkdir ─────────────────────────────────────────────── */

/* DPO: mkdir(p, name, mode)
 *   L = { p: Inode(kind=dir) }
 *   K = { p }
 *   R = { p, d: Inode(kind=dir, mode), e: child(p, name, d) }
 *   NAC: no existing child(p, name, _).
 */
int
sotfs_rewrite_mkdir(sotfs_graph_t *g, int parent_id,
                      const char *name, uint32_t mode)
{
    int parent_slot;
    int dir_id, edge_id;

    /* Validate name length */
    if (!name || name[0] == '\0')
        return SOTFS_ERR_INVAL;
    if (strlen(name) >= SOTFS_MAX_NAME)
        return SOTFS_ERR_NAMETOOLONG;

    /* L: parent must be a directory */
    parent_slot = _inode_slot(parent_id);
    if (parent_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* NAC: no existing child with this name */
    if (sotfs_find_edge(g, parent_id, name) != 0)
        return SOTFS_ERR_EXISTS;

    /* R: allocate inode for the new directory */
    dir_id = sotfs_alloc_inode(g, SOTFS_KIND_DIR, mode);
    if (dir_id == 0)
        return SOTFS_ERR_NOSPACE;

    /* R: allocate edge child(p, name, d) */
    edge_id = sotfs_alloc_edge(g, parent_id, dir_id, name);
    if (edge_id == 0) {
        /* all-or-nothing: roll back inode */
        sotfs_free_inode(g, dir_id);
        return SOTFS_ERR_NOSPACE;
    }

    return dir_id;  /* positive: new inode id */
}

/* ── sotfs_rewrite_unlink ────────────────────────────────────────────── */

/* DPO: unlink(p, name)
 *   L = { p: Inode(kind=dir), e: child(p, name, f), f: Inode(kind=file) }
 *   K = { p }
 *   R = { p }       (e and f are deleted)
 *   NAC: none (hard-link count handled via nlink; inode freed when nlink==0).
 */
int
sotfs_rewrite_unlink(sotfs_graph_t *g, int parent_id, const char *name)
{
    int parent_slot, edge_id, edge_slot, child_id, child_slot;

    /* Validate name */
    if (!name || name[0] == '\0')
        return SOTFS_ERR_INVAL;

    /* L: parent must be a directory */
    parent_slot = _inode_slot(parent_id);
    if (parent_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* L: edge must exist */
    edge_id = sotfs_find_edge(g, parent_id, name);
    if (edge_id == 0)
        return SOTFS_ERR_NOENT;

    edge_slot = _edge_slot(edge_id);
    if (edge_slot < 0)
        return SOTFS_ERR_INVAL;

    child_id   = g->edges[edge_slot].child_id;
    child_slot = _inode_slot(child_id);
    if (child_slot < 0)
        return SOTFS_ERR_INVAL;

    /* L: child must be a file (not a directory) */
    if (g->inodes[child_slot].kind == SOTFS_KIND_DIR)
        return SOTFS_ERR_ISDIR;

    /* R: free the edge */
    sotfs_free_edge(g, edge_id);

    /* R: decrement nlink; free inode when nlink reaches 0 — UNLESS a handle is
     * still open (POSIX delete-on-last-close).  apt/gpgv create a temp, open it,
     * unlink it (anonymous), then write+read via the open fd; freeing the inode
     * here made that write fail SOTFS_ERR_NOENT (which backends_sotfs mis-mapped
     * to ENOSPC) → InRelease verification broke → empty cache.  Defer: mark the
     * inode orphan, keep its blocks; the last sotfs_inode_close frees it. */
    g->inodes[child_slot].nlink--;
    if (g->inodes[child_slot].nlink <= 0) {
        if (g->inodes[child_slot].open_count > 0) {
            g->inodes[child_slot].orphan = 1;   /* free deferred to last close */
        } else {
            sotfs_free_file_storage(g, child_id);
        }
    }

    return SOTFS_OK;
}

/* Free a file inode + all its blocks.  Shared by unlink (nlink==0, no open fd)
 * and sotfs_inode_close (last close of an orphan).  Idempotent on an already-
 * free inode. */
void sotfs_free_file_storage(sotfs_graph_t *g, int file_id)
{
    int slot = _inode_slot(file_id);
    if (slot < 0 || g->inodes[slot].id == 0) return;
    for (int i = 0; i < SOTFS_MAX_BLOCKS; i++) {
        if (g->blocks[i].id != 0 && g->blocks[i].file_id == file_id)
            memset(&g->blocks[i], 0, sizeof(sotfs_block_t));
    }
    sotfs_free_inode(g, file_id);
}

/* Reference an inode on backend op_open (one per live handle). */
void sotfs_inode_open(sotfs_graph_t *g, int file_id)
{
    int slot = _inode_slot(file_id);
    if (slot < 0 || g->inodes[slot].id == 0) return;
    if (g->inodes[slot].open_count < 255) g->inodes[slot].open_count++;
}

/* Release an inode on backend op_close.  If it was unlinked while open (orphan)
 * and this was the last handle, free its storage now (delete-on-last-close). */
void sotfs_inode_close(sotfs_graph_t *g, int file_id)
{
    int slot = _inode_slot(file_id);
    if (slot < 0 || g->inodes[slot].id == 0) return;
    if (g->inodes[slot].open_count > 0) g->inodes[slot].open_count--;
    if (g->inodes[slot].open_count == 0 && g->inodes[slot].orphan)
        sotfs_free_file_storage(g, file_id);
}

/* ── sotfs_rewrite_rmdir ─────────────────────────────────────────────── */

/* DPO: rmdir(p, name)
 *   L = { p: Inode(kind=dir), e: child(p, name, d), d: Inode(kind=dir) }
 *   K = { p }
 *   R = { p }       (e and d are deleted)
 *   NAC: d has no children (directory must be empty).
 */
int
sotfs_rewrite_rmdir(sotfs_graph_t *g, int parent_id, const char *name)
{
    int parent_slot, edge_id, edge_slot, child_id, child_slot;

    /* Validate name */
    if (!name || name[0] == '\0')
        return SOTFS_ERR_INVAL;

    /* L: parent must be a directory */
    parent_slot = _inode_slot(parent_id);
    if (parent_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[parent_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* L: edge must exist */
    edge_id = sotfs_find_edge(g, parent_id, name);
    if (edge_id == 0)
        return SOTFS_ERR_NOENT;

    edge_slot = _edge_slot(edge_id);
    if (edge_slot < 0)
        return SOTFS_ERR_INVAL;

    child_id   = g->edges[edge_slot].child_id;
    child_slot = _inode_slot(child_id);
    if (child_slot < 0)
        return SOTFS_ERR_INVAL;

    /* L: child must be a directory */
    if (g->inodes[child_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* NAC: directory must be empty */
    if (_dir_has_children(g, child_id))
        return SOTFS_ERR_NOTEMPTY;

    /* R: free the edge and the inode */
    sotfs_free_edge(g, edge_id);
    sotfs_free_inode(g, child_id);

    return SOTFS_OK;
}

/* ── sotfs_rewrite_rename ────────────────────────────────────────────── */

/* DPO: rename(p_src, old_name, p_dst, new_name)
 *   L = { p_src: Inode(kind=dir), e_old: child(p_src, old_name, n),
 *          p_dst: Inode(kind=dir) }
 *   K = { p_src, p_dst, n }
 *   R = { p_src, p_dst, n, e_new: child(p_dst, new_name, n) }
 *          (e_old is deleted; e_new is created)
 *   NAC: no existing child(p_dst, new_name, _)  [clobber not supported].
 */
int
sotfs_rewrite_rename(sotfs_graph_t *g, int p_src, const char *old_name,
                       int p_dst, const char *new_name)
{
    int p_src_slot, p_dst_slot;
    int old_edge_id, old_edge_slot, child_id;
    int new_edge_id;

    /* Validate names */
    if (!old_name || old_name[0] == '\0')
        return SOTFS_ERR_INVAL;
    if (!new_name || new_name[0] == '\0')
        return SOTFS_ERR_INVAL;
    if (strlen(old_name) >= SOTFS_MAX_NAME)
        return SOTFS_ERR_NAMETOOLONG;
    if (strlen(new_name) >= SOTFS_MAX_NAME)
        return SOTFS_ERR_NAMETOOLONG;

    /* L: p_src must be a directory */
    p_src_slot = _inode_slot(p_src);
    if (p_src_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[p_src_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[p_src_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* L: p_dst must be a directory */
    p_dst_slot = _inode_slot(p_dst);
    if (p_dst_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[p_dst_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[p_dst_slot].kind != SOTFS_KIND_DIR)
        return SOTFS_ERR_NOTDIR;

    /* L: old edge must exist */
    old_edge_id = sotfs_find_edge(g, p_src, old_name);
    if (old_edge_id == 0)
        return SOTFS_ERR_NOENT;

    old_edge_slot = _edge_slot(old_edge_id);
    if (old_edge_slot < 0)
        return SOTFS_ERR_INVAL;

    child_id = g->edges[old_edge_slot].child_id;

    /* NAC: no existing child(p_dst, new_name, _) */
    if (sotfs_find_edge(g, p_dst, new_name) != 0)
        return SOTFS_ERR_EXISTS;

    /* R: allocate new edge child(p_dst, new_name, n) */
    new_edge_id = sotfs_alloc_edge(g, p_dst, child_id, new_name);
    if (new_edge_id == 0)
        return SOTFS_ERR_NOSPACE;

    /* R: free old edge (all-or-nothing: new edge already allocated above) */
    sotfs_free_edge(g, old_edge_id);

    return SOTFS_OK;
}
