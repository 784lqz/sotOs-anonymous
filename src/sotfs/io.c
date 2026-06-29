/*
 * sotOs · sotFS-α Phase 1 · File IO helpers
 *
 * sotfs_file_write / sotfs_file_read operate at the block level.
 *
 * Sparse-zero semantics: unwritten regions of a file read as zero.
 * A block covers exactly SOTFS_BLOCK_SIZE (4096) bytes aligned to
 * SOTFS_BLOCK_SIZE boundaries.  A write that crosses a block boundary
 * allocates multiple blocks as needed.
 */

#include <sotfs/graph.h>
#include <sotfs/blkdev.h>
#include <sotfs/rewrite.h>
#include <stddef.h>
#include <string.h>

/* ── helpers ──────────────────────────────────────────────────────────── */

/* Return the block slot index for a given id, or -1 on invalid id. */
static inline int
_block_slot(int id)
{
    if (id <= 0 || id > SOTFS_MAX_BLOCKS)
        return -1;
    return id - 1;
}

/* Find the block for a given (file_id, aligned_offset), or 0 if absent. */
static int
_find_block(const sotfs_graph_t *g, int file_id, uint32_t aligned_offset)
{
    int i;
    for (i = 0; i < SOTFS_MAX_BLOCKS; i++) {
        const sotfs_block_t *b = &g->blocks[i];
        if (b->id != 0 && b->file_id == file_id &&
            b->offset == aligned_offset)
            return b->id;
    }
    return 0;
}

/* Find the inode slot for file_id, or -1 on error. */
static inline int
_inode_slot(int id)
{
    if (id <= 0 || id > SOTFS_MAX_INODES)
        return -1;
    return id - 1;
}

/* ── sotfs_file_write ────────────────────────────────────────────────── */

/*
 * Write len bytes from buf into file file_id at byte offset.
 * Allocates blocks as needed.  Returns number of bytes written on
 * success (== len), or a negative SOTFS_ERR_* code.
 */
int
sotfs_file_write(sotfs_graph_t *g, int file_id, uint32_t offset,
                   const uint8_t *buf, uint32_t len)
{
    int inode_slot;
    uint32_t written = 0;

    if (!buf || len == 0)
        return 0;

    /* Validate inode */
    inode_slot = _inode_slot(file_id);
    if (inode_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[inode_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[inode_slot].kind != SOTFS_KIND_FILE)
        return SOTFS_ERR_ISDIR;

    /* Original size BEFORE this write · a block at/beyond it is fresh territory
     * that cannot already exist → skip the O(n) _find_block scan, keeping a
     * sequential append (apt's 50 MiB cache write) O(1) per block, not O(n²)
     * once SOTFS_MAX_BLOCKS is large. */
    uint32_t orig_size = g->inodes[inode_slot].size;

    while (written < len) {
        uint32_t cur_off     = offset + written;
        uint32_t blk_off     = cur_off & ~(uint32_t)(SOTFS_BLOCK_SIZE - 1);
        uint32_t blk_intra   = cur_off - blk_off;
        uint32_t blk_remain  = SOTFS_BLOCK_SIZE - blk_intra;
        uint32_t chunk       = len - written;
        int      blk_id, blk_slot;

        if (chunk > blk_remain)
            chunk = blk_remain;

        /* Find or allocate the block (append past orig_size → skip the scan) */
        blk_id = (blk_off >= orig_size) ? 0 : _find_block(g, file_id, blk_off);
        if (blk_id == 0) {
            blk_id = sotfs_alloc_block(g, file_id, blk_off);
            if (blk_id == 0)
                return (written > 0) ? (int)written : SOTFS_ERR_NOSPACE;
        }

        blk_slot = _block_slot(blk_id);
        if (blk_slot < 0)
            return SOTFS_ERR_INVAL;

        /* Write chunk into block · read-modify-write through the disk store.
         * The 4 KiB data lives on sotfs_blkdev now, not in blocks[].data. */
        {
            uint8_t page[SOTFS_BLOCK_SIZE];
            int     disk = g->blocks[blk_slot].disk_blk;

            /* Load the current block contents.  A new/sparse block (disk==0 ·
             * store down) or a read miss reads back as zero, preserving the
             * bytes outside [blk_intra, blk_intra+chunk). */
            if (disk == 0 || sotfs_blk_read(disk, page) != 0)
                memset(page, 0, sizeof(page));

            memcpy(&page[blk_intra], buf + written, chunk);

            /* Persist · a no-op when the block is unbacked (store down): the
             * write silently drops, matching the sparse-hole/ENOSPC contract. */
            if (disk != 0)
                sotfs_blk_write(disk, page);
        }

        /* Update block length to cover the written region */
        {
            uint32_t end_intra = blk_intra + chunk;
            if (end_intra > g->blocks[blk_slot].length)
                g->blocks[blk_slot].length = end_intra;
        }

        written += chunk;
    }

    /* Update inode size */
    {
        uint32_t new_end = offset + len;
        if (new_end > g->inodes[inode_slot].size)
            g->inodes[inode_slot].size = new_end;
    }

    return (int)written;
}

/* ── sotfs_file_read ─────────────────────────────────────────────────── */

/*
 * Read up to len bytes from file file_id starting at byte offset into buf.
 * Unallocated regions (sparse holes) read as zero.
 * Returns number of bytes read (may be 0 if offset >= file size), or
 * a negative SOTFS_ERR_* code.
 */
int
sotfs_file_read(const sotfs_graph_t *g, int file_id, uint32_t offset,
                  uint8_t *buf, uint32_t len)
{
    int inode_slot;
    uint32_t file_size, read_len, done;

    if (!buf || len == 0)
        return 0;

    /* Validate inode */
    inode_slot = _inode_slot(file_id);
    if (inode_slot < 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[inode_slot].id == 0)
        return SOTFS_ERR_NOENT;
    if (g->inodes[inode_slot].kind != SOTFS_KIND_FILE)
        return SOTFS_ERR_ISDIR;

    file_size = g->inodes[inode_slot].size;

    /* Clamp to file size */
    if (offset >= file_size)
        return 0;
    read_len = file_size - offset;
    if (read_len > len)
        read_len = len;

    done = 0;
    while (done < read_len) {
        uint32_t cur_off    = offset + done;
        uint32_t blk_off    = cur_off & ~(uint32_t)(SOTFS_BLOCK_SIZE - 1);
        uint32_t blk_intra  = cur_off - blk_off;
        uint32_t blk_remain = SOTFS_BLOCK_SIZE - blk_intra;
        uint32_t chunk      = read_len - done;
        int      blk_id, blk_slot;

        if (chunk > blk_remain)
            chunk = blk_remain;

        blk_id = _find_block(g, file_id, blk_off);
        if (blk_id == 0) {
            /* Sparse hole: fill with zeros */
            memset(buf + done, 0, chunk);
        } else {
            uint8_t page[SOTFS_BLOCK_SIZE];
            int     disk;

            blk_slot = _block_slot(blk_id);
            if (blk_slot < 0)
                return SOTFS_ERR_INVAL;

            /* Read the 4 KiB from the disk store.  An unbacked block (disk==0 ·
             * store down) or a read miss reads back as zero — same as a sparse
             * hole. */
            disk = g->blocks[blk_slot].disk_blk;
            if (disk == 0 || sotfs_blk_read(disk, page) != 0)
                memset(page, 0, sizeof(page));

            memcpy(buf + done, &page[blk_intra], chunk);
        }

        done += chunk;
    }

    return (int)done;
}
