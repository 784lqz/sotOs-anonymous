/*
 * sotOs · sotFS-α Phase 1 · Self-test
 *
 * sotfs_selftest() · 9 checks covering graph primitives and all 5 DPO
 * rewrites plus file IO.
 *
 * IMPORTANT: sotfs_graph_t is stack-local here (~70 KiB on the stack).
 * This is intentional: a static or file-scope instance would add 64+ KiB
 * to BSS, which would hurt the CPIO image size budget.  The selftest
 * function itself is safe to call from any context with sufficient stack
 * (kernel threads, test binaries, etc.).
 *
 * Phase 1 status: this function is CALLABLE but NOT CALLED from anywhere.
 * Phase 2 will wire it in when sotFS is mounted as a LUCAS VFS backend.
 */

#include <sotfs/graph.h>
#include <sotfs/rewrite.h>
#include <sotfs/selftest.h>
#include <stddef.h>
#include <string.h>

/* Simple assertion macro: on failure, spins forever so a debugger can catch
 * it.  We do not have a printf here · we're a static library with no I/O
 * dependency.  Phase 2 can wire in seL4_DebugPutChar if desired. */
#define SOTFS_ASSERT(cond)  \
    do {                    \
        if (!(cond)) {      \
            /* assertion failed · spin for debugger attach */   \
            volatile int _spin = 1;                             \
            while (_spin) { (void)_spin; }                      \
        }                   \
    } while (0)

void
sotfs_selftest(void)
{
    /*
     * Stack-local graph · ~70 KiB.  Do NOT make this static or global.
     * See file header comment for rationale.
     */
    sotfs_graph_t g;
    int root_id, dir_id, file_id, ret;
    uint8_t wbuf[16], rbuf[16];

    /* ── Check 1: graph_init creates a valid root directory ─────────── */
    sotfs_graph_init(&g);
    root_id = g.root_id;
    SOTFS_ASSERT(root_id > 0);
    SOTFS_ASSERT(g.inodes[root_id - 1].kind == SOTFS_KIND_DIR);
    SOTFS_ASSERT(g.inodes[root_id - 1].id   == root_id);

    /* ── Check 2: mkdir creates a subdirectory ───────────────────────── */
    dir_id = sotfs_rewrite_mkdir(&g, root_id, "etc", 0755);
    SOTFS_ASSERT(dir_id > 0);
    SOTFS_ASSERT(g.inodes[dir_id - 1].kind == SOTFS_KIND_DIR);
    /* find_edge must locate the new entry */
    SOTFS_ASSERT(sotfs_find_edge(&g, root_id, "etc") != 0);

    /* ── Check 3: mkdir NAC · duplicate name returns ERR_EXISTS ─────── */
    ret = sotfs_rewrite_mkdir(&g, root_id, "etc", 0755);
    SOTFS_ASSERT(ret == SOTFS_ERR_EXISTS);

    /* ── Check 4: create_file creates a file under /etc ─────────────── */
    file_id = sotfs_rewrite_create_file(&g, dir_id, "passwd", 0644);
    SOTFS_ASSERT(file_id > 0);
    SOTFS_ASSERT(g.inodes[file_id - 1].kind == SOTFS_KIND_FILE);
    SOTFS_ASSERT(sotfs_find_edge(&g, dir_id, "passwd") != 0);

    /* ── Check 5: file_write / file_read round-trip ──────────────────── */
    memset(wbuf, 0xAB, sizeof(wbuf));
    ret = sotfs_file_write(&g, file_id, 0, wbuf, sizeof(wbuf));
    SOTFS_ASSERT(ret == (int)sizeof(wbuf));

    memset(rbuf, 0, sizeof(rbuf));
    ret = sotfs_file_read(&g, file_id, 0, rbuf, sizeof(rbuf));
    SOTFS_ASSERT(ret == (int)sizeof(rbuf));
    SOTFS_ASSERT(memcmp(wbuf, rbuf, sizeof(wbuf)) == 0);

    /* ── Check 6: unlink removes the file ────────────────────────────── */
    ret = sotfs_rewrite_unlink(&g, dir_id, "passwd");
    SOTFS_ASSERT(ret == SOTFS_OK);
    /* Edge must be gone */
    SOTFS_ASSERT(sotfs_find_edge(&g, dir_id, "passwd") == 0);

    /* ── Check 7: unlink non-existent returns ERR_NOENT ─────────────── */
    ret = sotfs_rewrite_unlink(&g, dir_id, "passwd");
    SOTFS_ASSERT(ret == SOTFS_ERR_NOENT);

    /* ── Check 8: rmdir fails on non-empty directory ─────────────────── */
    /* Create a file in /etc first */
    file_id = sotfs_rewrite_create_file(&g, dir_id, "hosts", 0644);
    SOTFS_ASSERT(file_id > 0);
    ret = sotfs_rewrite_rmdir(&g, root_id, "etc");
    SOTFS_ASSERT(ret == SOTFS_ERR_NOTEMPTY);
    /* Remove the file, then rmdir succeeds */
    ret = sotfs_rewrite_unlink(&g, dir_id, "hosts");
    SOTFS_ASSERT(ret == SOTFS_OK);
    ret = sotfs_rewrite_rmdir(&g, root_id, "etc");
    SOTFS_ASSERT(ret == SOTFS_OK);
    SOTFS_ASSERT(sotfs_find_edge(&g, root_id, "etc") == 0);

    /* ── Check 9: rename moves an entry ──────────────────────────────── */
    /* Create /var and /var/log, then rename /var/log to /var/logs */
    {
        int var_id, log_id, rename_ret;
        var_id = sotfs_rewrite_mkdir(&g, root_id, "var", 0755);
        SOTFS_ASSERT(var_id > 0);
        log_id = sotfs_rewrite_mkdir(&g, var_id, "log", 0755);
        SOTFS_ASSERT(log_id > 0);

        rename_ret = sotfs_rewrite_rename(&g, var_id, "log",
                                            var_id, "logs");
        SOTFS_ASSERT(rename_ret == SOTFS_OK);
        /* Old name gone, new name present, same inode */
        SOTFS_ASSERT(sotfs_find_edge(&g, var_id, "log")  == 0);
        SOTFS_ASSERT(sotfs_find_edge(&g, var_id, "logs") != 0);
        /* Inode still valid */
        SOTFS_ASSERT(g.inodes[log_id - 1].kind == SOTFS_KIND_DIR);
    }

    /* All 9 checks passed · function returns normally. */
}
