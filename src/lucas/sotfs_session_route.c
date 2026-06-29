/* Static `/` backend -> shared sotfs graph route for Tier-2 sessions (apk-fs P2).
 *
 * `/`-rooted base-misses ("/opt/x", "/root/newfile") that the static honey table
 * does not have are stored as FLAT files under one dedicated graph subtree
 * (root = sotfs_mount_make_root("root")), keyed "<session>:<path with / -> _>" so
 * two sessions never collide and a whole-tree create needs no mkdir -p.  Inodes
 * are tagged to the session + writes charged against the 32 MiB cap, and the
 * SAME lucas_sotfs_session_visible gate the sotfs ops use is applied here -- so
 * /opt/x is operator-invisible and reaped on disconnect exactly like a /usr/bin
 * install.  Thin layer over sotfs_rewrite_* + the Phase-1 API; no FS reimpl. */
#include <lucas/sotfs_session_route.h>
#include <lucas/sotfs_session.h>
#include <sotfs/graph.h>
#include <sotfs/rewrite.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>

extern sotfs_graph_t *backends_sotfs_get_graph(void);
extern int sotfs_mount_make_root(const char *name);

/* Depth separator for the flat key: a control byte that cannot appear in a real
 * Unix filename (only '/' and NUL are illegal; we pick US 0x1F).  Using it
 * instead of '_' makes "/opt/x" unambiguous vs a literal "/opt_x" and lets
 * filenames containing '_' list correctly under ls. */
#define ROUTE_SEP '\x1f'

static int g_root = 0;
static int route_root(void) {
    /* orch is single-threaded (guest syscalls serialize through the seL4 fault
     * loop), so this check-then-set lazy init needs no mutex. */
    if (g_root <= 0) g_root = sotfs_mount_make_root("tier2_routes");
    return g_root;
}

static int route_key(uint32_t session, const char *path, char *out, size_t cap) {
    int n = snprintf(out, cap, "%u:", (unsigned)session);
    if (n <= 0 || (size_t)n >= cap) return -1;
    size_t o = (size_t)n;
    for (const char *p = path; *p; p++) {
        if (o + 1 >= cap) return -1;
        out[o++] = (*p == '/') ? ROUTE_SEP : *p;
    }
    out[o] = '\0';
    return 0;
}

static int route_inode(uint32_t session, const char *path) {
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return 0;
    int root = route_root();
    if (root <= 0) return 0;
    char key[256], abspath[260];
    if (route_key(session, path, key, sizeof(key)) != 0) return 0;
    int m = snprintf(abspath, sizeof(abspath), "/%s", key);
    if (m <= 0 || (size_t)m >= sizeof(abspath)) return 0;
    return sotfs_resolve_path_from(g, root, abspath);
}

int lucas_sotfs_route_has(uint32_t session, const char *path) {
    if (session == 0 || !path) return 0;
    int id = route_inode(session, path);
    return id != 0 && lucas_sotfs_session_visible(id, session);
}

int lucas_sotfs_route_create(uint32_t session, const char *path, uint32_t mode) {
    if (session == 0 || !path || !*path) return -22;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return -28;
    int root = route_root();
    if (root <= 0) return -28;
    if (route_inode(session, path) != 0) return 0;     /* idempotent */
    char key[256];
    if (route_key(session, path, key, sizeof(key)) != 0) return -22;
    int rc = sotfs_rewrite_create_file(g, root, key, mode ? mode : 0644);
    if (rc <= 0) return -28;
    int id = route_inode(session, path);
    if (id == 0) return -5;
    lucas_sotfs_session_tag(id, session);
    return 0;
}

int lucas_sotfs_route_mkdir(uint32_t session, const char *path, uint32_t mode) {
    if (session == 0 || !path || !*path) return -22;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return -28;
    int root = route_root();
    if (root <= 0) return -28;
    if (route_inode(session, path) != 0) return -17;    /* -EEXIST */
    char key[256];
    if (route_key(session, path, key, sizeof(key)) != 0) return -22;
    int rc = sotfs_rewrite_mkdir(g, root, key, mode ? mode : 0755);
    if (rc <= 0) return -28;
    int id = route_inode(session, path);
    if (id == 0) return -5;
    lucas_sotfs_session_tag(id, session);
    return 0;
}

int64_t lucas_sotfs_route_write(uint32_t session, const char *path,
                                const void *buf, size_t count, int64_t cursor) {
    if (session == 0 || !path) return -22;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return -28;
    int id = route_inode(session, path);
    if (id == 0) {
        int rc = lucas_sotfs_route_create(session, path, 0644);
        if (rc != 0) return rc;
        id = route_inode(session, path);
        if (id == 0) return -5;
    }
    uint32_t old_size = (uint32_t)g->inodes[id - 1].size;
    uint64_t off64 = (cursor > 0) ? (uint64_t)cursor : 0;
    uint64_t end64 = off64 + (uint64_t)count;
    if (end64 > UINT32_MAX) return -28;
    uint32_t off = (uint32_t)off64;
    uint32_t end = (uint32_t)end64;
    if (end > old_size) {
        int crc = lucas_sotfs_session_charge(session, end - old_size);
        if (crc != 0) return (int64_t)crc;
    }
    int wr = sotfs_file_write(g, id, off, (const uint8_t *)buf, (uint32_t)count);
    if (wr < 0) return -28;
    return (int64_t)count;
}

int64_t lucas_sotfs_route_read(uint32_t session, const char *path,
                               void *buf, size_t count, int64_t cursor) {
    if (session == 0 || !path) return -22;
    if (!lucas_sotfs_route_has(session, path)) return -2;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return -2;
    int id = route_inode(session, path);
    if (id == 0) return -2;
    uint32_t size = (uint32_t)g->inodes[id - 1].size;
    uint32_t off = (cursor > 0) ? (uint32_t)cursor : 0;
    if (off >= size) return 0;
    uint32_t want = (count < (size_t)(size - off)) ? (uint32_t)count : (size - off);
    int rd = sotfs_file_read(g, id, off, (uint8_t *)buf, want);
    if (rd < 0) return -2;
    return (int64_t)rd;
}

int lucas_sotfs_route_stat(uint32_t session, const char *path, struct lx_stat *out) {
    if (session == 0 || !path || !out) return -2;
    if (!lucas_sotfs_route_has(session, path)) return -2;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return -2;
    int id = route_inode(session, path);
    if (id == 0) return -2;
    sotfs_inode_t *in = &g->inodes[id - 1];
    memset(out, 0, sizeof(*out));
    /* struct lx_stat field names confirmed from include/lucas/vfs.h:
     * st_mode (uint32_t), st_size (int64_t), st_blksize (int64_t),
     * st_blocks (int64_t), st_nlink (uint64_t), st_dev (uint64_t),
     * st_ino (uint64_t), st_mtime (uint64_t), st_atime (uint64_t),
     * st_ctime (uint64_t) — all direct fields, no nested tv_sec. */
    out->st_mode    = in->mode ? in->mode : 0100644u;
    out->st_size    = (int64_t)in->size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)in->size + 511) / 512;
    out->st_nlink   = 1;
    out->st_dev     = 1;
    out->st_ino     = (uint64_t)id + 300000u;
    out->st_mtime   = (uint64_t)in->mtime_sec;
    out->st_atime   = (uint64_t)in->atime_sec;
    out->st_ctime   = (uint64_t)in->ctime_sec;
    return 0;
}

int lucas_sotfs_route_unlink(uint32_t session, const char *path) {
    if (session == 0 || !path) return -2;
    if (!lucas_sotfs_route_has(session, path)) return -2;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return -2;
    int root = route_root();
    char key[256];
    if (route_key(session, path, key, sizeof(key)) != 0) return -2;
    int id = route_inode(session, path);
    uint32_t freed = (id > 0) ? (uint32_t)g->inodes[id - 1].size : 0;
    int rc = sotfs_rewrite_unlink(g, root, key);
    if (rc != 0) return -2;
    if (id > 0) lucas_sotfs_session_tag(id, 0);
    if (freed) lucas_sotfs_session_uncharge(session, freed);
    return 0;
}

int lucas_sotfs_route_list_children(uint32_t session, const char *dirpath,
                                    char names[][32], uint8_t *types,
                                    int have, int max) {
    if (session == 0 || !dirpath) return have;
    sotfs_graph_t *g = backends_sotfs_get_graph();
    if (!g) return have;
    int root = route_root();
    if (root <= 0) return have;
    char pfx[256];
    if (route_key(session, dirpath, pfx, sizeof(pfx)) != 0) return have;
    size_t plen = strlen(pfx);
    int dir_is_root = (dirpath[0] == '/' && dirpath[1] == '\0');
    int count = have;
    for (int e = 0; e < SOTFS_MAX_EDGES && count < max; e++) {
        if (g->edges[e].id == 0) continue;
        if (g->edges[e].parent_id != root) continue;
        int child = g->edges[e].child_id;
        if (child <= 0) continue;
        if (!lucas_sotfs_session_visible(child, session)) continue;
        const char *nm = g->edges[e].name;
        size_t nlen = strlen(nm);
        if (nlen <= plen || strncmp(nm, pfx, plen) != 0) continue;
        const char *rest;
        if (dir_is_root) rest = nm + plen;          /* pfx for "/" already ends in ROUTE_SEP */
        else { if (nm[plen] != ROUTE_SEP) continue; rest = nm + plen + 1; }
        if (*rest == '\0' || strchr(rest, ROUTE_SEP) != NULL) continue;  /* direct child only */
        int dup = 0;
        for (int i = 0; i < count; i++)
            if (strncmp(names[i], rest, 31) == 0) { dup = 1; break; }
        if (dup) continue;
        strncpy(names[count], rest, 31); names[count][31] = '\0';
        types[count] = ((g->inodes[child - 1].mode & 0170000u) == 040000u) ? 4 : 8;
        count++;
    }
    return count;
}
