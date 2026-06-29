/* /usr overlay backend · the seL4 vfs_ops (P1.2).
 *
 * Composes two layers as a single mount:
 *   UPPER = a writable subtree of the disk-backed sotfs graph (root = the inode
 *           from sotfs_mount_make_root("usr")), reached via the public sotfs vfs_ops.
 *   BASE  = the read-only sysroot backend (the baked /usr tree).
 *
 * Overlay semantics:
 *   - read/stat: upper-first (or whiteout → absent), else base-fallback.
 *   - write/create/mkdir/unlink/rename: the UPPER.  Removing a base-only path
 *     writes a 0-byte ".wh.<name>" whiteout marker in the upper (base never moves).
 *   - getdents: merge upper + base (upper shadows base names; whiteouts hide base;
 *     ".wh.*" markers are filtered out).
 *
 * The PURE decision core (union_resolve_layer) lives in backends_union.c (host-
 * tested).  This TU holds the seL4-side ops + the per-open handle wrapper.
 *
 * Documented deferrals (the first install slice — `hello` — needs none of these):
 *   - copy-up: modifying a BASE-only file WITHOUT O_CREAT is not yet supported
 *     (open returns -EROFS).  dpkg's unpack creates NEW files in the upper.
 *   - cross-layer rename and the getdents merge cap (UNION_GD_MAX) are bounded.
 */
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include <lucas/vfs.h>
#include <lucas/sotfs_mount.h>
#include <lucas/backends_sysroot.h>
#include <lucas/backends_union.h>
#include <lucas/apk_basedb.h>   /* xxd-generated · Alpine 3.20 base installed-DB (apk-network-install T1/C2) */
#include <sotfs/graph.h>   /* SOTFS_MAX_NAME */

/* The sotfs ops table accessor (the table is static in backends_sotfs.c). */
extern const vfs_ops_t *lucas_sotfs_ops(void);

/* persona-coherence · hide the glibc multiarch dir from the Alpine honey
 * session's directory listings (getdents merge).  In union_drain_layer the
 * `void *st` param is the BACKEND state, NOT the caller — use the thread-local
 * current caller (lucas_get_current_caller) to read its cow_session. */
struct lucas_state;
extern struct lucas_state *lucas_get_current_caller(void);
extern bool lucas_persona_hides(const struct lucas_state *st, const char *path);
/* Idempotent: create top-level subtree `name` under the graph root, return its inode. */
extern int sotfs_mount_make_root(const char *name);
/* Static `/` honey table · the /usr-union's last-resort fallback layer. */
extern const vfs_ops_t vfs_static_ops;
extern void *vfs_static_state(void);

#define O_CREAT_BIT   0x40
#define O_WRONLY_BIT  1
#define O_RDWR_BIT    2
#define UNION_GD_MAX  96      /* merged-dirent buffer cap per open dir handle */
/* Concurrent overlay handles.  Sized to MATCH the wrapped base (sysroot) pool
 * SYSROOT_MAX_HANDLES (128) — every /usr open consumes one union handle PLUS a
 * base sub-handle, so a union pool smaller than the base makes the union the
 * bottleneck.  This pool is process-global, and a Tier-2 sotbox reaped via
 * arena-revoke ([p2a] destroy) is torn down WITHOUT walking its fd table, so its
 * open handles are never u_close'd — they leak.  At 12 slots that leak exhausted
 * the pool after ~2 dynamic-binary lifecycles (vim/dpkg/hello load several .so's
 * each from /usr/lib), and the NEXT dynamic exec's ld couldn't open its libs →
 * the process exited 127 at loader startup (the tui-gate Phase-C regression).
 * 128 restores the pre-overlay sysroot-mount headroom.  FOLLOW-UP: close VFS
 * handles on Tier-2 reap to bound the leak for very long-lived sessions. */
#define UNION_HPOOL   256   /* 128 -> 256 · `apt install` fans out many concurrent
                             * /usr-lib consumers (apt + forked http/gpgv/store methods,
                             * each mmapping ~20 .so's = one union handle apiece) and the
                             * reap-leak above compounds it → the union pool exhausted at
                             * 128 while the deduped sysroot pool sat at ~96, EMFILE'ing
                             * the method's ld.so (Error 24 loading libsystemd.so.0). */

typedef struct {
    sotfs_mount_t    upper;       /* {root_id, label="usr"/"etc"} */
    const vfs_ops_t *upper_ops;   /* lucas_sotfs_ops() */
    const vfs_ops_t *base_ops;    /* base layer ops (sysroot for /usr, static-view for /etc) */
    void            *base_state;  /* base layer backend_state */
    /* Per-instance latency flag (was the /usr-only global g_usr_upper_dirty): the
     * upper starts EMPTY → reads/stats/getdents go straight to the base with zero
     * upper probes; the first upper mutation flips it on.  Per-instance so a /etc
     * union and the /usr union don't share (slow-)path state. */
    int              upper_dirty;
    /* Static-table fallback prefix ("/usr") for paths absent from BOTH layers —
     * the /usr base is the sysroot, which lacks the static /usr/bin tool stubs
     * (dpkg-deb, rm, …) that dpkg's access(X_OK) probes.  NULL → no fallback
     * (the /etc base IS the static honey, so its base already serves them). */
    const char      *static_fallback;
} union_state_t;

static int union_static_fallback_open(union_state_t *us, const char *suffix,
                                      int flags, uint32_t mode, void **out_sub);

typedef struct {
    bool             in_use;
    union_layer_t    layer;       /* which layer `sub` belongs to */
    void            *sub;         /* sub-handle from the tagged layer */
    /* getdents merge state (only used for directory handles): */
    int              gd_built;    /* 0 = not yet enumerated, 1 = buffered */
    int              gd_count;
    int              gd_idx;      /* emit cursor into the buffer */
    char             gd_dirpath[256];   /* mount-relative dir path (for the merge) */
    char             gd_names[UNION_GD_MAX][SOTFS_MAX_NAME];
    uint8_t          gd_types[UNION_GD_MAX];
} union_handle_t;

static union_handle_t g_uhandles[UNION_HPOOL];

static union_handle_t *union_handle_alloc(void)
{
    for (int i = 0; i < UNION_HPOOL; i++) {
        if (!g_uhandles[i].in_use) {
            memset(&g_uhandles[i], 0, sizeof(g_uhandles[i]));
            g_uhandles[i].in_use = true;
            return &g_uhandles[i];
        }
    }
    return NULL;
}

/* whiteout marker path for `path`: dir + "/.wh." + leaf.  Returns 0 on success. */
static int union_whiteout_path(const char *path, char *out, size_t cap)
{
    const char *slash = strrchr(path, '/');
    if (!slash) return -1;
    const char *leaf = slash + 1;
    size_t dlen = (size_t)(slash - path);   /* dir part, may be 0 for "/leaf" */
    if (dlen + 5 + strlen(leaf) + 1 >= cap) return -1;
    memcpy(out, path, dlen);
    out[dlen] = '\0';
    /* out = "<dir>/.wh.<leaf>" */
    snprintf(out + dlen, cap - dlen, "/.wh.%s", leaf);
    return 0;
}

static int union_upper_has(union_state_t *us, const char *path)
{
    struct lx_stat st;
    return us->upper_ops->stat(&us->upper, path, &st) == 0;
}
static int union_upper_whiteout(union_state_t *us, const char *path)
{
    char wp[SOTFS_MAX_NAME + 128];
    if (union_whiteout_path(path, wp, sizeof(wp)) != 0) return 0;
    struct lx_stat st;
    return us->upper_ops->stat(&us->upper, wp, &st) == 0;
}
static int union_base_has(union_state_t *us, const char *path)
{
    struct lx_stat st;
    return us->base_ops->stat(us->base_state, path, &st) == 0;
}

/* mkdir -p the PARENT directory chain of `path` in the upper (idempotent). */
static void union_upper_mkparents(union_state_t *us, const char *path)
{
    if (!us->upper_ops->mkdir) return;
    char cur[SOTFS_MAX_NAME * 4];
    const char *slash = strrchr(path, '/');
    if (!slash || slash == path) return;              /* parent is the mount root */
    size_t plen = (size_t)(slash - path);
    if (plen >= sizeof(cur)) return;
    memcpy(cur, path, plen); cur[plen] = '\0';
    /* walk "/a/b/c" creating "/a","/a/b","/a/b/c" */
    char acc[SOTFS_MAX_NAME * 4]; size_t al = 0; acc[0] = '\0';
    const char *p = cur; if (*p == '/') p++;
    while (*p) {
        const char *seg = p;
        while (*p && *p != '/') p++;
        size_t sl = (size_t)(p - seg);
        if (sl == 0) { if (*p == '/') p++; continue; }
        if (al + 1 + sl + 1 >= sizeof(acc)) return;
        acc[al++] = '/'; memcpy(acc + al, seg, sl); al += sl; acc[al] = '\0';
        us->upper_ops->mkdir(&us->upper, acc, 0755);  /* -EEXIST ignored */
        if (*p == '/') p++;
    }
}

/* ── vfs_ops ──────────────────────────────────────────────────────────── */

static int u_open(void *backend, const char *path, int flags, uint32_t mode,
                  void **out_handle)
{
    union_state_t *us = backend;
    int write_intent = (flags & O_CREAT_BIT) ||
                       (flags & O_WRONLY_BIT) || (flags & O_RDWR_BIT);

    union_handle_t *uh = union_handle_alloc();
    if (!uh) return -24; /* -EMFILE */
    strncpy(uh->gd_dirpath, path ? path : "/", sizeof(uh->gd_dirpath) - 1);
    uh->gd_dirpath[sizeof(uh->gd_dirpath) - 1] = '\0';

    if (write_intent) {
        /* All writes target the UPPER → the upper is now non-empty: enable the
         * full overlay resolution for subsequent reads/stats. */
        us->upper_dirty = 1;
        if (flags & O_CREAT_BIT) {
            /* a NEW file in the upper · ensure the parent dirs exist there, and
             * clear any whiteout that hid the (base) name. */
            union_upper_mkparents(us, path);
            if (union_upper_whiteout(us, path)) {
                char wp[SOTFS_MAX_NAME + 128];
                if (union_whiteout_path(path, wp, sizeof(wp)) == 0 && us->upper_ops->unlink)
                    us->upper_ops->unlink(&us->upper, wp);
            }
        } else if (!union_upper_has(us, path)) {
            /* modify a base-only file without O_CREAT · copy-up not yet supported. */
            uh->in_use = false;
            return -30; /* -EROFS · documented deferral */
        }
        void *sub = NULL;
        int rc = us->upper_ops->open(&us->upper, path, flags, mode, &sub);
        if (rc != 0) { uh->in_use = false; return rc; }
        uh->layer = UNION_UPPER; uh->sub = sub;
        *out_handle = uh;
        return 0;
    }

    /* read-intent.  FAST PATH: while the upper is empty (no install yet), go
     * straight to the base — zero upper probes (identical cost to the old
     * sysroot mount, so library/closure loads aren't slowed). */
    if (!us->upper_dirty) {
        void *sub = NULL;
        int rc = us->base_ops->open(us->base_state, path, flags, mode, &sub);
        if (rc != 0) {
            /* base (sysroot) lacks it · try the static /usr/bin stub table. */
            rc = union_static_fallback_open(us, path, flags, mode, &sub);
            if (rc != 0) { uh->in_use = false; return rc; }
            uh->layer = UNION_STATIC; uh->sub = sub;
            *out_handle = uh;
            return 0;
        }
        uh->layer = UNION_BASE; uh->sub = sub;
        *out_handle = uh;
        return 0;
    }
    /* upper non-empty · full overlay: upper-first, whiteout → absent, else base. */
    union_layer_t L = union_resolve_layer(union_upper_has(us, path),
                                          union_upper_whiteout(us, path),
                                          union_base_has(us, path));
    void *sub = NULL;
    int rc;
    if (L == UNION_NONE) {
        /* absent from both layers · static /usr/bin stub fallback. */
        rc = union_static_fallback_open(us, path, flags, mode, &sub);
        if (rc != 0) { uh->in_use = false; return -2; /* -ENOENT */ }
        uh->layer = UNION_STATIC; uh->sub = sub;
        *out_handle = uh;
        return 0;
    }
    if (L == UNION_UPPER) rc = us->upper_ops->open(&us->upper, path, flags, mode, &sub);
    else                  rc = us->base_ops->open(us->base_state, path, flags, mode, &sub);
    if (rc != 0) { uh->in_use = false; return rc; }
    uh->layer = L; uh->sub = sub;
    *out_handle = uh;
    return 0;
}

static int u_close(void *backend, void *handle)
{
    union_state_t *us = backend;
    union_handle_t *uh = handle;
    if (!uh) return 0;
    if (uh->layer == UNION_STATIC) {
        int rc = (uh->sub && vfs_static_ops.close) ? vfs_static_ops.close(vfs_static_state(), uh->sub) : 0;
        uh->in_use = false;
        return rc;
    }
    const vfs_ops_t *ops = (uh->layer == UNION_UPPER) ? us->upper_ops : us->base_ops;
    void *st = (uh->layer == UNION_UPPER) ? (void *)&us->upper : us->base_state;
    int rc = (uh->sub && ops->close) ? ops->close(st, uh->sub) : 0;
    uh->in_use = false;
    return rc;
}

static int64_t u_read(void *backend, void *handle, void *buf, size_t count, int64_t cursor)
{
    union_state_t *us = backend;
    union_handle_t *uh = handle;
    if (!uh || !uh->sub) return -9; /* -EBADF */
    if (uh->layer == UNION_UPPER) return us->upper_ops->read(&us->upper, uh->sub, buf, count, cursor);
    if (uh->layer == UNION_STATIC) return vfs_static_ops.read(vfs_static_state(), uh->sub, buf, count, cursor);
    return us->base_ops->read(us->base_state, uh->sub, buf, count, cursor);
}

static int64_t u_write(void *backend, void *handle, const void *buf, size_t count, int64_t cursor)
{
    union_state_t *us = backend;
    union_handle_t *uh = handle;
    if (!uh || !uh->sub) return -9;
    if (uh->layer != UNION_UPPER || !us->upper_ops->write) return -30; /* -EROFS */
    return us->upper_ops->write(&us->upper, uh->sub, buf, count, cursor);
}

/* The /usr union shadows the static `/` backend (longest-prefix match routes all
 * /usr/* to this mount), so the static-table /usr/bin/* TOOL stubs (dpkg-deb,
 * rm, diff, ldconfig, start-stop-daemon, …) become invisible — yet dpkg's startup
 * access(X_OK) check needs them.  When neither the upper nor the sysroot base has
 * the path, fall through to the static `/` backend (which keys on FULL paths, so
 * restore the "/usr" prefix the mount stripped).  Keeps the upper clean (the
 * fast-path optimisation stands) and execve still loads the REAL binary by
 * basename → binstore. */
/* Per-instance static-table fallback: when the path is absent from BOTH layers,
 * the /usr union (sysroot base, which lacks the /usr/bin tool stubs) restores its
 * "/usr" prefix and probes the static `/` table.  us->static_fallback is NULL for
 * the /etc union (its base IS the static honey → no fallback needed). */
static int union_static_fallback_stat(union_state_t *us, const char *suffix, struct lx_stat *out)
{
    if (!us->static_fallback || !vfs_static_ops.stat) return -2;
    char full[320];
    int n = snprintf(full, sizeof(full), "%s%s", us->static_fallback, suffix);
    if (n <= 0 || n >= (int)sizeof(full)) return -2;
    return vfs_static_ops.stat(vfs_static_state(), full, out);
}

/* Read-only open from the static `/` table (prefix restored), so a /usr/bin
 * static stub that is a #! script (the getconf facade) can be READ — u_stat
 * already falls through, but execve's shebang probe needs open+read too. */
static int union_static_fallback_open(union_state_t *us, const char *suffix,
                                      int flags, uint32_t mode, void **out_sub)
{
    if (!us->static_fallback || !vfs_static_ops.open) return -2;
    char full[320];
    int n = snprintf(full, sizeof(full), "%s%s", us->static_fallback, suffix);
    if (n <= 0 || n >= (int)sizeof(full)) return -2;
    return vfs_static_ops.open(vfs_static_state(), full, flags, mode, out_sub);
}

static int u_stat(void *backend, const char *path, struct lx_stat *out)
{
    union_state_t *us = backend;
    if (!us->upper_dirty) {                              /* fast path · upper empty */
        int rc = us->base_ops->stat(us->base_state, path, out);
        return rc == 0 ? 0 : union_static_fallback_stat(us, path, out);
    }
    if (union_upper_whiteout(us, path)) return -2;
    if (union_upper_has(us, path))      return us->upper_ops->stat(&us->upper, path, out);
    int rc = us->base_ops->stat(us->base_state, path, out);
    return rc == 0 ? 0 : union_static_fallback_stat(us, path, out);
}

static int u_fstat(void *backend, void *handle, struct lx_stat *out)
{
    union_state_t *us = backend;
    union_handle_t *uh = handle;
    if (!uh || !uh->sub) return -9;
    if (uh->layer == UNION_STATIC)
        return vfs_static_ops.fstat ? vfs_static_ops.fstat(vfs_static_state(), uh->sub, out) : -38;
    const vfs_ops_t *ops = (uh->layer == UNION_UPPER) ? us->upper_ops : us->base_ops;
    void *st = (uh->layer == UNION_UPPER) ? (void *)&us->upper : us->base_state;
    if (!ops->fstat) return -38; /* -ENOSYS */
    return ops->fstat(st, uh->sub, out);
}

static int u_readlink(void *backend, const char *path, char *buf, size_t size)
{
    union_state_t *us = backend;
    if (!us->upper_dirty)             /* fast path · base only */
        return us->base_ops->readlink ? us->base_ops->readlink(us->base_state, path, buf, size) : -22;
    if (union_upper_whiteout(us, path)) return -2;
    if (union_upper_has(us, path) && us->upper_ops->readlink)
        return us->upper_ops->readlink(&us->upper, path, buf, size);
    if (us->base_ops->readlink)
        return us->base_ops->readlink(us->base_state, path, buf, size);
    return -22; /* -EINVAL */
}

static int u_truncate(void *backend, void *handle, int64_t newlen)
{
    union_state_t *us = backend;
    union_handle_t *uh = handle;
    if (!uh || !uh->sub) return -9;
    if (uh->layer != UNION_UPPER || !us->upper_ops->truncate) return 0; /* silent for base */
    return us->upper_ops->truncate(&us->upper, uh->sub, newlen);
}

static int u_mkdir(void *backend, const char *path, uint32_t mode)
{
    union_state_t *us = backend;
    us->upper_dirty = 1;
    union_upper_mkparents(us, path);
    return us->upper_ops->mkdir ? us->upper_ops->mkdir(&us->upper, path, mode) : -30;
}

/* write a 0-byte whiteout marker in the upper to hide a base name. */
static void union_write_whiteout(union_state_t *us, const char *path)
{
    us->upper_dirty = 1;
    char wp[SOTFS_MAX_NAME + 128];
    if (union_whiteout_path(path, wp, sizeof(wp)) != 0) return;
    union_upper_mkparents(us, path);
    void *h = NULL;
    if (us->upper_ops->open(&us->upper, wp, O_CREAT_BIT | O_WRONLY_BIT, 0644, &h) == 0 && us->upper_ops->close)
        us->upper_ops->close(&us->upper, h);
}

static int u_unlink(void *backend, const char *path)
{
    union_state_t *us = backend;
    if (union_upper_has(us, path)) {
        int rc = us->upper_ops->unlink ? us->upper_ops->unlink(&us->upper, path) : -30;
        if (rc == 0 && union_base_has(us, path)) union_write_whiteout(us, path);
        return rc;
    }
    if (union_base_has(us, path)) { union_write_whiteout(us, path); return 0; }
    return -2; /* -ENOENT */
}

static int u_rmdir(void *backend, const char *path)
{
    union_state_t *us = backend;
    if (union_upper_has(us, path)) {
        int rc = us->upper_ops->rmdir ? us->upper_ops->rmdir(&us->upper, path) : -30;
        if (rc == 0 && union_base_has(us, path)) union_write_whiteout(us, path);
        return rc;
    }
    if (union_base_has(us, path)) { union_write_whiteout(us, path); return 0; }
    return -2;
}

static int u_rename(void *backend, const char *oldp, const char *newp)
{
    union_state_t *us = backend;
    /* within-upper rename (dpkg's <path>.dpkg-new → <path>). */
    if (union_upper_has(us, oldp)) {
        union_upper_mkparents(us, newp);
        if (union_upper_whiteout(us, newp)) {
            char wp[SOTFS_MAX_NAME + 128];
            if (union_whiteout_path(newp, wp, sizeof(wp)) == 0 && us->upper_ops->unlink)
                us->upper_ops->unlink(&us->upper, wp);
        }
        int rc = us->upper_ops->rename ? us->upper_ops->rename(&us->upper, oldp, newp) : -30;
        if (rc == 0 && union_base_has(us, oldp)) union_write_whiteout(us, oldp);
        return rc;
    }
    /* Source not in the upper.  A base-only source is a cross-layer copy-up
     * rename (deferred → -EXDEV).  But if the source is absent from BOTH layers,
     * POSIX requires -ENOENT — NOT -EXDEV — and dpkg depends on it: its unpack
     * cleanup does rename(<path>.dpkg-tmp, <path>) and only aborts when
     * errno != ENOENT, so a spurious EXDEV on a non-existent .dpkg-tmp killed
     * the install ("unable to clean up mess surrounding './usr/bin/hello' ...
     * Invalid cross-device link"). */
    if (union_base_has(us, oldp))
        return -18; /* -EXDEV · base→upper copy-up rename deferred */
    return -2;      /* -ENOENT · source absent in both layers */
}

/* ── getdents merge (buffered on first call) ─────────────────────────────
 * Drain a layer's getdents, parse the linux_dirent64 records, append the names
 * (skipping ".wh.*" and duplicates) into the handle's buffer. */
/* is `name` whitened in the upper at `dirpath`? (a ".wh.<name>" marker present) */
static int union_name_whitened(union_state_t *us, const char *dirpath, const char *name)
{
    char wp[SOTFS_MAX_NAME * 4];
    snprintf(wp, sizeof(wp), "%s/.wh.%s", (dirpath[1] == '\0') ? "" : dirpath, name);
    struct lx_stat st;
    return us->upper_ops->stat(&us->upper, wp, &st) == 0;
}

/* Drain one layer's getdents for `dirpath` into uh's name buffer.  Skips "." "..",
 * the ".wh.*" markers, and any name already buffered (upper is drained first, so
 * upper shadows base).  When `filter_base_whiteouts`, a base name whitened in the
 * upper is skipped. */
static void union_drain_layer(union_state_t *us, union_handle_t *uh,
                              const vfs_ops_t *ops, void *st,
                              const char *dirpath, int filter_base_whiteouts)
{
    if (!ops || !ops->open || !ops->getdents) return;
    void *sub = NULL;
    if (ops->open(st, dirpath, LX_O_RDONLY | LX_O_DIRECTORY, 0, &sub) != 0) return;
    uint8_t buf[2048];
    int64_t cur = 0;
    for (;;) {
        int64_t n = ops->getdents(st, sub, buf, sizeof(buf), &cur);
        if (n <= 0) break;
        size_t off = 0;
        while (off < (size_t)n) {
            struct lx_dirent64 *de = (struct lx_dirent64 *)(buf + off);
            if (de->d_reclen == 0) break;
            const char *nm = de->d_name;
            off += de->d_reclen;
            if (nm[0] == '.' && (nm[1] == '\0' || (nm[1] == '.' && nm[2] == '\0'))) continue;
            if (strncmp(nm, ".wh.", 4) == 0) continue;     /* never emit a marker */
            /* persona-coherence · the glibc multiarch dir (x86_64-linux-gnu) is a
             * Debian/Ubuntu tell — hide it from the Alpine honey session's `ls`. */
            if (lucas_persona_hides(lucas_get_current_caller(), nm)) continue;
            if (filter_base_whiteouts && union_name_whitened(us, dirpath, nm)) continue;
            int dup = 0;
            for (int i = 0; i < uh->gd_count; i++)
                if (strcmp(uh->gd_names[i], nm) == 0) { dup = 1; break; }
            if (dup) continue;
            if (uh->gd_count >= UNION_GD_MAX) continue;     /* capped (documented) */
            strncpy(uh->gd_names[uh->gd_count], nm, SOTFS_MAX_NAME - 1);
            uh->gd_names[uh->gd_count][SOTFS_MAX_NAME - 1] = '\0';
            uh->gd_types[uh->gd_count] = de->d_type;
            uh->gd_count++;
        }
    }
    if (ops->close) ops->close(st, sub);
}

static int64_t u_getdents(void *backend, void *handle, void *dirp,
                          size_t count, int64_t *cursor)
{
    union_state_t *us = backend;
    union_handle_t *uh = handle;
    (void)cursor;
    if (!uh) return -9;

    if (!uh->gd_built) {
        /* Merge: drain the UPPER first (so upper names shadow base in the dedup),
         * then the BASE (skipping names whitened in the upper).  When the upper is
         * empty (no install yet), skip the upper drain entirely — base only. */
        if (us->upper_dirty)
            union_drain_layer(us, uh, us->upper_ops, &us->upper, uh->gd_dirpath, 0);
        union_drain_layer(us, uh, us->base_ops, us->base_state, uh->gd_dirpath,
                          us->upper_dirty);
        uh->gd_built = 1;
        uh->gd_idx = 0;
    }

    uint8_t *out = dirp; size_t written = 0;
    while (uh->gd_idx < uh->gd_count) {
        const char *nm = uh->gd_names[uh->gd_idx];
        size_t name_len = strlen(nm) + 1;
        size_t reclen = (offsetof(struct lx_dirent64, d_name) + name_len + 7) & ~(size_t)7;
        if (written + reclen > count) break;
        struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
        de->d_ino    = (uint64_t)(uh->gd_idx + 1);
        de->d_off    = (int64_t)(uh->gd_idx + 1);
        de->d_reclen = (uint16_t)reclen;
        de->d_type   = uh->gd_types[uh->gd_idx];
        memcpy(de->d_name, nm, name_len);
        written += reclen;
        uh->gd_idx++;
    }
    return (int64_t)written;
}

static void *u_dup_handle(void *backend, void *src)
{
    union_state_t *us = backend;
    union_handle_t *s = src;
    if (!s) return NULL;
    union_handle_t *d = union_handle_alloc();
    if (!d) return NULL;
    d->layer = s->layer;
    const vfs_ops_t *ops = (s->layer == UNION_UPPER) ? us->upper_ops : us->base_ops;
    void *st = (s->layer == UNION_UPPER) ? (void *)&us->upper : us->base_state;
    d->sub = (s->sub && ops->dup_handle) ? ops->dup_handle(st, s->sub) : NULL;
    if (!d->sub) { d->in_use = false; return NULL; }
    return d;
}

static const vfs_ops_t union_ops = {
    .open = u_open, .close = u_close, .read = u_read, .write = u_write,
    .stat = u_stat, .fstat = u_fstat, .getdents = u_getdents, .readlink = u_readlink,
    .dup_handle = u_dup_handle, .truncate = u_truncate,
    .mkdir = u_mkdir, .unlink = u_unlink, .rmdir = u_rmdir, .rename = u_rename,
};

static union_state_t g_usr_union;

vfs_mount_t lucas_usr_union_mount(void)
{
    vfs_mount_t base = lucas_sysroot_mount();   /* {prefix "/usr", ops, backend_state} */
    g_usr_union.upper.root_id    = sotfs_mount_make_root("usr");
    g_usr_union.upper.label      = "usr";
    g_usr_union.upper_ops        = lucas_sotfs_ops();
    g_usr_union.base_ops         = base.ops;
    g_usr_union.base_state       = base.backend_state;
    g_usr_union.static_fallback  = "/usr";   /* sysroot base lacks the /usr/bin tool stubs */
    printf("[vfs] /usr OVERLAY mount · upper=sotfs(usr root_id=%d) base=sysroot\n",
           g_usr_union.upper.root_id);

    /* One-shot self-test: prove a NEW file create lands in the upper + reads back,
     * and that a base path (/lib/.. served by the sysroot) still resolves through
     * the overlay base-fallback.  Runs once per boot (the first /usr mount). */
    static int probed = 0;
    if (!probed) {
        probed = 1;
        void *h = NULL;
        int rc = union_ops.open(&g_usr_union, "/.uprobe",
                                O_CREAT_BIT | O_WRONLY_BIT, 0644, &h);
        if (rc == 0) {
            union_ops.write(&g_usr_union, h, "UPPER-OK\n", 9, 0);
            union_ops.close(&g_usr_union, h);
            char rb[16] = {0}; void *h2 = NULL;
            if (union_ops.open(&g_usr_union, "/.uprobe", 0, 0, &h2) == 0) {
                int64_t n = union_ops.read(&g_usr_union, h2, rb, sizeof(rb) - 1, 0);
                union_ops.close(&g_usr_union, h2);
                printf("[usr-overlay-selftest] upper write+read=%lld '%.8s' · %s\n",
                       (long long)n, rb,
                       (n == 9 && memcmp(rb, "UPPER-OK", 8) == 0) ? "UPPER-OK" : "FAIL");
            }
            union_ops.unlink(&g_usr_union, "/.uprobe");
        } else {
            printf("[usr-overlay-selftest] upper create rc=%d · FAIL\n", rc);
        }
        /* the probe netted zero entries · the upper is empty again → re-arm the
         * clean fast path so library/closure loads aren't slowed before an install. */
        g_usr_union.upper_dirty = 0;
    }

    /* apk-network-install Task 1 (C2) · seed the credible Alpine 3.20 base
     * installed-DB at /lib/apk/db/installed.  The guest's /lib/apk/db/installed
     * routes (vfs.c) to THIS /usr union — reads fall through upper→sysroot base,
     * writes/creates land in the upper.  We seed it into the upper at BOOT with
     * NO sotbox caller (pid 0 · untagged), so it is the PRISTINE shared base that
     * the operator + every session read identically.  apk's per-session installs
     * land tagged in the same upper (the op_open cow_session create path) and are
     * operator/2nd-session-invisible, leaving this base intact.  With these 14
     * base packages present, apk's solver closes a realistic closure
     * (`apk add nano` → ncurses-terminfo-base + libncursesw + nano).  Mirrors the
     * dpkg_db_seed pattern: mkdir -p the nested dirs in the upper, then write. */
    static int basedb_seeded = 0;
    if (!basedb_seeded) {
        basedb_seeded = 1;
        u_mkdir(&g_usr_union, "/lib",         0755);
        u_mkdir(&g_usr_union, "/lib/apk",     0755);
        u_mkdir(&g_usr_union, "/lib/apk/db",  0755);
        void *bh = NULL;
        int brc = union_ops.open(&g_usr_union, "/lib/apk/db/installed",
                                 O_CREAT_BIT | O_WRONLY_BIT, 0644, &bh);
        if (brc == 0 && bh) {
            int64_t bw = union_ops.write(&g_usr_union, bh, apk_basedb,
                                         (size_t)apk_basedb_len, 0);
            union_ops.close(&g_usr_union, bh);
            if (bw == (int64_t)apk_basedb_len)
                printf("[apk] base installed-DB seeded · /lib/apk/db/installed (%u bytes · 14 pkgs)\n",
                       apk_basedb_len);
            else
                printf("[apk] base installed-DB seed SHORT/FAILED · wrote %lld of %u bytes — apk solver will see an empty base DB\n",
                       (long long)bw, apk_basedb_len);
        } else {
            printf("[apk] base installed-DB seed FAILED · open rc=%d\n", brc);
        }
        /* the seed is the shared pristine base (untagged) · the upper now holds it
         * for all sessions; keep upper_dirty set so reads probe the upper. */
    }

    return (vfs_mount_t){ .prefix = "/usr", .ops = &union_ops, .backend_state = &g_usr_union };
}

/* ── /etc writable union ─────────────────────────────────────────────────
 * /etc carries the DECEPTION honey (passwd/group/shadow/os-release/… across the
 * alpine/ubuntu/canary personas), served by the static `/` backend on FULL paths.
 * A plain writable mount would shadow + lose all of it; the union keeps the honey
 * as the read-only BASE and lands postinst writes (e.g. `cp foo /etc/foo`) in a
 * writable sotfs UPPER.  The base must see "/etc/passwd" but the union strips the
 * "/etc" mount prefix to "/passwd" — so the base is a thin "static view" that
 * restores the prefix before delegating to the static table. */
typedef struct { const char *prefix; } static_view_t;

static void sv_full(const char *prefix, const char *suffix, char *out, size_t cap)
{
    if (!suffix || suffix[0] == '\0' || (suffix[0] == '/' && suffix[1] == '\0'))
        snprintf(out, cap, "%s", prefix);                 /* the mount root itself */
    else
        snprintf(out, cap, "%s%s", prefix, suffix);
}
static int sv_open(void *bs, const char *suffix, int flags, uint32_t mode, void **h)
{
    static_view_t *s = bs;
    if (!vfs_static_ops.open) return -2;
    char full[320]; sv_full(s->prefix, suffix, full, sizeof(full));
    return vfs_static_ops.open(vfs_static_state(), full, flags, mode, h);
}
static int sv_close(void *bs, void *h)
{ (void)bs; return vfs_static_ops.close ? vfs_static_ops.close(vfs_static_state(), h) : 0; }
static int64_t sv_read(void *bs, void *h, void *buf, size_t n, int64_t cur)
{ (void)bs; return vfs_static_ops.read ? vfs_static_ops.read(vfs_static_state(), h, buf, n, cur) : -9; }
static int sv_stat(void *bs, const char *suffix, struct lx_stat *out)
{
    static_view_t *s = bs;
    if (!vfs_static_ops.stat) return -2;
    char full[320]; sv_full(s->prefix, suffix, full, sizeof(full));
    return vfs_static_ops.stat(vfs_static_state(), full, out);
}
static int sv_fstat(void *bs, void *h, struct lx_stat *out)
{ (void)bs; return vfs_static_ops.fstat ? vfs_static_ops.fstat(vfs_static_state(), h, out) : -38; }
static int64_t sv_getdents(void *bs, void *h, void *dirp, size_t n, int64_t *cur)
{ (void)bs; return vfs_static_ops.getdents ? vfs_static_ops.getdents(vfs_static_state(), h, dirp, n, cur) : -38; }
static int sv_readlink(void *bs, const char *suffix, char *buf, size_t size)
{
    static_view_t *s = bs;
    if (!vfs_static_ops.readlink) return -22;
    char full[320]; sv_full(s->prefix, suffix, full, sizeof(full));
    return vfs_static_ops.readlink(vfs_static_state(), full, buf, size);
}
static void *sv_dup_handle(void *bs, void *h)
{ (void)bs; return vfs_static_ops.dup_handle ? vfs_static_ops.dup_handle(vfs_static_state(), h) : NULL; }

static const vfs_ops_t static_view_ops = {
    .open = sv_open, .close = sv_close, .read = sv_read,
    .stat = sv_stat, .fstat = sv_fstat, .getdents = sv_getdents,
    .readlink = sv_readlink, .dup_handle = sv_dup_handle,
    /* read-only base · no write/mkdir/unlink/rename (the union routes writes to the upper) */
};
static static_view_t g_etc_static_view = { "/etc" };
static union_state_t g_etc_union;

vfs_mount_t lucas_etc_union_mount(void)
{
    g_etc_union.upper.root_id   = sotfs_mount_make_root("etc");
    g_etc_union.upper.label     = "etc";
    g_etc_union.upper_ops       = lucas_sotfs_ops();
    g_etc_union.base_ops        = &static_view_ops;
    g_etc_union.base_state      = &g_etc_static_view;
    g_etc_union.static_fallback = NULL;   /* base IS the static honey → no fallback */
    printf("[vfs] /etc OVERLAY mount · upper=sotfs(etc root_id=%d) base=static-honey\n",
           g_etc_union.upper.root_id);
    return (vfs_mount_t){ .prefix = "/etc", .ops = &union_ops, .backend_state = &g_etc_union };
}
