/*
 * sotOs · LUCAS · musl sysroot VFS backend (tcc-libc).
 * Mounts the read-only musl tree at "/usr": /usr/include/* + /usr/lib/*.
 * Reads the entry table once (lazy-init) and serves open/read/stat/getdents/
 * readlink from the baked tree in sotfs.img [64,112 MiB) via
 * virtio_blk_read_sector.  LNK entries (symlinks) are followed on open/stat
 * (bounded · SYSROOT_MAX_SYMLINK_FOLLOW · -ELOOP past the bound) and reported
 * verbatim by readlink; open(O_NOFOLLOW) yields the link entry itself.
 */
#include <lucas/backends_sysroot.h>
#include <lucas/vfs.h>
#include <lucas/clock.h>
#include <sotfs/layout.h>
#include <sotfs/sysroot.h>
#include <sotfs/storage_virtio_blk.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#define SYSROOT_MAX_SYMLINK_FOLLOW 8   /* anti-loop bound for LNK resolution */

static sotfs_sysroot_header_t g_hdr;
static sotfs_sysroot_entry_t  g_entries[SOTFS_SYSROOT_MAX_ENTRIES];
static int g_initialized = 0, g_ready = 0;

/* Read `len` bytes at absolute image offset `off` into `dst`. 0 on success.
 * (static sector buffer: lucas serves one syscall at a time, same as op_read) */
static int read_blob(uint64_t off, void *dst, uint64_t len)
{
    static uint8_t sec[512];
    uint64_t done = 0;
    while (done < len) {
        uint64_t disk = off + done;
        if (virtio_blk_read_sector(disk / 512u, sec) != 0) return -1;
        size_t inner = (size_t)(disk % 512u);
        size_t chunk = 512 - inner;
        if (chunk > len - done) chunk = (size_t)(len - done);
        memcpy((uint8_t *)dst + done, sec + inner, chunk);
        done += chunk;
    }
    return 0;
}

static int sysroot_lazy_init(void)
{
    if (g_initialized) return g_ready ? 0 : -2;
    g_initialized = 1;

    uint8_t sec[512];
    uint64_t base = (uint64_t)SOTFS_SYSROOT_HEADER_OFFSET / 512u;
    if (virtio_blk_read_sector(base, sec) != 0) return -2;
    memcpy(&g_hdr, sec, sizeof(g_hdr));
    if (g_hdr.magic != SOTFS_SYSROOT_MAGIC) {
        printf("[sysroot] magic mismatch · got 0x%x · region not populated\n", g_hdr.magic);
        return -2;
    }
    if (g_hdr.count == 0 || g_hdr.count > SOTFS_SYSROOT_MAX_ENTRIES) return -2;

    /* Entry table follows the 16-byte header at SOTFS_SYSROOT_HEADER_OFFSET. */
    uint64_t tbl_off  = (uint64_t)SOTFS_SYSROOT_HEADER_OFFSET + sizeof(g_hdr);
    size_t   tbl_size = g_hdr.count * sizeof(sotfs_sysroot_entry_t);
    uint8_t *dst = (uint8_t *)g_entries;
    size_t got = 0;
    while (got < tbl_size) {
        uint64_t off = tbl_off + got;
        if (virtio_blk_read_sector(off / 512u, sec) != 0) return -2;
        size_t inner = (size_t)(off % 512u);
        size_t chunk = 512 - inner;
        if (chunk > tbl_size - got) chunk = tbl_size - got;
        memcpy(dst + got, sec + inner, chunk);
        got += chunk;
    }
    g_ready = 1;
    printf("[sysroot] ready · %u entries · mounted /usr\n", g_hdr.count);
    return 0;
}

/* Strip the leading '/' the VFS layer leaves on the mount-relative suffix. */
static const char *rel(const char *path) { return (path[0] == '/') ? path + 1 : path; }

static const sotfs_sysroot_entry_t *find(const char *relpath)
{
    for (uint32_t i = 0; i < g_hdr.count; ++i)
        if (strncmp(g_entries[i].path, relpath, SOTFS_SYSROOT_PATH_BYTES) == 0)
            return &g_entries[i];
    /* Case-INSENSITIVE fallback · Windows is case-insensitive, our VFS is not.
     * A Win32 PE imports e.g. GDI32.dll / USER32.dll (uppercase, as mingw writes
     * the classic DLL names) but the staged file is gdi32.dll — wine's loader
     * open()s the uppercase name → exact match fails → STATUS_DLL_NOT_FOUND.
     * Only runs after the exact pass fails, so it never shadows a real file. */
    for (uint32_t i = 0; i < g_hdr.count; ++i) {
        const char *a = g_entries[i].path, *b = relpath; uint32_t n = 0;
        for (;; ++n) {
            if (n >= SOTFS_SYSROOT_PATH_BYTES) break;
            char ca = a[n], cb = b[n];
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) break;
            if (ca == '\0') return &g_entries[i];
        }
    }
    return NULL;
}

/* Join a symlink target against the link's parent directory and normalize
 * "." / ".." components into a sysroot-relative key (no leading slash).
 * Absolute targets are accepted only within the mounted tree: "/usr/lib/x"
 * -> "lib/x", "/lib/x" -> "lib/x" (the /lib alias maps here); other absolute
 * targets resolve relative to the tree root.  A too-long join truncates and
 * simply matches no entry (ENOENT).  Caller-owned `out`; out may alias
 * link_relpath (it is fully consumed into `work` before `out` is written). */
static void join_target(const char *link_relpath, const char *target,
                        char *out, size_t outsz)
{
    char work[SOTFS_SYSROOT_PATH_BYTES * 2];
    if (target[0] == '/') {
        const char *t = target;
        if (strncmp(t, "/usr/", 5) == 0) t += 5;       /* /usr/lib/x -> lib/x */
        else if (strncmp(t, "/lib/", 5) == 0) t += 1;  /* /lib/x     -> lib/x */
        else while (*t == '/') t++;                    /* tree-relative */
        snprintf(work, sizeof(work), "%s", t);
    } else {
        /* relative to the link's parent dir */
        const char *slash = strrchr(link_relpath, '/');
        size_t dlen = slash ? (size_t)(slash - link_relpath) : 0;
        if (dlen) snprintf(work, sizeof(work), "%.*s/%s", (int)dlen, link_relpath, target);
        else      snprintf(work, sizeof(work), "%s", target);
    }
    /* normalize: drop "." segments, collapse "x/.." */
    char *seg[64]; int n = 0;
    for (char *p = strtok(work, "/"); p; p = strtok(NULL, "/")) {
        if (strcmp(p, ".") == 0) continue;
        if (strcmp(p, "..") == 0) { if (n) n--; continue; }
        if (n < 64) seg[n++] = p;
    }
    size_t w = 0; out[0] = '\0';
    for (int i = 0; i < n && w + 1 < outsz; i++) {
        int k = snprintf(out + w, outsz - w, "%s%s", i ? "/" : "", seg[i]);
        if (k < 0) break;
        w += (size_t)k;
        if (w >= outsz) break;   /* truncated · will ENOENT, never underflow */
    }
}

/* find() that follows LNK entries · bound of SYSROOT_MAX_SYMLINK_FOLLOW loop
 * iterations resolves chains of up to SYSROOT_MAX_SYMLINK_FOLLOW-1 symlinks
 * (the terminal lookup spends one iteration).  Returns the final non-link
 * entry, or NULL with *err set to the negative errno: -2 ENOENT (no entry /
 * dangling or empty target), -5 EIO (blk read failed), -40 ELOOP (bound
 * exhausted · loop or over-deep chain). */
static const sotfs_sysroot_entry_t *find_follow(const char *relpath, int *err)
{
    char buf[SOTFS_SYSROOT_PATH_BYTES];
    const char *cur = relpath;
    for (int hop = 0; hop < SYSROOT_MAX_SYMLINK_FOLLOW; hop++) {
        const sotfs_sysroot_entry_t *e = find(cur);
        if (!e) { *err = -2; return NULL; }                      /* ENOENT */
        if (e->type != SOTFS_SYSROOT_TYPE_LNK) { *err = 0; return e; }
        char target[SOTFS_SYSROOT_PATH_BYTES];
        uint64_t n = e->size < sizeof(target) - 1 ? e->size : sizeof(target) - 1;
        if (n == 0) { *err = -2; return NULL; }   /* empty target · Linux: ENOENT */
        if (read_blob(e->offset, target, n) != 0) { *err = -5; return NULL; }
        target[n] = '\0';
        join_target(cur, target, buf, sizeof(buf));   /* cur==buf alias is safe */
        cur = buf;
    }
    *err = -40;   /* ELOOP */
    return NULL;
}

struct sysroot_handle { bool in_use; int entry_idx; };
/* GLOBAL pool (shared across sotboxes).  A lazy file-backed mmap PINS its handle
 * past the guest's close() (handlers_fs.c · lazy_pinned) so on-demand faults can
 * still read — so a dynamic guest holds one handle per mapped shared library for
 * its whole life.  A static-musl app holds ~0; the SDL2 closure ~7; a real GTK3
 * app drags 57.  Bumped 16→128 for GTK + a full boot's concurrent dynamic apps.
 * sotbox teardown releases them (lucas_release_lazy_regions) so the pool returns
 * to baseline per launch. */
/* 128 -> 256 · `apt install` runs MANY concurrent glibc consumers whose lazy-
 * mmap'd lib closures each PIN a sysroot handle: apt itself (~20 libs) + a forked
 * http transport method (~20) + a large gpgv-sq (sequoia · ~30) can be alive at
 * once, and apt RETRIES the method on transient egress errors → the pinned-handle
 * peak crossed 128 → the method's ld.so EMFILE'd (Error 24) opening libsystemd.so.0.
 * 256 covers the install fan-out (each handle is a small struct). */
#define SYSROOT_MAX_HANDLES 256
static struct sysroot_handle g_handles[SYSROOT_MAX_HANDLES];

/* Allocate a handle slot for entry `idx` WITHOUT clobbering a closed-but-still-
 * identified slot out from under a dangling reference.  Wine creates an NLS section
 * over a file, close()s the file fd, then later SCM_RIGHTS-passes the section's
 * backing fd to another process; LUCAS dups that fd by POINTER and reads the slot's
 * CURRENT entry_idx.  If op_open had recycled that closed slot for a different file
 * (the old "first !in_use, clobber entry_idx" loop), the dup read the WRONG file —
 * the launcher's sortdefault.nls section aliased to l_intl.nls (5546 B) → kernelbase
 * NLS collation cursor overrun → #GP.  Preference order: (1) a closed slot already
 * holding `idx` (same identity, safe), (2) a never-used / closed-/usr-root slot
 * (entry_idx == -1, nothing to alias), (3) only as a last resort under pool pressure,
 * recycle a closed slot of a different file. */
static struct sysroot_handle *alloc_handle_slot(int idx)
{
    int reuse = -1, neverused = -1, recycle = -1;
    for (int i = 0; i < SYSROOT_MAX_HANDLES; ++i) {
        if (g_handles[i].in_use) continue;
        if (g_handles[i].entry_idx == idx) { reuse = i; break; }
        if (g_handles[i].entry_idx == -1 && neverused < 0) neverused = i;
        if (recycle < 0) recycle = i;
    }
    int slot = reuse >= 0 ? reuse : (neverused >= 0 ? neverused : recycle);
    if (slot < 0) return NULL;
    g_handles[slot].in_use    = true;
    g_handles[slot].entry_idx = idx;
    return &g_handles[slot];
}

static int op_open(void *b, const char *path, int flags, uint32_t mode, void **out)
{
    (void)b; (void)mode;
    if (sysroot_lazy_init() != 0) return -2;
    const char *r = rel(path);
    const sotfs_sysroot_entry_t *e = NULL;
    if (*r != '\0') {
        if (flags & LX_O_NOFOLLOW) {
            /* O_NOFOLLOW on the final component returns the link itself
             * (lstat/readlink semantics per the v2-vfs spec) · fstat on the
             * handle reports IFLNK.  Deliberately O_PATH|O_NOFOLLOW-like —
             * bare Linux open(O_NOFOLLOW) on a link would ELOOP instead.
             * Non-links are unaffected, as on Linux. */
            e = find(r);
            if (!e) return -2;              /* ENOENT */
        } else {
            /* follow symlinks: opening "lib/libfoo.so" (a LNK) yields the
             * target's bytes */
            int err;
            e = find_follow(r, &err);
            if (!e) return err;             /* ENOENT / EIO / ELOOP */
        }
    }
    /* O_DIRECTORY: the resolved entry must be a directory (Linux: ENOTDIR ·
     * musl opendir() relies on this).  With O_NOFOLLOW a link resolves to
     * itself, so O_NOFOLLOW|O_DIRECTORY on a link → ENOTDIR, as on Linux.
     * e == NULL is the /usr root dir (always a directory). */
    if ((flags & LX_O_DIRECTORY) && e && e->type != SOTFS_SYSROOT_TYPE_DIR)
        return -20;
    int idx = e ? (int)(e - g_entries) : -1; /* -1 = the /usr root dir */
    struct sysroot_handle *hs = alloc_handle_slot(idx);
    if (!hs) return -24; /* EMFILE */
    *out = hs;
    return 0;
}

static int op_close(void *b, void *h)
{ (void)b; if (h) ((struct sysroot_handle *)h)->in_use = false; return 0; }

/* Allocate a fresh, independent handle for the same entry as `src` — see the
 * vfs_ops dup_handle contract.  The wine PE loader file-backed-mmaps page-aligned
 * builtin .exe's (wineboot/start) from a section fd passed across sotboxes via
 * SCM_RIGHTS; the receiver needs a handle decoupled from the sender's (which the
 * sender close()s and the shared pool recycles → op_read -EBADF → c000007b). */
static void *op_dup_handle(void *b, void *src)
{
    (void)b;
    struct sysroot_handle *s = (struct sysroot_handle *)src;
    /* Accept a closed-but-not-yet-recycled handle too: op_close only clears
     * in_use, leaving entry_idx intact, and wine often close()s the section fd
     * before SCM-sending it.  entry_idx>=0 means the identity is still this
     * file's (a recycled slot would be in_use=1 for a different entry). */
    if (!s || s->entry_idx < 0) return NULL;
    /* WINE-M1 diag · the SCM-passed NLS section fd dups read the WRONG file
     * (launcher's sortdefault section reads l_intl's 5546 bytes).  Log the source
     * handle's entry identity (idx + size + in_use) so we see whether the captured
     * entry is sortdefault (size 0x338bc4) or a recycled/wrong entry (l_intl 5546). */
    printf("[sysroot] dup_handle · src=%p in_use=%d entry_idx=%d size=%lu\n",
           (void *)s, s->in_use, s->entry_idx,
           (unsigned long)g_entries[s->entry_idx].size);
    return alloc_handle_slot(s->entry_idx); /* same preserve-closed-identities policy as op_open */
}

static int64_t op_read(void *b, void *h, void *buf, size_t count, int64_t cursor)
{
    (void)b;
    struct sysroot_handle *hd = (struct sysroot_handle *)h;
    if (!hd || !hd->in_use || hd->entry_idx < 0) return -9;
    const sotfs_sysroot_entry_t *e = &g_entries[hd->entry_idx];
    if (e->type != SOTFS_SYSROOT_TYPE_FILE) return -21; /* EISDIR */
    if (cursor < 0) return -22;
    if ((uint64_t)cursor >= e->size) return 0;
    uint64_t remaining = e->size - (uint64_t)cursor;
    if ((uint64_t)count > remaining) count = (size_t)remaining;
    uint64_t disk = e->offset + (uint64_t)cursor;
    size_t copied = 0; static uint8_t sec[512];
    extern void lucas_doom_probe(const char *tag);
    lucas_doom_probe("sysroot:op_read-entry");
    while (copied < count) {
        uint64_t s = disk / 512u; size_t inner = (size_t)(disk % 512u);
        if (virtio_blk_read_sector(s, sec) != 0) return -5;
        lucas_doom_probe("sysroot:after-blk-read");
        size_t chunk = 512 - inner;
        if (chunk > count - copied) chunk = count - copied;
        memcpy((uint8_t *)buf + copied, sec + inner, chunk);
        lucas_doom_probe("sysroot:after-memcpy-to-buf");
        copied += chunk; disk += chunk;
    }
    return (int64_t)copied;
}

/* WINE-M1 baked prefix · read a staged sysroot file by its entry-relative path
 * (e.g. "share/wine/baseprefix/system.reg") into `buf` at `off`.  Returns bytes
 * read (0 at EOF) or -errno.  The baked-prefix seeder uses this to copy the
 * version-matched .reg hives into the writable sotfs graph so wine treats the
 * prefix as already initialized and SKIPS wineboot.  (Explicit baked-mode path —
 * NOT a default; the seeder logs that the prefix is pre-baked, not booted.) */
int64_t lucas_sysroot_pread(const char *relpath, void *buf, size_t count, int64_t off)
{
    const sotfs_sysroot_entry_t *e = find(relpath);
    if (!e || e->type != SOTFS_SYSROOT_TYPE_FILE) return -2; /* -ENOENT */
    if (off < 0) return -22;
    if ((uint64_t)off >= e->size) return 0;
    uint64_t remaining = e->size - (uint64_t)off;
    if ((uint64_t)count > remaining) count = (size_t)remaining;
    uint64_t disk = e->offset + (uint64_t)off;
    size_t copied = 0; static uint8_t sec[512];
    while (copied < count) {
        uint64_t s = disk / 512u; size_t inner = (size_t)(disk % 512u);
        if (virtio_blk_read_sector(s, sec) != 0) return -5;
        size_t chunk = 512 - inner;
        if (chunk > count - copied) chunk = count - copied;
        memcpy((uint8_t *)buf + copied, sec + inner, chunk);
        copied += chunk; disk += chunk;
    }
    return (int64_t)copied;
}

/* ── Operator-side merged-root accessors ──────────────────────────────────
 * The operator console (sotShell) historically listed/read only the writable
 * sotfs store.  These let it see the SAME read-only Alpine tree a guest sees
 * under /usr (+ the /lib alias), so `ls /usr/lib/wine` / `cat /usr/...` work
 * from the operator console.  They mirror op_getdents/op_read but emit the
 * compact operator dirent (name/size/kind) the ORCH_OP_SOTFS_LS reply uses. */
typedef struct { char name[32]; uint32_t size; uint8_t kind; uint8_t pad[3]; } op_dirent_t;

/* Map an absolute operator path to a sysroot entry-table key (relative to /usr).
 * "/usr" -> "" (tree root) · "/usr/lib/x" -> "lib/x" · "/lib" -> "lib" ·
 * "/lib/x" -> "lib/x" (the /lib -> /usr/lib alias).  NULL if not sysroot-served. */
static const char *sysroot_opkey(const char *abspath, char *buf, size_t bufsz)
{
    if (strcmp(abspath, "/usr") == 0)        return "";
    if (strncmp(abspath, "/usr/", 5) == 0)   return abspath + 5;
    if (strcmp(abspath, "/lib") == 0)        return "lib";
    if (strncmp(abspath, "/lib/", 5) == 0) { snprintf(buf, bufsz, "lib/%s", abspath + 5); return buf; }
    return NULL;
}

int lucas_sysroot_list_dir(const char *abspath, void *out_v, int max)
{
    op_dirent_t *out = (op_dirent_t *)out_v;
    if (!abspath || !out || max <= 0) return -22;
    if (sysroot_lazy_init() != 0) return -2;
    char kbuf[SOTFS_SYSROOT_PATH_BYTES];
    const char *dir = sysroot_opkey(abspath, kbuf, sizeof(kbuf));
    if (!dir) return -2;
    size_t dirlen = strlen(dir);
    int count = 0;
    for (uint32_t i = 0; i < g_hdr.count && count < max; ++i) {
        const char *p = g_entries[i].path;
        if (dirlen) {
            if (strncmp(p, dir, dirlen) != 0 || p[dirlen] != '/') continue;
            p += dirlen + 1;
        }
        if (*p == '\0' || strchr(p, '/')) continue;   /* self / grandchildren */
        strncpy(out[count].name, p, 31);
        out[count].name[31] = '\0';
        out[count].size = (uint32_t)g_entries[i].size;
        out[count].kind = (g_entries[i].type == SOTFS_SYSROOT_TYPE_DIR) ? 2 : 1;
        out[count].pad[0] = out[count].pad[1] = out[count].pad[2] = 0;
        count++;
    }
    return count;
}

/* Read a sysroot-served file by absolute operator path (no symlink follow ·
 * the operator cats real files).  Returns bytes read, or -errno. */
int lucas_sysroot_read_abs(const char *abspath, void *buf, size_t max)
{
    if (!abspath || !buf || max == 0) return -22;
    if (sysroot_lazy_init() != 0) return -2;
    char kbuf[SOTFS_SYSROOT_PATH_BYTES];
    const char *rel = sysroot_opkey(abspath, kbuf, sizeof(kbuf));
    if (!rel || !*rel) return -21; /* -EISDIR / tree root */
    return (int)lucas_sysroot_pread(rel, buf, max, 0);
}

/* offset-capable variant for the operator's chunked `cat` (READ_AT). */
int lucas_sysroot_read_abs_at(const char *abspath, void *buf, size_t max, int64_t off)
{
    if (!abspath || !buf || max == 0) return -22;
    if (sysroot_lazy_init() != 0) return -2;
    char kbuf[SOTFS_SYSROOT_PATH_BYTES];
    const char *rel = sysroot_opkey(abspath, kbuf, sizeof(kbuf));
    if (!rel || !*rel) return -21;
    return (int)lucas_sysroot_pread(rel, buf, max, off);
}

static void fill_stat(const sotfs_sysroot_entry_t *e, struct lx_stat *out)
{
    memset(out, 0, sizeof(*out));
    if (!e || e->type == SOTFS_SYSROOT_TYPE_DIR) {
        out->st_mode = LX_S_IFDIR | 0555; out->st_nlink = 2;
    } else if (e->type == SOTFS_SYSROOT_TYPE_LNK) {
        out->st_mode = LX_S_IFLNK | 0777; out->st_size = (int64_t)e->size;
        out->st_nlink = 1;
    } else {
        /* 0755, NOT 0444: the sysroot holds /usr/bin binaries (dpkg, dpkg-split,
         * dpkg-deb, ld, …) as well as libs.  A read-only 0444 made every binary
         * appear NON-EXECUTABLE → apt's `apt-get install` PATH-search for an
         * executable dpkg rejected /usr/bin/dpkg, ended up with an EMPTY Args[0],
         * and its forked child's `execvp("")` made no execve at all → "Sub-process
         * /usr/bin/dpkg returned an error code (100)" with no unpack.  Real /usr
         * binaries are 0755; .so files vary (0644/0755) but 0755 is realistic and
         * carries no recon tell. */
        out->st_mode = LX_S_IFREG | 0755; out->st_size = (int64_t)e->size;
        out->st_blocks = ((int64_t)e->size + 511) / 512; out->st_nlink = 1;
    }
    out->st_blksize = 4096; out->st_dev = 7;
    /* Unique inode per entry.  musl's ld.so dedups already-loaded shared
     * libraries by (st_dev, st_ino); a constant ino made every 2nd+ dependency
     * fstat identical to the first, so musl treated it as already-loaded and
     * silently skipped mapping it (a real bin → libwayland → libffi chain:
     * libffi opened but never mapped → "ffi_call: symbol not found" relocating
     * libwayland).  The entry index is a stable per-file id; +2 stays clear of
     * the /usr root dir (ino 1).  A symlink resolves to its target entry first,
     * so it correctly reports the target's inode. */
    out->st_ino = e ? (uint64_t)(e - g_entries) + 2 : 1;
    /* clock-fidelity · the read-only sysroot (/usr) is born at the image wall
     * clock, not 1970 — `ls -la /` / `ls -l /usr/...` must not show "Jan 1 1970". */
    { int64_t s, n; lucas_now_realtime(&s, &n); (void)n;
      out->st_mtime = (uint64_t)s; out->st_atime = (uint64_t)s; out->st_ctime = (uint64_t)s; }
}

static int op_stat(void *b, const char *path, struct lx_stat *out)
{
    (void)b;
    if (sysroot_lazy_init() != 0) return -2;
    const char *r = rel(path);
    if (*r == '\0') { fill_stat(NULL, out); return 0; }   /* /usr root */
    int err;
    const sotfs_sysroot_entry_t *e = find_follow(r, &err); /* stat(2) follows links */
    if (!e) return err;                                    /* ENOENT / EIO / ELOOP */
    fill_stat(e, out); return 0;
}

static int op_readlink(void *b, const char *path, char *buf, size_t size)
{
    (void)b;
    if (sysroot_lazy_init() != 0) return -2;
    const char *r = rel(path);
    /* The /usr root EXISTS (it's a DIR, not a link) → EINVAL, NOT ENOENT.  musl's
     * realpath() readlinks EVERY path component and treats EINVAL as "not a
     * symlink, proceed" but ENOENT as "path missing, fail".  Returning ENOENT for
     * the root broke realpath() of any /usr/... path → Wine's ntdll "cannot get
     * path to ntdll.so" (it dladdr+realpath()s its own /usr/lib/wine/... path). */
    if (*r == '\0') return -22;                          /* EINVAL · root dir, not a link */
    const sotfs_sysroot_entry_t *e = find(r);            /* NO follow · the link itself */
    if (!e) return -2;                                   /* ENOENT */
    if (e->type != SOTFS_SYSROOT_TYPE_LNK) return -22;   /* EINVAL · not a link */
    uint64_t n = e->size < size ? e->size : size;        /* readlink(2): silent truncate */
    if (read_blob(e->offset, buf, n) != 0) return -5;    /* EIO */
    return (int)n;
}

static int op_fstat(void *b, void *h, struct lx_stat *out)
{
    (void)b;
    struct sysroot_handle *hd = (struct sysroot_handle *)h;
    if (!hd || !hd->in_use) return -9;
    fill_stat(hd->entry_idx < 0 ? NULL : &g_entries[hd->entry_idx], out);
    return 0;
}

/* getdents: list entries whose parent dir == the open dir's relpath.
 * Symlink-to-dir handles were followed at open (op_open resolves LNK), so
 * this lists the TARGET dir's children — Linux semantics.  No "." / ".."
 * entries are synthesized (matches backends_static/sotfs; musl readdir and
 * plain ls tolerate it · only `ls -a` could tell). */
static int64_t op_getdents(void *b, void *h, void *dirp, size_t count, int64_t *cursor)
{
    (void)b;
    struct sysroot_handle *hd = (struct sysroot_handle *)h;
    if (!hd || !hd->in_use || !cursor) return -22;
    /* getdents64(2) on a non-directory fd → ENOTDIR (a LNK entry can only
     * get here via an O_NOFOLLOW handle; entry_idx < 0 is the /usr root). */
    if (hd->entry_idx >= 0 && g_entries[hd->entry_idx].type != SOTFS_SYSROOT_TYPE_DIR)
        return -20;
    const char *dir = (hd->entry_idx < 0) ? "" : g_entries[hd->entry_idx].path;
    size_t dirlen = strlen(dir);

    uint8_t *out = (uint8_t *)dirp; size_t written = 0;
    /* *cursor walks the entry table; we emit children of `dir` only. */
    while (*cursor < (int64_t)g_hdr.count) {
        const sotfs_sysroot_entry_t *e = &g_entries[*cursor];
        (*cursor)++;
        const char *p = e->path;
        /* child iff p starts with dir + "/" and has no further '/' after. */
        if (dirlen) {
            if (strncmp(p, dir, dirlen) != 0 || p[dirlen] != '/') continue;
            p += dirlen + 1;
        }
        if (*p == '\0' || strchr(p, '/')) continue;   /* skip self / grandchildren */
        size_t name_len = strlen(p) + 1;
        size_t reclen = (offsetof(struct lx_dirent64, d_name) + name_len + 7) & ~(size_t)7;
        if (written + reclen > count) {
            (*cursor)--;                  /* never consume the unsent entry — */
            if (written == 0) return -22; /* EINVAL leaves the position unchanged
                                           * (Linux) · a bigger retry resumes here */
            break;
        }
        struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
        de->d_ino = (uint64_t)(*cursor); de->d_off = *cursor; de->d_reclen = (uint16_t)reclen;
        de->d_type = (e->type == SOTFS_SYSROOT_TYPE_DIR) ? LX_DT_DIR
                   : (e->type == SOTFS_SYSROOT_TYPE_LNK) ? LX_DT_LNK : LX_DT_REG;
        memcpy(de->d_name, p, name_len);
        written += reclen;
    }
    return (int64_t)written;
}

static const vfs_ops_t sysroot_ops = {
    .open = op_open, .close = op_close, .read = op_read, .write = NULL,
    .stat = op_stat, .fstat = op_fstat, .getdents = op_getdents, .readlink = op_readlink,
    .dup_handle = op_dup_handle,
};

vfs_mount_t lucas_sysroot_mount(void)
{
    memset(g_handles, 0, sizeof(g_handles));
    /* entry_idx == -1 marks a NEVER-USED (or closed /usr-root) slot · alloc_handle_slot
     * prefers these over recycling a closed file slot, so closed NLS-section handles
     * keep their identity for a later SCM_RIGHTS dup (see alloc_handle_slot). */
    for (int i = 0; i < SYSROOT_MAX_HANDLES; ++i) g_handles[i].entry_idx = -1;
    /* Eagerly read the entry table so '[sysroot] ready · N entries · mounted /usr'
     * prints at boot (when vfs_install_defaults runs) rather than on the first
     * /usr open/stat.  virtio-blk is ready by mount time — backends_sotfs.c
     * relies on the same precondition for its boot-time graph-capacity print. */
    sysroot_lazy_init();
    return (vfs_mount_t){ .prefix = "/usr", .ops = &sysroot_ops, .backend_state = (void *)1 };
}
