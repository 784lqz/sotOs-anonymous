/*
 * sotOs · LUCAS · PTY VFS backend.
 *
 * Mounted at prefix "/dev/p" which covers both:
 *   /dev/ptmx       - open returns a master fd for a new PTY pair
 *   /dev/pts/N      - open returns the slave fd for PTY pair N
 *
 * Internals:
 *   - Pool of LUCAS_MAX_PTYS (2) pairs, each with two 256-byte ring buffers:
 *       ring_m2s: master writes → slave reads
 *       ring_s2m: slave writes → master reads
 *   - No state.h modification: uses LUCAS_FD_VFS kind; the handle pointer
 *     points into a static handle pool (pty_handle_t g_handles[]).
 *   - termios and winsize stored per-pair; no line-discipline enforcement.
 *
 * L10 Phase-A: infrastructure only (ring I/O + open routing).
 * Full interactive vi support requires line-discipline + signalfd (Phase-B).
 */

#include <lucas/vfs.h>
#include "state.h"
#include <lucas/linux_abi.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── constants ────────────────────────────────────────────────────────────── */

/* Keep pool small to fit within orch's allocman budget.
 * Ring is 256 bytes: sufficient for the L10 demo ("HELLO-PTY\n" = 10 bytes).
 * Phase-B can bump these when pool budget is expanded. */
#define LUCAS_MAX_PTYS       2
#define LUCAS_PTY_RING_BYTES 256
#define LUCAS_PTY_HANDLES    (LUCAS_MAX_PTYS * 2)  /* master + slave per pair */

/* ── PTY pair state ───────────────────────────────────────────────────────── */

typedef struct {
    int  in_use;

    /* Two ring buffers: master writes → slave reads (m2s), slave writes → master reads (s2m).
     * head = write pointer (next write position, absolute),
     * tail = read  pointer (next read  position, absolute).
     * Available bytes = head - tail.  Buffer is circular with LUCAS_PTY_RING_BYTES modulus. */
    char   ring_m2s[LUCAS_PTY_RING_BYTES];
    char   ring_s2m[LUCAS_PTY_RING_BYTES];
    size_t m2s_head, m2s_tail;
    size_t s2m_head, s2m_tail;

    /* Stored termios and window size (no enforcement; just accept/return). */
    struct lx_termios termios;
    struct lx_winsize winsize;
} lucas_pty_pair_t;

/* ── per-open handle ──────────────────────────────────────────────────────── */

typedef struct {
    bool in_use;
    int  pair_idx;   /* index into g_pairs */
    bool is_master;  /* true → master side, false → slave side */
} pty_handle_t;

/* ── static storage ──────────────────────────────────────────────────────── */

static lucas_pty_pair_t g_pairs[LUCAS_MAX_PTYS];
static pty_handle_t     g_handles[LUCAS_PTY_HANDLES];

/* ── ring I/O helpers ─────────────────────────────────────────────────────── */

/* Read up to `n` bytes from ring (head/tail as absolute counters).
 * Returns actual bytes read. */
static size_t ring_read(const char *ring, size_t ring_size,
                         size_t *head, size_t *tail,
                         void *buf, size_t n)
{
    size_t avail = *head - *tail;
    if (n > avail) n = avail;
    for (size_t i = 0; i < n; ++i) {
        ((uint8_t *)buf)[i] = (uint8_t)ring[(*tail + i) % ring_size];
    }
    *tail += n;
    return n;
}

/* Write up to `n` bytes into ring.  Silently drops bytes that would
 * overflow (ring_size limit).  Returns bytes actually written. */
static size_t ring_write(char *ring, size_t ring_size,
                          size_t *head, size_t *tail,
                          const void *buf, size_t n)
{
    size_t free_space = ring_size - (*head - *tail);
    if (n > free_space) n = free_space;
    for (size_t i = 0; i < n; ++i) {
        ring[(*head + i) % ring_size] = (char)((const uint8_t *)buf)[i];
    }
    *head += n;
    return n;
}

/* ── op_open ──────────────────────────────────────────────────────────────── */

/*
 * The VFS layer strips the mount prefix ("/dev/p") from the client path
 * before calling us, so `path` is the suffix:
 *   /dev/ptmx     → prefix="/dev/p",  suffix = "tmx"    (or "/tmx" — depends on trailing '/')
 * Actually, vfs_resolve gives suffix = path + prefix_len.  For prefix "/dev/p":
 *   path="/dev/ptmx"   → suffix = "tmx"
 *   path="/dev/pts/0"  → suffix = "ts/0"
 *
 * We match on the FULL client path from the state if possible, but since we
 * only receive the suffix, we check:
 *   suffix == "tmx"  → /dev/ptmx  → allocate new master
 *   suffix starts with "ts/"      → /dev/pts/N → slave of pair N
 */
static int op_open(void *backend, const char *path, int flags, uint32_t mode,
                   void **out_handle)
{
    (void)backend; (void)flags; (void)mode;

    /* Allocate a handle slot. */
    int hslot = -1;
    for (int i = 0; i < LUCAS_PTY_HANDLES; ++i) {
        if (!g_handles[i].in_use) { hslot = i; break; }
    }
    if (hslot < 0) return -24;  /* -EMFILE */

    /* Discriminate on path suffix (see comment above). */
    if (strcmp(path, "tmx") == 0 || strcmp(path, "/tmx") == 0 ||
        strcmp(path, "/ptmx") == 0) {
        /* /dev/ptmx: allocate a new PTY pair. */
        int pidx = -1;
        for (int i = 0; i < LUCAS_MAX_PTYS; ++i) {
            if (!g_pairs[i].in_use) { pidx = i; break; }
        }
        if (pidx < 0) return -24;  /* -EMFILE: too many PTYs */

        memset(&g_pairs[pidx], 0, sizeof(g_pairs[pidx]));
        g_pairs[pidx].in_use = 1;

        /* Sensible default termios (raw-ish, as would come from cfmakeraw). */
        g_pairs[pidx].termios.c_iflag = 0x4500;
        g_pairs[pidx].termios.c_oflag = 0x5;
        g_pairs[pidx].termios.c_cflag = 0xbf;
        g_pairs[pidx].termios.c_lflag = 0x8a3b;
        g_pairs[pidx].winsize.ws_row   = 24;
        g_pairs[pidx].winsize.ws_col   = 80;

        g_handles[hslot].in_use    = true;
        g_handles[hslot].pair_idx  = pidx;
        g_handles[hslot].is_master = true;
        *out_handle = &g_handles[hslot];

        printf("[pty] ptmx allocated · pair %d · ring %u bytes\n",
               pidx, (unsigned)LUCAS_PTY_RING_BYTES);
        return 0;
    }

    /* /dev/pts/N: open the slave end of an existing pair.
     * Suffix is "ts/N" (prefix="/dev/p" was stripped). */
    const char *pts_num = NULL;
    if (strncmp(path, "ts/", 3) == 0) {
        pts_num = path + 3;
    } else if (strncmp(path, "/pts/", 5) == 0) {
        pts_num = path + 5;
    } else if (strncmp(path, "ts", 2) == 0 && path[2] == '\0') {
        /* /dev/pts directory open · return ENOENT (no dir listing needed). */
        return -2;  /* -ENOENT */
    }

    if (pts_num) {
        /* Parse the pair index. */
        int pidx = 0;
        if (*pts_num >= '0' && *pts_num <= '9') {
            pidx = *pts_num - '0';
        } else {
            return -2;  /* -ENOENT: not a digit */
        }
        if (pidx < 0 || pidx >= LUCAS_MAX_PTYS) return -2;
        if (!g_pairs[pidx].in_use) return -2;  /* -ENOENT */

        g_handles[hslot].in_use    = true;
        g_handles[hslot].pair_idx  = pidx;
        g_handles[hslot].is_master = false;
        *out_handle = &g_handles[hslot];

        printf("[pty] slave open · pair %d\n", pidx);
        return 0;
    }

    return -2;  /* -ENOENT */
}

/* ── op_close ─────────────────────────────────────────────────────────────── */

static int op_close(void *backend, void *handle)
{
    (void)backend;
    pty_handle_t *h = handle;
    if (!h) return 0;
    h->in_use = false;
    /* If no handles remain for this pair, free it. */
    int pidx = h->pair_idx;
    bool any_open = false;
    for (int i = 0; i < LUCAS_PTY_HANDLES; ++i) {
        if (g_handles[i].in_use && g_handles[i].pair_idx == pidx) {
            any_open = true;
            break;
        }
    }
    if (!any_open && pidx >= 0 && pidx < LUCAS_MAX_PTYS) {
        g_pairs[pidx].in_use = 0;
        printf("[pty] pair %d freed (no open handles)\n", pidx);
    }
    return 0;
}

/* ── op_read ──────────────────────────────────────────────────────────────── */

static int64_t op_read(void *backend, void *handle, void *buf,
                        size_t count, int64_t cursor)
{
    (void)backend; (void)cursor;
    pty_handle_t *h = handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    int pidx = h->pair_idx;
    if (pidx < 0 || pidx >= LUCAS_MAX_PTYS || !g_pairs[pidx].in_use) return -9;

    lucas_pty_pair_t *p = &g_pairs[pidx];
    size_t n;
    if (h->is_master) {
        /* Master reads slave's output (s2m ring). */
        n = ring_read(p->ring_s2m, LUCAS_PTY_RING_BYTES,
                      &p->s2m_head, &p->s2m_tail, buf, count);
        if (n > 0)
            printf("[pty] master read %zu bytes (pair %d)\n", n, pidx);
    } else {
        /* Slave reads master's output (m2s ring). */
        n = ring_read(p->ring_m2s, LUCAS_PTY_RING_BYTES,
                      &p->m2s_head, &p->m2s_tail, buf, count);
        if (n > 0)
            printf("[pty] slave read %zu bytes (pair %d)\n", n, pidx);
    }
    return (int64_t)n;
}

/* ── op_write ─────────────────────────────────────────────────────────────── */

static int64_t op_write(void *backend, void *handle, const void *buf,
                         size_t count, int64_t cursor)
{
    (void)backend; (void)cursor;
    pty_handle_t *h = handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    int pidx = h->pair_idx;
    if (pidx < 0 || pidx >= LUCAS_MAX_PTYS || !g_pairs[pidx].in_use) return -9;

    lucas_pty_pair_t *p = &g_pairs[pidx];
    size_t n;
    if (h->is_master) {
        /* Master writes into m2s (slave reads it). */
        n = ring_write(p->ring_m2s, LUCAS_PTY_RING_BYTES,
                       &p->m2s_head, &p->m2s_tail, buf, count);
        printf("[pty] master write %zu bytes (pair %d)\n", n, pidx);
    } else {
        /* Slave writes into s2m (master reads it). */
        n = ring_write(p->ring_s2m, LUCAS_PTY_RING_BYTES,
                       &p->s2m_head, &p->s2m_tail, buf, count);
        printf("[pty] slave write %zu bytes (pair %d)\n", n, pidx);
    }
    return (int64_t)n;
}

/* ── op_stat ──────────────────────────────────────────────────────────────── */

static int op_stat(void *backend, const char *path, struct lx_stat *out)
{
    (void)backend;
    memset(out, 0, sizeof(*out));

    /* /dev/ptmx appears as a character device. */
    if (strcmp(path, "tmx") == 0 || strcmp(path, "/tmx") == 0 ||
        strcmp(path, "/ptmx") == 0) {
        out->st_mode    = LX_S_IFCHR | 0666;
        out->st_rdev    = 0x0502;  /* major=5, minor=2 (Linux ptmx) */
        out->st_blksize = 4096;
        out->st_nlink   = 1;
        out->st_dev     = 5;
        out->st_ino     = 2;
        return 0;
    }

    /* /dev/pts/N */
    const char *pts_num = NULL;
    if (strncmp(path, "ts/", 3) == 0) pts_num = path + 3;
    else if (strncmp(path, "/pts/", 5) == 0) pts_num = path + 5;
    if (pts_num) {
        int pidx = (*pts_num >= '0' && *pts_num <= '9') ? (*pts_num - '0') : -1;
        if (pidx >= 0 && pidx < LUCAS_MAX_PTYS && g_pairs[pidx].in_use) {
            out->st_mode    = LX_S_IFCHR | 0620;
            out->st_rdev    = (uint64_t)((136 << 8) | pidx);  /* major=136 */
            out->st_blksize = 4096;
            out->st_nlink   = 1;
            out->st_dev     = 5;
            out->st_ino     = (uint64_t)(10 + pidx);
            return 0;
        }
        return -2;  /* -ENOENT */
    }

    return -2;  /* -ENOENT */
}

/* ── op_fstat ─────────────────────────────────────────────────────────────── */

static int op_fstat(void *backend, void *handle, struct lx_stat *out)
{
    (void)backend;
    pty_handle_t *h = handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    int pidx = h->pair_idx;

    memset(out, 0, sizeof(*out));
    out->st_blksize = 4096;
    out->st_nlink   = 1;
    out->st_dev     = 5;

    if (h->is_master) {
        out->st_mode = LX_S_IFCHR | 0666;
        out->st_rdev = 0x0502;  /* ptmx */
        out->st_ino  = 2;
    } else {
        out->st_mode = LX_S_IFCHR | 0620;
        out->st_rdev = (uint64_t)((136 << 8) | pidx);
        out->st_ino  = (uint64_t)(10 + pidx);
    }
    return 0;
}

/* ── op_readlink ──────────────────────────────────────────────────────────── */

static int op_readlink(void *backend, const char *path, char *buf, size_t size)
{
    (void)backend; (void)path; (void)buf; (void)size;
    return -22;  /* -EINVAL: no symlinks */
}

/* ── getdents: not needed ─────────────────────────────────────────────────── */

/* ── vfs_ops_t table ──────────────────────────────────────────────────────── */

static const vfs_ops_t pty_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = op_write,
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = NULL,
    .readlink = op_readlink,
};

/* ── public mount-installation entrypoint ──────────────────────────────────── */

/*
 * lucas_pty_mount() — returns the vfs_mount_t for the PTY backend.
 *
 * Prefix "/dev/p" is chosen because it is the longest common prefix of
 * "/dev/ptmx" and "/dev/pts/N" that doesn't conflict with any other mount.
 * The VFS longest-prefix match will prefer this over the "/" root mount for
 * all /dev/pt* paths.
 */
vfs_mount_t lucas_pty_mount(void)
{
    memset(g_pairs,   0, sizeof(g_pairs));
    memset(g_handles, 0, sizeof(g_handles));
    printf("[pty] PTY backend init · max_pairs=%d ring=%d bytes\n",
           LUCAS_MAX_PTYS, LUCAS_PTY_RING_BYTES);
    return (vfs_mount_t) {
        .prefix        = "/dev/p",
        .ops           = &pty_ops,
        .backend_state = (void *)1,  /* non-NULL sentinel */
    };
}

/* ── ptsname helper (used by grantpt/unlockpt stubs) ────────────────────────
 *
 * Given a VFS handle pointer (which callers obtained via open("/dev/ptmx")),
 * returns the slave device path string.  Exported so handlers_proc.c can
 * implement TIOCGPTN / ptsname ioctl if needed in Phase-B.
 */
int lucas_pty_ptsname(void *handle, char *buf, size_t len)
{
    pty_handle_t *h = handle;
    if (!h || !h->in_use || !h->is_master) return -9;
    /* Write "/dev/pts/N\0" into buf. */
    int n = (int)(sizeof("/dev/pts/0") - 1);
    if ((int)len < n + 1) return -22;  /* -EINVAL */
    snprintf(buf, len, "/dev/pts/%d", h->pair_idx);
    return 0;
}
