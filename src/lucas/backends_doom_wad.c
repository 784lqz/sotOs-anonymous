/*
 * sotOs · LUCAS · Doom WAD VFS backend.
 *
 * Mount prefix:        "/doom1.wad"
 * Single exposed file: "/doom1.wad"
 *
 * On-disk layout: the WAD is a binstore blob named "doom1.wad" packed into
 * sotfs.img[28 MiB .. 64 MiB).  binstore_lookup("doom1.wad", &base_off)
 * returns the blob size and sets base_off to its absolute byte offset in
 * the image.  Reads are sector-by-sector via virtio_blk_read_sector,
 * mirroring backends_python_stdlib.c.
 *
 * Concurrency: orch is single-threaded · the file-scope sector_buf is safe.
 */

#include "backends_doom_wad.h"
#include <sotfs/binstore.h>
#include <sotfs/storage_virtio_blk.h>
#include <lucas/vfs.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ── cached lookup state ─────────────────────────────────────────────── */

static uint64_t g_wad_base_off  = 0;
static uint64_t g_wad_size      = 0;
static int      g_initialized   = 0;
static int      g_ready         = 0;

static int doom_wad_lazy_init(void)
{
    if (g_initialized) return g_ready ? 0 : -2;
    g_initialized = 1;

    uint64_t off = 0;
    long sz = binstore_lookup("doom1.wad", &off);
    if (sz < 0) {
        printf("[doom-wad] binstore_lookup('doom1.wad') failed · rc=%ld · WAD not in binstore\n", sz);
        return -2;
    }
    if (sz == 0) {
        printf("[doom-wad] doom1.wad has zero size in binstore\n");
        return -2;
    }

    g_wad_base_off = off;
    g_wad_size     = (uint64_t)sz;
    g_ready        = 1;
    printf("[doom-wad] mount installed · size=%lu bytes · disk_off=%lu\n",
           (unsigned long)g_wad_size, (unsigned long)g_wad_base_off);
    return 0;
}

/* ── per-open handle ─────────────────────────────────────────────────── */

struct wad_handle {
    bool in_use;
};

#define WAD_MAX_HANDLES 4
static struct wad_handle g_handles[WAD_MAX_HANDLES];

/* ── ops ─────────────────────────────────────────────────────────────── */

/*
 * op_open: the mount prefix is "/doom1.wad"; vfs_resolve strips the prefix
 * and passes the remaining suffix as `path`.  For an open of exactly
 * "/doom1.wad" the suffix is "" (empty string after stripping "/doom1.wad").
 * We accept both "" and "/" as the suffix so doom's fopen("/doom1.wad") works
 * regardless of how vfs strips the prefix.
 */
static int op_open(void *backend, const char *path, int flags, uint32_t mode, void **out_handle)
{
    (void)backend; (void)flags; (void)mode;

    int rc = doom_wad_lazy_init();
    if (rc != 0) return -2;  /* -ENOENT */

    /* Accept "" or "/" as the suffix (vfs strips the mount prefix "/doom1.wad"). */
    if (path[0] != '\0' && !(path[0] == '/' && path[1] == '\0')) {
        return -2;  /* -ENOENT · path is something other than /doom1.wad */
    }

    for (int i = 0; i < WAD_MAX_HANDLES; ++i) {
        if (!g_handles[i].in_use) {
            g_handles[i].in_use = true;
            *out_handle = &g_handles[i];
            printf("[doom-wad] open · slot=%d\n", i);
            return 0;
        }
    }
    return -24;  /* -EMFILE */
}

static int op_close(void *backend, void *handle)
{
    (void)backend;
    struct wad_handle *h = (struct wad_handle *)handle;
    if (h) h->in_use = false;
    return 0;
}

static int64_t op_read(void *backend, void *handle, void *buf, size_t count, int64_t cursor)
{
    (void)backend;
    struct wad_handle *h = (struct wad_handle *)handle;
    if (!h || !h->in_use) return -9;   /* -EBADF */
    if (!g_ready)          return -5;  /* -EIO · unreachable post-open */
    if (cursor < 0)        return -22; /* -EINVAL */
    if ((uint64_t)cursor >= g_wad_size) return 0;  /* EOF */

    /* Clamp count to remaining bytes. */
    uint64_t remaining = g_wad_size - (uint64_t)cursor;
    if ((uint64_t)count > remaining) count = (size_t)remaining;

    /* Read sector-by-sector from disk.
     * disk offset = g_wad_base_off + cursor  (binstore blob's absolute disk byte offset) */
    uint64_t disk_off = g_wad_base_off + (uint64_t)cursor;
    size_t   copied   = 0;
    static uint8_t sector_buf[512];

    while (copied < count) {
        uint64_t sector    = disk_off / 512u;
        size_t   inner_off = (size_t)(disk_off % 512u);
        int rc = virtio_blk_read_sector(sector, sector_buf);
        if (rc != 0) {
            printf("[doom-wad] read failed · sector=%lu rc=%d\n",
                   (unsigned long)sector, rc);
            return -5;  /* -EIO */
        }

        size_t chunk = 512 - inner_off;
        if (chunk > count - copied) chunk = count - copied;
        memcpy((uint8_t *)buf + copied, sector_buf + inner_off, chunk);
        copied   += chunk;
        disk_off += chunk;
    }

    return (int64_t)copied;
}

static int op_stat(void *backend, const char *path, struct lx_stat *out)
{
    (void)backend;
    int rc = doom_wad_lazy_init();
    if (rc != 0) return -2;
    /* Accept "" or "/" as the suffix. */
    if (path[0] != '\0' && !(path[0] == '/' && path[1] == '\0')) return -2;

    memset(out, 0, sizeof(*out));
    out->st_mode    = LX_S_IFREG | 0444;
    out->st_size    = (int64_t)g_wad_size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)g_wad_size + 511) / 512;
    out->st_nlink   = 1;
    out->st_dev     = 7;   /* distinct from other backends */
    out->st_ino     = 1;
    return 0;
}

static int op_fstat(void *backend, void *handle, struct lx_stat *out)
{
    (void)backend;
    struct wad_handle *h = (struct wad_handle *)handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    if (!g_ready)          return -5; /* -EIO · unreachable */

    memset(out, 0, sizeof(*out));
    out->st_mode    = LX_S_IFREG | 0444;
    out->st_size    = (int64_t)g_wad_size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)g_wad_size + 511) / 512;
    out->st_nlink   = 1;
    out->st_dev     = 7;
    out->st_ino     = 1;
    return 0;
}

static const vfs_ops_t doom_wad_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = NULL,    /* read-only */
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = NULL,
    .readlink = NULL,
};

/* ── public mount-installation entrypoint ────────────────────────────── */

vfs_mount_t lucas_doom_wad_mount(void)
{
    memset(g_handles, 0, sizeof(g_handles));

    return (vfs_mount_t) {
        .prefix        = "/doom1.wad",
        .ops           = &doom_wad_ops,
        .backend_state = (void *)1,  /* non-NULL sentinel */
    };
}
