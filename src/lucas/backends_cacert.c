/*
 * sotOs · LUCAS · CA-certificates VFS backend.
 *
 * Mount prefix:        "/etc/ssl/cert.pem"
 * Single exposed file: "/etc/ssl/cert.pem"
 *
 * On-disk layout: the real Alpine ca-certificates bundle is a binstore blob
 * named "ca-certificates.crt" packed into sotfs.img[28 MiB .. 64 MiB).
 * binstore_lookup("ca-certificates.crt", &base_off) returns the blob size and
 * its absolute byte offset; reads are sector-by-sector via
 * virtio_blk_read_sector (mirrors backends_doom_wad.c / backends_python_stdlib.c).
 *
 * Concurrency: orch is single-threaded · the file-scope sector_buf is safe.
 */

#include "backends_cacert.h"
#include <sotfs/binstore.h>
#include <sotfs/storage_virtio_blk.h>
#include <lucas/vfs.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

static uint64_t g_ca_base_off = 0;
static uint64_t g_ca_size     = 0;
static int      g_initialized = 0;
static int      g_ready       = 0;

static int cacert_lazy_init(void)
{
    if (g_initialized) return g_ready ? 0 : -2;
    g_initialized = 1;

    uint64_t off = 0;
    long sz = binstore_lookup("ca-certificates.crt", &off);
    if (sz <= 0) {
        printf("[cacert] binstore_lookup('ca-certificates.crt') failed · rc=%ld\n", sz);
        return -2;
    }
    g_ca_base_off = off;
    g_ca_size     = (uint64_t)sz;
    g_ready       = 1;
    printf("[cacert] mount installed · /etc/ssl/cert.pem · size=%lu bytes · disk_off=%lu\n",
           (unsigned long)g_ca_size, (unsigned long)g_ca_base_off);
    return 0;
}

struct cacert_handle { bool in_use; };

#define CACERT_MAX_HANDLES 4
static struct cacert_handle g_handles[CACERT_MAX_HANDLES];

/* The suffix after the mount prefix "/etc/ssl/cert.pem" is "" (exact match).
 * Accept "" or "/" so a path-normalising open still resolves. */
static int suffix_ok(const char *path)
{
    return path[0] == '\0' || (path[0] == '/' && path[1] == '\0');
}

static int op_open(void *backend, const char *path, int flags, uint32_t mode, void **out_handle)
{
    (void)backend; (void)flags; (void)mode;
    if (cacert_lazy_init() != 0) return -2;
    if (!suffix_ok(path)) return -2;
    for (int i = 0; i < CACERT_MAX_HANDLES; ++i) {
        if (!g_handles[i].in_use) {
            g_handles[i].in_use = true;
            *out_handle = &g_handles[i];
            return 0;
        }
    }
    return -24;  /* -EMFILE */
}

static int op_close(void *backend, void *handle)
{
    (void)backend;
    struct cacert_handle *h = (struct cacert_handle *)handle;
    if (h) h->in_use = false;
    return 0;
}

static int64_t op_read(void *backend, void *handle, void *buf, size_t count, int64_t cursor)
{
    (void)backend;
    struct cacert_handle *h = (struct cacert_handle *)handle;
    if (!h || !h->in_use) return -9;   /* -EBADF */
    if (!g_ready)          return -5;  /* -EIO */
    if (cursor < 0)        return -22; /* -EINVAL */
    if ((uint64_t)cursor >= g_ca_size) return 0;  /* EOF */

    uint64_t remaining = g_ca_size - (uint64_t)cursor;
    if ((uint64_t)count > remaining) count = (size_t)remaining;

    uint64_t disk_off = g_ca_base_off + (uint64_t)cursor;
    size_t   copied   = 0;
    static uint8_t sector_buf[512];
    while (copied < count) {
        uint64_t sector    = disk_off / 512u;
        size_t   inner_off = (size_t)(disk_off % 512u);
        if (virtio_blk_read_sector(sector, sector_buf) != 0) {
            printf("[cacert] read failed · sector=%lu\n", (unsigned long)sector);
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

static void fill_stat(struct lx_stat *out)
{
    memset(out, 0, sizeof(*out));
    out->st_mode    = LX_S_IFREG | 0444;
    out->st_size    = (int64_t)g_ca_size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)g_ca_size + 511) / 512;
    out->st_nlink   = 1;
    out->st_dev     = 9;   /* distinct from other backends */
    out->st_ino     = 1;
}

static int op_stat(void *backend, const char *path, struct lx_stat *out)
{
    (void)backend;
    if (cacert_lazy_init() != 0) return -2;
    if (!suffix_ok(path)) return -2;
    fill_stat(out);
    return 0;
}

static int op_fstat(void *backend, void *handle, struct lx_stat *out)
{
    (void)backend;
    struct cacert_handle *h = (struct cacert_handle *)handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    if (!g_ready)          return -5; /* -EIO */
    fill_stat(out);
    return 0;
}

static const vfs_ops_t cacert_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = NULL,    /* read-only */
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = NULL,
    .readlink = NULL,
};

vfs_mount_t lucas_cacert_mount(void)
{
    memset(g_handles, 0, sizeof(g_handles));
    return (vfs_mount_t) {
        .prefix        = "/etc/ssl/cert.pem",
        .ops           = &cacert_ops,
        .backend_state = (void *)1,  /* non-NULL sentinel */
    };
}
