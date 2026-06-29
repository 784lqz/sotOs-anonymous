/*
 * sotOs · LUCAS · python_stdlib VFS backend (L11-γ U2).
 *
 * Mount prefix:        "/install/lib"
 * Single exposed file: "/install/lib/python312.zip"
 *
 * On-disk layout (see include/sotfs/layout.h):
 *   sotfs.img[0 .. 4 KiB)         struct sotfs_stdlib_header (magic, version, zip_size)
 *   sotfs.img[4 KiB .. 28 MiB)    raw python312.zip bytes
 *
 * Lazy init reads sector 0 once and caches the header.  If magic mismatches
 * or zip_size is zero / oversize, the backend treats the file as absent
 * (returns -ENOENT for open/stat) · the "stdlib not populated" condition.
 *
 * Reads are sector-by-sector via virtio_blk_read_sector.  No caching · each
 * client read may trigger many virtio requests.  Acceptable for the L11-γ
 * Python bring-up.  Future U-batches can add a 1-sector look-aside cache
 * if zipimport's access pattern proves expensive.
 *
 * Concurrency: orch is single-threaded · the file-scope sector_buf is safe.
 */

#include <lucas/backends_python_stdlib.h>
#include <sotfs/layout.h>
#include <sotfs/storage_virtio_blk.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

/* ── cached header state ─────────────────────────────────────────────── */

static struct sotfs_stdlib_header g_header;
static int g_initialized = 0;
static int g_ready       = 0;       /* magic valid + zip_size in (0, SOTFS_STDLIB_MAX_BYTES] */

static int python_stdlib_lazy_init(void)
{
    if (g_initialized) return g_ready ? 0 : -2;
    g_initialized = 1;

    /* Read first sector (512 bytes) which contains the header at offset 0. */
    uint8_t sector_buf[512];
    int rc = virtio_blk_read_sector(0, sector_buf);
    if (rc != 0) {
        printf("[python-stdlib] virtio_blk_read_sector(0) failed · rc=%d\n", rc);
        return -2;
    }

    memcpy(&g_header, sector_buf, sizeof(g_header));
    if (g_header.magic != SOTFS_STDLIB_MAGIC) {
        printf("[python-stdlib] header magic mismatch · got 0x%x expected 0x%x · stdlib not populated\n",
               g_header.magic, SOTFS_STDLIB_MAGIC);
        return -2;
    }
    if (g_header.zip_size == 0 || g_header.zip_size > SOTFS_STDLIB_MAX_BYTES) {
        printf("[python-stdlib] invalid zip_size=%lu\n", (unsigned long)g_header.zip_size);
        return -2;
    }

    g_ready = 1;
    printf("[python-stdlib] mount installed · zip_size=%lu bytes · header version=%u\n",
           (unsigned long)g_header.zip_size, g_header.version);
    return 0;
}

/* ── per-open handle ─────────────────────────────────────────────────── */

struct stdlib_handle {
    bool in_use;
};

#define STDLIB_MAX_HANDLES 8
static struct stdlib_handle g_handles[STDLIB_MAX_HANDLES];

/* ── ops ─────────────────────────────────────────────────────────────── */

static int op_open(void *backend, const char *path, int flags, uint32_t mode, void **out_handle)
{
    (void)backend; (void)flags; (void)mode;

    int rc = python_stdlib_lazy_init();
    if (rc != 0) return -2;  /* -ENOENT */

    /* Path is the suffix after the mount prefix "/install/lib" was stripped.
     * For "/install/lib/python312.zip" the suffix is "/python312.zip". */
    if (strcmp(path, "/python312.zip") != 0) {
        return -2;  /* -ENOENT */
    }

    for (int i = 0; i < STDLIB_MAX_HANDLES; ++i) {
        if (!g_handles[i].in_use) {
            g_handles[i].in_use = true;
            *out_handle = &g_handles[i];
            printf("[python-stdlib] open · slot=%d\n", i);
            return 0;
        }
    }
    return -24;  /* -EMFILE */
}

static int op_close(void *backend, void *handle)
{
    (void)backend;
    struct stdlib_handle *h = (struct stdlib_handle *)handle;
    if (h) h->in_use = false;
    return 0;
}

static int64_t op_read(void *backend, void *handle, void *buf, size_t count, int64_t cursor)
{
    (void)backend;
    struct stdlib_handle *h = (struct stdlib_handle *)handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    if (!g_ready)          return -5; /* -EIO · should be unreachable post-open */
    if (cursor < 0)        return -22; /* -EINVAL */
    if ((uint64_t)cursor >= g_header.zip_size) return 0;  /* EOF */

    /* Clamp count to remaining bytes. */
    uint64_t remaining = g_header.zip_size - (uint64_t)cursor;
    if ((uint64_t)count > remaining) count = (size_t)remaining;

    /* Read sector-by-sector from disk, splice into caller buffer.
     * disk offset = SOTFS_STDLIB_ZIP_OFFSET + cursor. */
    uint64_t disk_off = (uint64_t)SOTFS_STDLIB_ZIP_OFFSET + (uint64_t)cursor;
    size_t   copied   = 0;
    static uint8_t sector_buf[512];

    while (copied < count) {
        uint64_t sector    = disk_off / 512u;
        size_t   inner_off = (size_t)(disk_off % 512u);
        int rc = virtio_blk_read_sector(sector, sector_buf);
        if (rc != 0) {
            printf("[python-stdlib] read failed · sector=%lu rc=%d\n",
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
    int rc = python_stdlib_lazy_init();
    if (rc != 0) return -2;
    if (strcmp(path, "/python312.zip") != 0) return -2;

    memset(out, 0, sizeof(*out));
    out->st_mode    = LX_S_IFREG | 0444;
    out->st_size    = (int64_t)g_header.zip_size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)g_header.zip_size + 511) / 512;
    out->st_nlink   = 1;
    out->st_dev     = 6;             /* distinct from other backends */
    out->st_ino     = 1;
    return 0;
}

static int op_fstat(void *backend, void *handle, struct lx_stat *out)
{
    (void)backend;
    struct stdlib_handle *h = (struct stdlib_handle *)handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    if (!g_ready)          return -5; /* -EIO · should be unreachable */

    memset(out, 0, sizeof(*out));
    out->st_mode    = LX_S_IFREG | 0444;
    out->st_size    = (int64_t)g_header.zip_size;
    out->st_blksize = 4096;
    out->st_blocks  = ((int64_t)g_header.zip_size + 511) / 512;
    out->st_nlink   = 1;
    out->st_dev     = 6;
    out->st_ino     = 1;
    return 0;
}

/* ── op_getdents ─────────────────────────────────────────────────────────
 *
 * The python_stdlib mount exposes a single virtual directory whose entries
 * are:
 *   cursor 0 → "."             (DT_DIR, d_ino = 1)
 *   cursor 1 → "python312.zip" (DT_REG, d_ino = 2)
 *   cursor ≥ 2 → end of directory (return 0)
 *
 * The cursor is owned by the caller (lucas_fd_t::cursor in handlers_fs.c)
 * and threaded through via the *cursor pointer · we mutate it in place so
 * subsequent calls resume where the previous one stopped.  Per STUB-AUDIT
 * Unit E spec: if even a single record will not fit in the caller buffer
 * we return -EINVAL (-22); otherwise we return total bytes written.
 */
static int64_t op_getdents(void *backend, void *handle, void *dirp,
                           size_t count, int64_t *cursor)
{
    (void)backend;
    struct stdlib_handle *h = (struct stdlib_handle *)handle;
    if (!h || !h->in_use) return -9;  /* -EBADF */
    if (!cursor)          return -22; /* -EINVAL · misuse */

    static const struct {
        const char *name;
        uint8_t     d_type;
        uint64_t    d_ino;
    } entries[] = {
        { ".",             LX_DT_DIR, 1 },
        { "python312.zip", LX_DT_REG, 2 },
    };
    const int n_entries = (int)(sizeof(entries) / sizeof(entries[0]));

    uint8_t *out     = (uint8_t *)dirp;
    size_t   written = 0;

    while (*cursor < n_entries) {
        const char *name     = entries[*cursor].name;
        size_t      name_len = strlen(name) + 1;  /* include trailing NUL */
        size_t      reclen   = (offsetof(struct lx_dirent64, d_name)
                                + name_len + 7) & ~(size_t)7;

        if (written + reclen > count) {
            /* Per spec: a single entry that does not fit is an error,
             * not a partial-success short read. */
            if (written == 0) return -22;  /* -EINVAL */
            break;
        }

        struct lx_dirent64 *de = (struct lx_dirent64 *)(out + written);
        de->d_ino    = entries[*cursor].d_ino;
        de->d_off    = (int64_t)(*cursor + 1);
        de->d_reclen = (uint16_t)reclen;
        de->d_type   = entries[*cursor].d_type;
        memcpy(de->d_name, name, name_len);

        written  += reclen;
        (*cursor) += 1;
    }

    return (int64_t)written;
}

static const vfs_ops_t python_stdlib_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = NULL,    /* read-only */
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = op_getdents,
    .readlink = NULL,
};

/* ── public mount-installation entrypoint ────────────────────────────── */

vfs_mount_t lucas_python_stdlib_mount(void)
{
    /* Reset handle pool on every mount (defensive · supports re-mount cycles). */
    memset(g_handles, 0, sizeof(g_handles));

    return (vfs_mount_t) {
        .prefix        = "/install/lib",
        .ops           = &python_stdlib_ops,
        .backend_state = (void *)1,  /* non-NULL sentinel */
    };
}
