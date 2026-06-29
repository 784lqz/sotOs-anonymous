/*
 * sotOs · LUCAS · U4 · POSIX shared-memory VFS backend.
 *
 * Mounted at prefix "/dev/shm".  Backs shm_open(name, ...) / shm_unlink(name)
 * by maintaining a pool of named, page-allocated in-memory objects.  Each
 * named object owns a single 4 KiB frame (vka_alloc_frame) and is mapped
 * into the orch's parent vspace (sel4utils_dup_and_map) so read/write ops
 * touch it as a plain byte buffer.
 *
 * δ-1 scope (this commit):
 *   - Single-sotbox lifetime: opens from the SAME sotbox to the SAME name
 *     return fds backed by the SAME 4 KiB frame.  Cross-process sharing
 *     (different client vspaces sharing one frame) is follow-up work · for
 *     now each sotbox has its own pool because the pool is file-scope
 *     static and orch is single-threaded.
 *   - Bounded: LUCAS_MAX_SHM_OBJECTS (= 8) named objects, one page each.
 *   - shm_unlink marks the object for deletion; the actual frame is freed
 *     when the last open handle is closed (POSIX semantics).
 *
 * The backend provides op_open / op_close / op_read / op_write / op_lseek
 * (no-op for VFS layer · seek-via-cursor is handled by lucas_sys_lseek
 * which mutates lucas_fd_t.cursor before the next read/write) / op_stat /
 * op_fstat.  No op_mmap is wired through VFS yet · MAP_SHARED is still
 * rejected by lucas_sys_mmap (see TODO at the bottom of this file).
 *
 * No state.h modification: the existing fd table (LUCAS_FD_VFS kind) is
 * sufficient.  Per-pair state lives in a file-scope static pool, matching
 * the pattern used by backends_pty.c.
 */

#include <lucas/vfs.h>
#include "state.h"
#include <lucas/linux_abi.h>

#include <sel4utils/mapping.h>
#include <vka/object.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* ── constants ────────────────────────────────────────────────────────────── */

/* Bounded · max 8 named shm objects per sotbox (file-scope pool).
 * One 4 KiB frame each = 32 KiB total worst-case footprint. */
#define LUCAS_MAX_SHM_OBJECTS  8
#define LUCAS_SHM_HANDLES      16   /* 2x to allow each object opened twice */
#define LUCAS_SHM_PAGE_BYTES   4096
#define LUCAS_SHM_NAME_MAX     63

/* ── named-object state ──────────────────────────────────────────────────── */

typedef struct {
    bool        in_use;          /* slot occupied? */
    bool        unlinked;        /* shm_unlink() called · drop when refcount→0 */
    int         open_count;      /* number of live handles referencing this object */
    char        name[LUCAS_SHM_NAME_MAX + 1];

    /* Page-allocated backing storage.  obj_cptr is the frame cap (so we can
     * vka_free_object() on last close).  local_map is the orch-side mapping
     * pointer (zeroed page, ready for memcpy on read/write). */
    vka_object_t frame_obj;
    void        *local_map;
} shm_object_t;

/* Per-open-fd handle.  The lucas_fd_t carries a pointer to this. */
typedef struct {
    bool in_use;
    int  obj_slot;   /* index into g_objects · or -1 if invalid */
    int  flags;
} shm_handle_t;

/* ── static storage ──────────────────────────────────────────────────────── */

static shm_object_t g_objects[LUCAS_MAX_SHM_OBJECTS];
static shm_handle_t g_handles[LUCAS_SHM_HANDLES];

/* ── name helpers ────────────────────────────────────────────────────────── */

/* shm_open POSIX accepts names starting with '/'; the path passed by VFS
 * here is the suffix after "/dev/shm" so a client-side "/dev/shm/foo"
 * arrives as "/foo".  Tolerate both forms ("foo" and "/foo"). */
static const char *normalise_name(const char *path) {
    if (!path) return NULL;
    while (*path == '/') path++;
    if (*path == '\0') return NULL;
    return path;
}

static int find_object_by_name(const char *name) {
    for (int i = 0; i < LUCAS_MAX_SHM_OBJECTS; ++i) {
        if (g_objects[i].in_use && !g_objects[i].unlinked &&
            strcmp(g_objects[i].name, name) == 0) {
            return i;
        }
    }
    return -1;
}

static int alloc_object_slot(void) {
    for (int i = 0; i < LUCAS_MAX_SHM_OBJECTS; ++i) {
        if (!g_objects[i].in_use) return i;
    }
    return -1;
}

static int alloc_handle_slot(void) {
    for (int i = 0; i < LUCAS_SHM_HANDLES; ++i) {
        if (!g_handles[i].in_use) return i;
    }
    return -1;
}

/* Persistent vka/vspace handles captured at mount time.
 *
 * Why: op_close runs from paths that do NOT call lucas_set_current_caller()
 * first · close_fd_entry (in handlers_fs.c) and lucas_close_all_fds (sotbox
 * exit) both invoke the backend's close op without threading st through.
 * If release_object relied solely on lucas_get_current_caller(), the free
 * would be silently skipped (st==NULL) and the 4 KiB frame + orch-side
 * mapping would leak.
 *
 * The vka and parent_vspace are root-task-owned and have process lifetime
 * (state.h header comment: "borrowed from the root task ... NOT freed by
 * lucas"), so caching them at mount time is safe: every sotbox shares the
 * same root vka/vspace by design. */
static vka_t    *g_vka = NULL;
static vspace_t *g_parent_vspace = NULL;

/* Release backing storage for an unused object slot.  Caller MUST have
 * decremented open_count to 0 before calling.
 *
 * Uses the cached g_vka / g_parent_vspace (captured at mount time) rather
 * than a per-call lucas_state_t pointer, because op_close can fire from
 * lucas_close_all_fds / close_fd_entry where lucas_get_current_caller()
 * is NULL. */
static void release_object(shm_object_t *obj) {
    if (!obj->in_use) return;
    if (obj->local_map && g_vka && g_parent_vspace) {
        sel4utils_unmap_dup(g_vka, g_parent_vspace,
                             obj->local_map, seL4_PageBits);
    }
    obj->local_map = NULL;
    if (obj->frame_obj.cptr != 0 && g_vka) {
        vka_free_object(g_vka, &obj->frame_obj);
    }
    memset(&obj->frame_obj, 0, sizeof(obj->frame_obj));
    obj->in_use    = false;
    obj->unlinked  = false;
    obj->open_count = 0;
    obj->name[0]   = '\0';
}

/* ── op_open ─────────────────────────────────────────────────────────────── */

static int op_open(void *backend, const char *path, int flags, uint32_t mode,
                   void **out_handle) {
    (void)backend; (void)mode;

    /* O_CREAT lives at 0x40, O_EXCL at 0x80 on Linux x86_64.  We accept
     * either presence/absence of these · POSIX shm_open passes them
     * straight through. */
    const int O_CREAT = 0x40;
    const int O_EXCL  = 0x80;

    const char *name = normalise_name(path);
    if (!name) return -22;                     /* -EINVAL */
    if (strlen(name) > LUCAS_SHM_NAME_MAX) return -36;  /* -ENAMETOOLONG */

    /* Caller state needed for vka_alloc_frame on first-create. */
    struct lucas_state *st = lucas_get_current_caller();
    if (!st) return -5;                        /* -EIO · should not happen */

    /* Latch vka / parent_vspace on first reach so release_object can free
     * frames from close paths that don't thread st (see g_vka comment). */
    if (g_vka == NULL) {
        g_vka = st->vka;
        g_parent_vspace = st->parent_vspace;
    }

    int slot = find_object_by_name(name);

    /* O_EXCL with O_CREAT and existing object → EEXIST. */
    if (slot >= 0 && (flags & O_CREAT) && (flags & O_EXCL)) {
        return -17;                            /* -EEXIST */
    }

    /* Not present and O_CREAT not requested → ENOENT (POSIX). */
    if (slot < 0 && !(flags & O_CREAT)) {
        return -2;                             /* -ENOENT */
    }

    /* Need to create: allocate slot, allocate frame, map locally. */
    if (slot < 0) {
        slot = alloc_object_slot();
        if (slot < 0) return -28;              /* -ENOSPC */

        shm_object_t *obj = &g_objects[slot];
        memset(obj, 0, sizeof(*obj));

        int err = vka_alloc_frame(st->vka, seL4_PageBits, &obj->frame_obj);
        if (err) {
            printf("[shm] vka_alloc_frame failed (err=%d) for '%s'\n", err, name);
            memset(obj, 0, sizeof(*obj));
            return -12;                        /* -ENOMEM */
        }

        /* Map the frame into the orch's parent vspace so we can memcpy
         * directly via obj->local_map.  This is the pattern used in
         * lucas_copy_from_client / lucas_copy_to_client (sel4utils_dup_and_map). */
        obj->local_map = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                                obj->frame_obj.cptr,
                                                seL4_PageBits);
        if (!obj->local_map) {
            printf("[shm] sel4utils_dup_and_map failed for '%s'\n", name);
            vka_free_object(st->vka, &obj->frame_obj);
            memset(obj, 0, sizeof(*obj));
            return -12;                        /* -ENOMEM */
        }
        /* Zero the page · POSIX shm_open returns a zero-initialised object. */
        memset(obj->local_map, 0, LUCAS_SHM_PAGE_BYTES);
        obj->in_use = true;
        strncpy(obj->name, name, LUCAS_SHM_NAME_MAX);
        obj->name[LUCAS_SHM_NAME_MAX] = '\0';
        printf("[shm] created '%s' · slot=%d frame_cap=0x%lx\n",
               obj->name, slot, (unsigned long)obj->frame_obj.cptr);
    }

    /* Allocate handle slot and bump refcount. */
    int hslot = alloc_handle_slot();
    if (hslot < 0) {
        /* If we JUST created the object on this call, roll the create
         * back to avoid leaking the slot.  We must NOT free a pre-existing
         * named region just because its current open_count is 0 (other
         * processes can still shm_open it by name) · track whether THIS
         * invocation transitioned slot from unallocated to created. */
        bool we_just_created = (g_objects[slot].open_count == 0 &&
                                !g_objects[slot].unlinked);
        /* Stricter signal: an object we just allocated has open_count==0
         * AND no other handle in g_handles references its slot.  Walk the
         * handle pool to confirm. */
        if (we_just_created) {
            for (int i = 0; i < LUCAS_SHM_HANDLES; ++i) {
                if (g_handles[i].in_use && g_handles[i].obj_slot == slot) {
                    we_just_created = false;
                    break;
                }
            }
        }
        if (we_just_created) {
            release_object(&g_objects[slot]);
        }
        return -24;                            /* -EMFILE */
    }
    g_handles[hslot].in_use   = true;
    g_handles[hslot].obj_slot = slot;
    g_handles[hslot].flags    = flags;
    g_objects[slot].open_count++;

    *out_handle = &g_handles[hslot];
    printf("[shm] open '%s' · slot=%d handle=%d refcnt=%d\n",
           g_objects[slot].name, slot, hslot, g_objects[slot].open_count);
    return 0;
}

/* ── op_close ────────────────────────────────────────────────────────────── */

static int op_close(void *backend, void *handle) {
    (void)backend;
    shm_handle_t *h = handle;
    if (!h || !h->in_use) return 0;

    int slot = h->obj_slot;
    h->in_use   = false;
    h->obj_slot = -1;

    if (slot < 0 || slot >= LUCAS_MAX_SHM_OBJECTS) return 0;
    shm_object_t *obj = &g_objects[slot];
    if (!obj->in_use) return 0;

    if (obj->open_count > 0) obj->open_count--;
    /* If the object was unlinked and no handles remain, drop the storage.
     * release_object uses g_vka / g_parent_vspace (latched at first open)
     * rather than lucas_get_current_caller() because this op fires from
     * close_fd_entry / lucas_close_all_fds where current_caller is NULL. */
    if (obj->open_count == 0 && obj->unlinked) {
        printf("[shm] freeing unlinked object '%s' (slot=%d)\n",
               obj->name, slot);
        release_object(obj);
    }
    return 0;
}

/* ── op_read ─────────────────────────────────────────────────────────────── */

static int64_t op_read(void *backend, void *handle, void *buf,
                        size_t count, int64_t cursor) {
    (void)backend;
    shm_handle_t *h = handle;
    if (!h || !h->in_use) return -9;           /* -EBADF */
    int slot = h->obj_slot;
    if (slot < 0 || slot >= LUCAS_MAX_SHM_OBJECTS) return -9;
    shm_object_t *obj = &g_objects[slot];
    if (!obj->in_use || !obj->local_map) return -9;

    if (cursor < 0) return -22;                /* -EINVAL */
    if ((size_t)cursor >= LUCAS_SHM_PAGE_BYTES) return 0;  /* EOF */
    size_t available = LUCAS_SHM_PAGE_BYTES - (size_t)cursor;
    if (count > available) count = available;
    memcpy(buf, (const uint8_t *)obj->local_map + cursor, count);
    return (int64_t)count;
}

/* ── op_write ────────────────────────────────────────────────────────────── */

static int64_t op_write(void *backend, void *handle, const void *buf,
                         size_t count, int64_t cursor) {
    (void)backend;
    shm_handle_t *h = handle;
    if (!h || !h->in_use) return -9;           /* -EBADF */
    int slot = h->obj_slot;
    if (slot < 0 || slot >= LUCAS_MAX_SHM_OBJECTS) return -9;
    shm_object_t *obj = &g_objects[slot];
    if (!obj->in_use || !obj->local_map) return -9;

    if (cursor < 0) return -22;
    if ((size_t)cursor >= LUCAS_SHM_PAGE_BYTES) return -27;  /* -EFBIG */
    size_t writable = LUCAS_SHM_PAGE_BYTES - (size_t)cursor;
    if (count > writable) count = writable;
    memcpy((uint8_t *)obj->local_map + cursor, buf, count);
    return (int64_t)count;
}

/* ── op_stat / op_fstat ──────────────────────────────────────────────────── */

static int op_stat(void *backend, const char *path, struct lx_stat *out) {
    (void)backend;
    const char *name = normalise_name(path);
    memset(out, 0, sizeof(*out));
    if (!name) {
        /* "/dev/shm" itself · advertise the directory. */
        out->st_mode    = LX_S_IFDIR | 0777;
        out->st_blksize = 4096;
        out->st_nlink   = 2;
        out->st_dev     = 7;
        out->st_ino     = 1;
        return 0;
    }
    int slot = find_object_by_name(name);
    if (slot < 0) return -2;                   /* -ENOENT */
    out->st_mode    = LX_S_IFREG | 0666;
    out->st_size    = LUCAS_SHM_PAGE_BYTES;
    out->st_blksize = 4096;
    out->st_nlink   = 1;
    out->st_dev     = 7;
    out->st_ino     = (uint64_t)(100 + slot);
    return 0;
}

static int op_fstat(void *backend, void *handle, struct lx_stat *out) {
    (void)backend;
    shm_handle_t *h = handle;
    if (!h || !h->in_use) return -9;
    int slot = h->obj_slot;
    if (slot < 0 || slot >= LUCAS_MAX_SHM_OBJECTS) return -9;
    if (!g_objects[slot].in_use) return -9;
    memset(out, 0, sizeof(*out));
    out->st_mode    = LX_S_IFREG | 0666;
    out->st_size    = LUCAS_SHM_PAGE_BYTES;
    out->st_blksize = 4096;
    out->st_nlink   = 1;
    out->st_dev     = 7;
    out->st_ino     = (uint64_t)(100 + slot);
    return 0;
}

/* ── op_readlink (no-op) ─────────────────────────────────────────────────── */

static int op_readlink(void *backend, const char *path, char *buf, size_t size) {
    (void)backend; (void)path; (void)buf; (void)size;
    return -22;                                /* -EINVAL · no symlinks */
}

/* ── vfs_ops_t table ─────────────────────────────────────────────────────── */

static const vfs_ops_t shm_ops = {
    .open     = op_open,
    .close    = op_close,
    .read     = op_read,
    .write    = op_write,
    .stat     = op_stat,
    .fstat    = op_fstat,
    .getdents = NULL,
    .readlink = op_readlink,
};

/* ── public mount-installation entrypoint ─────────────────────────────────── */

/*
 * lucas_shm_mount() — return the vfs_mount_t for the shm backend.
 *
 * Prefix "/dev/shm" is the POSIX-canonical mount point.  Longest-prefix
 * match in vfs_resolve() ensures /dev/shm/<name> binds here rather than
 * to the "/dev/p" PTY mount or the "/" static mount.
 */
vfs_mount_t lucas_shm_mount(void) {
    memset(g_objects, 0, sizeof(g_objects));
    memset(g_handles, 0, sizeof(g_handles));
    printf("[shm] U4 backend init · max_objects=%d page=%d bytes\n",
           LUCAS_MAX_SHM_OBJECTS, LUCAS_SHM_PAGE_BYTES);
    return (vfs_mount_t) {
        .prefix        = "/dev/shm",
        .ops           = &shm_ops,
        .backend_state = (void *)1,   /* non-NULL sentinel */
    };
}

/* ── name → object slot lookup (for shm_unlink) ──────────────────────────── */

/*
 * lucas_shm_unlink_name() — mark a named object for deletion.
 *
 * Called from handlers_shm.c lucas_sys_shm_unlink (after stripping the
 * "/dev/shm" prefix from the client-supplied name).
 *
 * Returns 0 on success, -ENOENT if not found.  If open_count is already
 * 0 the storage is freed immediately; otherwise it lingers until the
 * last close (POSIX semantics).
 */
int lucas_shm_unlink_name(const char *name) {
    const char *n = normalise_name(name);
    if (!n) return -22;                        /* -EINVAL */
    int slot = find_object_by_name(n);
    if (slot < 0) return -2;                   /* -ENOENT */
    shm_object_t *obj = &g_objects[slot];
    obj->unlinked = true;
    printf("[shm] unlink '%s' · slot=%d refcnt=%d (lazy=%s)\n",
           obj->name, slot, obj->open_count,
           obj->open_count > 0 ? "yes" : "no");
    if (obj->open_count == 0) {
        release_object(obj);
    }
    return 0;
}
