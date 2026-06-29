/*
 * sotOs · LUCAS L2 · Virtual filesystem interface.
 *
 * Pluggable backend pattern: each backend implements vfs_ops_t and
 * registers a mount point (path prefix) in the companion's mount_table.
 * Path resolution is longest-prefix match.
 *
 * L2 ships three backends: static_vfs (/etc and similar hardcoded
 * content), proc_vfs (per-pid /proc entries synthesized from state),
 * and dev_vfs (placeholder for L3).
 *
 * When sotFS arrives (Phase 2 of the roadmap), a sto_vfs backend
 * is added without touching this interface.
 */

#ifndef SOTOS_LUCAS_VFS_H
#define SOTOS_LUCAS_VFS_H

#include <stdint.h>
#include <stddef.h>

/* Linux struct stat (x86_64). Fields we populate. */
struct lx_stat {
    uint64_t st_dev;
    uint64_t st_ino;
    uint64_t st_nlink;
    uint32_t st_mode;
    uint32_t st_uid;
    uint32_t st_gid;
    uint32_t pad0;
    uint64_t st_rdev;
    int64_t  st_size;
    int64_t  st_blksize;
    int64_t  st_blocks;
    uint64_t st_atime;
    uint64_t st_atime_nsec;
    uint64_t st_mtime;
    uint64_t st_mtime_nsec;
    uint64_t st_ctime;
    uint64_t st_ctime_nsec;
    int64_t  unused[3];
};

/* Linux struct linux_dirent64 (used by getdents64). */
struct lx_dirent64 {
    uint64_t d_ino;
    int64_t  d_off;
    uint16_t d_reclen;
    uint8_t  d_type;
    char     d_name[];   /* null-terminated */
};

#define LX_DT_REG  8
#define LX_DT_DIR  4
#define LX_DT_LNK  10
#define LX_DT_CHR  2
#define LX_DT_BLK  6

/* Linux stat mode bits */
#define LX_S_IFMT   0170000
#define LX_S_IFREG  0100000
#define LX_S_IFDIR  0040000
#define LX_S_IFSOCK 0140000   /* WINE-M1 · AF_UNIX socket node (wine lstat S_ISSOCK check) */
#define LX_S_IFMT   0170000   /* file-type mask */
#define LX_S_IFLNK  0120000
#define LX_S_IFCHR  0020000
#define LX_S_IFBLK  0060000   /* block device node (/dev/vda, /dev/vda1) */
#define LX_S_IFIFO  0010000
/* device node st_rdev = (major << 8) | minor (Linux x86_64 legacy encoding) */
#define LX_MAKEDEV(maj, min) ((uint64_t)(((maj) << 8) | ((min) & 0xff)))
#define LX_S_IRUSR  0400
#define LX_S_IWUSR  0200
#define LX_S_IXUSR  0100
#define LX_S_IRGRP  0040
#define LX_S_IROTH  0004

/* Open flags subset */
#define LX_O_RDONLY    0
#define LX_O_WRONLY    1
#define LX_O_RDWR      2
#define LX_O_DIRECTORY 0200000
#define LX_O_NOFOLLOW  0400000
#define LX_O_CLOEXEC   02000000

/* Forward · pulls from src/lucas/state.h (private to lucas library). */
struct lucas_state;

/* Per-backend operations. Each function returns 0 on success or a
 * negative Linux errno (so handlers can pass the value straight to
 * the client). */
typedef struct vfs_ops {
    int     (*open)     (void *backend, const char *path, int flags,
                          uint32_t mode, void **out_handle);
    int     (*close)    (void *backend, void *handle);
    int64_t (*read)     (void *backend, void *handle, void *buf,
                          size_t count, int64_t cursor);
    int64_t (*write)    (void *backend, void *handle, const void *buf,
                          size_t count, int64_t cursor);
    int     (*stat)     (void *backend, const char *path,
                          struct lx_stat *out);
    int     (*fstat)    (void *backend, void *handle,
                          struct lx_stat *out);
    int64_t (*getdents) (void *backend, void *handle, void *dirp,
                          size_t count, int64_t *cursor);
    int     (*readlink) (void *backend, const char *path, char *buf,
                          size_t size);
    /* WINE-M1 · allocate a fresh, INDEPENDENT backend handle for the same open
     * file as `handle` (same inode/path/flags).  Used when an fd is passed across
     * sotboxes via SCM_RIGHTS: the receiver must own a handle whose lifetime is
     * decoupled from the sender's (the sender close()s its copy, and pooled
     * handles get recycled).  Returns NULL on failure (pool full / bad handle).
     * Optional · NULL if the backend does not support it. */
    void   *(*dup_handle)(void *backend, void *handle);
    /* F3 · COW shrink-on-resave · truncate the backend's view of `handle` to
     * `newlen`.  For the static + sotfs canary surfaces this truncates the
     * caller's per-session overlay entry (the base is never mutated).  Optional
     * · NULL if the backend does not support it (ftruncate then succeeds-silently). */
    int     (*truncate) (void *backend, void *handle, int64_t newlen);
    /* Install-arc · writable-mount ops · NULL on read-only backends (sysroot). */
    int     (*mkdir)  (void *backend, const char *path, uint32_t mode);
    int     (*unlink) (void *backend, const char *path);
    /* unlinkat(AT_REMOVEDIR)/rmdir · remove an EMPTY directory.  Distinct from
     * unlink (file removal): the sotfs backend routes this to its dir-removal
     * rewrite (NOTEMPTY-aware), so file-unlink and dir-removal stay separate.
     * NULL on read-only backends; the unlinkat handler then returns -EROFS. */
    int     (*rmdir)  (void *backend, const char *path);
    int     (*rename) (void *backend, const char *oldp, const char *newp);   /* same-mount only */
} vfs_ops_t;

/* Mount entry. The prefix is matched against the open()/stat()
 * path; the longest matching prefix wins. The path passed to the
 * backend is the SUFFIX (after the mount point), with a leading "/"
 * for paths inside the mount, "/" for the mount root itself. */
typedef struct vfs_mount {
    const char     *prefix;       /* e.g. "/etc", "/proc", "/" */
    const vfs_ops_t *ops;
    void           *backend_state;
} vfs_mount_t;

/* Resolve a client-side absolute path to (mount, suffix).
 * Returns a pointer into the state's mount_table, or NULL if no
 * mount matches (which is a "ENOENT" condition). On success,
 * *out_suffix points into `path` to the matching suffix. */
const vfs_mount_t *vfs_resolve(struct lucas_state *st,
                                const char *path,
                                const char **out_suffix);

/* Install the L2 default mounts (static, proc) into st->mount_table.
 * Called from lucas_run_l1 right after client_setup. */
void vfs_install_defaults(struct lucas_state *st);

/* L5 profile system: selects the active static VFS entries table.
 * Must be called before vfs_install_defaults (i.e. before sotbox_init)
 * for the profile to take effect from the first syscall.
 *
 * NOTE: this is a GLOBAL switch.  All concurrent sotBoxes share the same
 * profile.  Per-sotBox profiles require threading the profile through every
 * backend op and are deferred to L5-T2+.
 */
typedef enum {
    LUCAS_PROFILE_ALPINE = 0,
    LUCAS_PROFILE_DEBIAN = 1,
} lucas_profile_t;

void vfs_set_profile(lucas_profile_t profile);

/* L7: tier-aware VFS content selection.  Tier 2 activates canary_entries
 * (isolated-write path); other tiers use the active profile (Alpine/Ubuntu).
 * Must be called after vfs_set_profile if both are used. */
void vfs_set_tier(int tier);

#endif /* SOTOS_LUCAS_VFS_H */
