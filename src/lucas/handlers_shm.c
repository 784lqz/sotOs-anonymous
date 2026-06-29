/*
 * sotOs · LUCAS · U4 · shm_open / shm_unlink syscall handlers.
 *
 * These are LUCAS-private syscalls (numbers above LX_SYS_pledge · see
 * include/lucas/syscalls.h for the rationale).  Linux x86_64 has no
 * shm_open syscall; glibc implements it as a wrapper around
 * open("/dev/shm/<name>", ...) + fchmod.  By exposing the LUCAS-private
 * numbers we let a sotBox call into the /dev/shm VFS mount without
 * needing the full open() filename plumbing.
 *
 * Argument convention (matches Linux x86_64 ABI · RDI/RSI/RDX = a0/a1/a2):
 *
 *   int lucas_sys_shm_open(const char *name, int oflag, mode_t mode)
 *       a0 = name_vaddr (client pointer to NUL-terminated POSIX name)
 *       a1 = oflag      (O_RDONLY / O_RDWR / O_CREAT / O_EXCL · standard)
 *       a2 = mode       (creation mode; passed through · unused for now)
 *       returns: lucas fd ≥ 0 on success, negative errno on failure
 *
 *   int lucas_sys_shm_unlink(const char *name)
 *       a0 = name_vaddr
 *       returns: 0 on success, negative errno
 *
 * The name is the POSIX shm name (e.g. "/test") · we transparently
 * prepend "/dev/shm" so the VFS resolver routes us to the shm backend.
 */

#include "handlers.h"
#include "state.h"
#include <lucas/linux_abi.h>
#include <lucas/vfs.h>
#include <lucas/syscalls.h>

#include <stdio.h>
#include <string.h>

/* Imported from handlers_fs.c · same helpers used by lucas_sys_open. */
extern int lucas_copy_cstr_from_client(struct lucas_state *st,
                                        uintptr_t client_vaddr,
                                        char *buf, size_t buf_size);
extern void lucas_set_current_caller(struct lucas_state *st);

/* Imported from backends_shm.c · operates on the shm backend's
 * named-object table directly (handlers_shm cannot resolve the path
 * to a VFS handle without an open, so unlink calls into the backend). */
extern int lucas_shm_unlink_name(const char *name);

/* Bounded sotBox name buffer.  POSIX limits shm names to NAME_MAX (255);
 * we cap at LUCAS_PATH_MAX-9 to leave room for the "/dev/shm" prefix. */
#define LUCAS_SHM_NAME_BUFLEN 240

/* Compose the canonical "/dev/shm/<name>" path the VFS resolver expects.
 * Returns 0 on success, -1 on overflow. */
static int build_shm_path(const char *user_name, char *out, size_t out_sz) {
    /* POSIX shm names start with '/'.  Strip the leading slash so we
     * always produce "/dev/shm/<bare-name>". */
    while (*user_name == '/') user_name++;
    if (*user_name == '\0') return -1;

    size_t name_len = strlen(user_name);
    static const char prefix[] = "/dev/shm/";
    const size_t prefix_len = sizeof(prefix) - 1;
    if (name_len + prefix_len + 1 > out_sz) return -1;

    memcpy(out, prefix, prefix_len);
    memcpy(out + prefix_len, user_name, name_len);
    out[prefix_len + name_len] = '\0';
    return 0;
}

/* Locate a free fd ≥ 3 in the state's fd table.  Matches the helper
 * pattern used by lucas_sys_open. */
static int alloc_fd(lucas_state_t *st) {
    for (int i = 3; i < LUCAS_MAX_FDS; ++i) {
        if (st->fds[i].kind == LUCAS_FD_INVALID) return i;
    }
    return -1;
}

/* ── lucas_sys_shm_open ───────────────────────────────────────────────── */

int64_t lucas_sys_shm_open(lucas_state_t *st,
                            uint64_t name_vaddr, uint64_t oflag,
                            uint64_t mode,
                            uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a3; (void)_a4; (void)_a5;

    char user_name[LUCAS_SHM_NAME_BUFLEN];
    int slen = lucas_copy_cstr_from_client(st, name_vaddr,
                                            user_name, sizeof(user_name));
    if (slen < 0) return -(int64_t)LX_EFAULT;

    char path[LUCAS_PATH_MAX];
    if (build_shm_path(user_name, path, sizeof(path)) != 0) {
        return -(int64_t)36;                    /* -ENAMETOOLONG */
    }

    const char *suffix = NULL;
    const vfs_mount_t *m = vfs_resolve(st, path, &suffix);
    if (!m || !m->ops || !m->ops->open) {
        printf("[shm] sys_shm_open: vfs_resolve('%s') failed\n", path);
        return -(int64_t)2;                     /* -ENOENT */
    }

    void *handle = NULL;
    lucas_set_current_caller(st);
    int rc = m->ops->open(m->backend_state, suffix, (int)oflag,
                           (uint32_t)mode, &handle);
    lucas_set_current_caller(NULL);
    if (rc < 0) return (int64_t)rc;

    int fd = alloc_fd(st);
    if (fd < 0) {
        if (m->ops->close) m->ops->close(m->backend_state, handle);
        return -(int64_t)24;                    /* -EMFILE */
    }
    st->fds[fd].kind   = LUCAS_FD_VFS;
    st->fds[fd].mount  = m;
    st->fds[fd].handle = handle;
    st->fds[fd].cursor = 0;
    st->fds[fd].flags  = (int)oflag;
    st->fds[fd].is_std = false;
    st->fds[fd].pipe   = NULL;
    printf("[shm] shm_open('%s', oflag=0x%lx) → fd=%d\n",
           user_name, (unsigned long)oflag, fd);
    return (int64_t)fd;
}

/* ── lucas_sys_shm_unlink ─────────────────────────────────────────────── */

int64_t lucas_sys_shm_unlink(lucas_state_t *st,
                              uint64_t name_vaddr,
                              uint64_t _a1, uint64_t _a2,
                              uint64_t _a3, uint64_t _a4, uint64_t _a5) {
    (void)_a1; (void)_a2; (void)_a3; (void)_a4; (void)_a5;

    char user_name[LUCAS_SHM_NAME_BUFLEN];
    int slen = lucas_copy_cstr_from_client(st, name_vaddr,
                                            user_name, sizeof(user_name));
    if (slen < 0) return -(int64_t)LX_EFAULT;

    /* lucas_shm_unlink_name uses the backend's cached vka/vspace handles
     * (latched at first open) so it no longer relies on g_current_caller. */
    int rc = lucas_shm_unlink_name(user_name);
    printf("[shm] shm_unlink('%s') → %d\n", user_name, rc);
    return (int64_t)rc;
}
