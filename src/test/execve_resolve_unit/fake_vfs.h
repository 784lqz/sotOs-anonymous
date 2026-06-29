#ifndef FAKE_VFS_H
#define FAKE_VFS_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>

/* Mirror of the fields resolve_path_vfs uses from struct lx_stat / vfs_ops_t. */
struct lx_stat { int64_t st_size; };

typedef struct fake_ops {
    int     (*open)(void *backend, const char *path, int flags, uint32_t mode, void **out_handle);
    int     (*close)(void *backend, void *handle);
    int64_t (*read)(void *backend, void *handle, void *buf, size_t count, int64_t cursor);
    int     (*stat)(void *backend, const char *path, struct lx_stat *out);
} fake_ops_t;

typedef struct fake_mount {
    const char *prefix;
    const fake_ops_t *ops;
    void *backend_state;
} fake_mount_t;

/* A file resident in either layer. */
typedef struct fake_file {
    const char *path;        /* absolute, e.g. "/usr/bin/upbin" */
    const uint8_t *bytes;
    uint32_t len;
    uint32_t owner_session;  /* 0 = base (visible to all); !=0 = upper, owner-only */
} fake_file_t;

typedef struct fake_union {
    const fake_file_t *files;
    int nfiles;
} fake_union_t;

extern uint32_t g_fake_active_session;   /* stands in for caller->cow_session */
static inline void fake_set_session(uint32_t s) { g_fake_active_session = s; }

int     fake_union_open(void *backend, const char *path, int flags, uint32_t mode, void **out_handle);
int     fake_union_close(void *backend, void *handle);
int64_t fake_union_read(void *backend, void *handle, void *buf, size_t count, int64_t cursor);
int     fake_union_stat(void *backend, const char *path, struct lx_stat *out);

extern const fake_ops_t fake_union_ops;

const void *resolve_path_vfs_test(fake_mount_t *mounts, int nmounts,
                                  const char *path, unsigned long *out_size,
                                  uint8_t *stage, size_t stage_cap);

#endif /* FAKE_VFS_H */
