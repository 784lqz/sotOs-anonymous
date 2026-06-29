/* Host unit · the resolve_path VFS-read fallback algorithm.
 *
 * Proves: (1) an upper-resident file visible to the active session is read
 * back byte-exact into the staging buffer (size taken from stat); (2) the
 * operator session (0) does NOT see the session's upper file (session-gate);
 * (3) an upper file shadows a base file of the same path (upper-before-base);
 * (4) a stage smaller than the file is rejected (NULL). */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "fake_vfs.h"

uint32_t g_fake_active_session = 0;

int fake_union_open(void *backend, const char *path, int flags, uint32_t mode, void **out_handle) {
    (void)flags; (void)mode;
    fake_union_t *u = backend;
    for (int i = 0; i < u->nfiles; i++) {
        const fake_file_t *f = &u->files[i];
        if (f->owner_session != 0 && f->owner_session == g_fake_active_session &&
            strcmp(f->path, path) == 0) { *out_handle = (void *)(intptr_t)(i + 1); return 0; }
    }
    for (int i = 0; i < u->nfiles; i++) {
        const fake_file_t *f = &u->files[i];
        if (f->owner_session == 0 && strcmp(f->path, path) == 0) {
            *out_handle = (void *)(intptr_t)(i + 1); return 0; }
    }
    return -2; /* -ENOENT */
}
int fake_union_close(void *backend, void *handle) { (void)backend; (void)handle; return 0; }
int64_t fake_union_read(void *backend, void *handle, void *buf, size_t count, int64_t cursor) {
    fake_union_t *u = backend; int idx = (int)(intptr_t)handle - 1;
    if (idx < 0 || idx >= u->nfiles) return -9;
    const fake_file_t *f = &u->files[idx];
    if (cursor >= (int64_t)f->len) return 0;
    size_t avail = f->len - (size_t)cursor;
    size_t n = count < avail ? count : avail;
    memcpy(buf, f->bytes + cursor, n);
    return (int64_t)n;
}
int fake_union_stat(void *backend, const char *path, struct lx_stat *out) {
    void *h = NULL; if (fake_union_open(backend, path, 0, 0, &h) != 0) return -2;
    fake_union_t *u = backend; int idx = (int)(intptr_t)h - 1;
    out->st_size = (int64_t)u->files[idx].len; return 0;
}
const fake_ops_t fake_union_ops = {
    fake_union_open, fake_union_close, fake_union_read, fake_union_stat };

static const uint8_t BASE_BIN[]  = { 0x7f,'E','L','F', 'B','A','S','E' };
static const uint8_t UPPER_BIN[] = { 0x7f,'E','L','F', 'U','P','P','E','R','!' };

int main(void) {
    static const fake_file_t files[] = {
        { "/usr/bin/upbin",  BASE_BIN,  sizeof(BASE_BIN),  0 },
        { "/usr/bin/upbin",  UPPER_BIN, sizeof(UPPER_BIN), 7 },
        { "/usr/bin/onlyup", UPPER_BIN, sizeof(UPPER_BIN), 7 },
    };
    static fake_union_t u = { files, 3 };
    fake_mount_t mounts[1] = { { "/usr", &fake_union_ops, &u } };
    uint8_t stage[64]; unsigned long sz = 0;

    fake_set_session(7);
    const void *b = resolve_path_vfs_test(mounts, 1, "/usr/bin/upbin", &sz, stage, sizeof(stage));
    assert(b != NULL); assert(sz == sizeof(UPPER_BIN));
    assert(memcmp(b, UPPER_BIN, sizeof(UPPER_BIN)) == 0);

    fake_set_session(0);
    sz = 0; b = resolve_path_vfs_test(mounts, 1, "/usr/bin/onlyup", &sz, stage, sizeof(stage));
    assert(b == NULL);

    sz = 0; b = resolve_path_vfs_test(mounts, 1, "/usr/bin/upbin", &sz, stage, sizeof(stage));
    assert(b != NULL); assert(sz == sizeof(BASE_BIN));
    assert(memcmp(b, BASE_BIN, sizeof(BASE_BIN)) == 0);

    fake_set_session(7);
    sz = 0; b = resolve_path_vfs_test(mounts, 1, "/usr/bin/onlyup", &sz, stage, 4 /*< 10*/);
    assert(b == NULL);

    printf("[execve-resolve-unit] VFS-FALLBACK/SESSION-GATE/UPPER-FIRST PASS\n");
    return 0;
}

/* Mirror of the orch helper (Task 2): longest-prefix mount match, then
 * open → stat(size) → bounds-check stage → read-full → close. */
static fake_mount_t *fake_resolve(fake_mount_t *mounts, int nmounts, const char *path,
                                  const char **out_suffix) {
    fake_mount_t *best = NULL; size_t best_len = 0;
    for (int i = 0; i < nmounts; i++) {
        const char *pfx = mounts[i].prefix; size_t plen = strlen(pfx);
        int m = (strncmp(path, pfx, plen) == 0) && (path[plen] == '\0' || path[plen] == '/');
        if (m && plen > best_len) { best = &mounts[i]; best_len = plen; }
    }
    if (best) *out_suffix = path;
    return best;
}

const void *resolve_path_vfs_test(fake_mount_t *mounts, int nmounts,
                                  const char *path, unsigned long *out_size,
                                  uint8_t *stage, size_t stage_cap) {
    const char *suffix = NULL;
    fake_mount_t *m = fake_resolve(mounts, nmounts, path, &suffix);
    if (!m || !m->ops || !m->ops->open || !m->ops->read) return NULL;

    struct lx_stat sb = { 0 };
    if (!m->ops->stat || m->ops->stat(m->backend_state, suffix, &sb) != 0) return NULL;
    if (sb.st_size <= 0 || (size_t)sb.st_size > stage_cap) return NULL;

    void *h = NULL;
    if (m->ops->open(m->backend_state, suffix, 0 /*O_RDONLY*/, 0, &h) != 0) return NULL;

    size_t want = (size_t)sb.st_size, got = 0;
    while (got < want) {
        int64_t n = m->ops->read(m->backend_state, h, stage + got, want - got, (int64_t)got);
        if (n <= 0) break;
        got += (size_t)n;
    }
    if (m->ops->close) m->ops->close(m->backend_state, h);
    if (got != want) return NULL;
    *out_size = (unsigned long)want;
    return stage;
}
