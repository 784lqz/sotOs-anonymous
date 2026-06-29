/* Per-session copy-on-write-lite overlay.
 *
 * At Tier-2 (the SSH attacker) a file write is "contained" — the base canary
 * file is NEVER mutated.  But silently dropping the write is a honeypot tell:
 * an attacker who edits a file with vim, `:w`-saves, then re-reads it would see
 * the OLD content.  This overlay holds the attacker's writes per SSH session so
 * read-back is coherent within the session, while the base stays pristine; the
 * VFS layer reaps the session's entries when the SSH session ends.
 *
 * The orch is a freestanding seL4 process: NO host malloc.  This module is a
 * fixed static pool (16 * 64 KiB = 1 MiB BSS), pure C string/mem ops, no seL4
 * deps — so it compiles standalone with `cc` for the host unit test.
 *
 * An attacker controls both `path` and `content`, so EVERY copy is bounded.
 */
#include "lucas/cow_overlay.h"
#include <string.h>

typedef struct {
    uint8_t  used;
    uint32_t session;
    char     path[LUCAS_COW_MAX_PATH];
    uint32_t len;
    uint8_t  data[LUCAS_COW_MAX_BYTES];
} cow_entry_t;

static cow_entry_t g_cow[LUCAS_COW_MAX_ENTRIES];

void lucas_cow_init(void)
{
    for (int i = 0; i < LUCAS_COW_MAX_ENTRIES; i++) {
        g_cow[i].used = 0;
    }
}

/* Linear scan for a used entry matching BOTH session and path (exact). */
static cow_entry_t *lucas_cow_find(uint32_t session, const char *path)
{
    if (!path) {
        return 0;
    }
    for (int i = 0; i < LUCAS_COW_MAX_ENTRIES; i++) {
        cow_entry_t *e = &g_cow[i];
        if (e->used && e->session == session && strcmp(e->path, path) == 0) {
            return e;
        }
    }
    return 0;
}

int lucas_cow_has(uint32_t session, const char *path)
{
    return lucas_cow_find(session, path) ? 1 : 0;
}

int lucas_cow_write(uint32_t session, const char *path,
                    const uint8_t *src, uint32_t n)
{
    if (!path || (n && !src)) {
        return -28; /* -ENOSPC: refuse a malformed write the same as no-space */
    }
    if (n > LUCAS_COW_MAX_BYTES) {
        return -28; /* -ENOSPC: per-entry cap → believable for a big :w */
    }

    /* Overwrite an existing (session,path) entry, else claim a free slot. */
    cow_entry_t *e = lucas_cow_find(session, path);
    if (!e) {
        for (int i = 0; i < LUCAS_COW_MAX_ENTRIES; i++) {
            if (!g_cow[i].used) {
                e = &g_cow[i];
                break;
            }
        }
        if (!e) {
            return -28; /* -ENOSPC: overlay table full */
        }
    }

    e->session = session;
    /* Bound the attacker-controlled path; always NUL-terminate. */
    strncpy(e->path, path, LUCAS_COW_MAX_PATH - 1);
    e->path[LUCAS_COW_MAX_PATH - 1] = '\0';
    /* Bound the attacker-controlled content (n already <= MAX_BYTES). */
    if (n) {
        memcpy(e->data, src, n);
    }
    e->len = n;
    e->used = 1;
    return 0;
}

int lucas_cow_read(uint32_t session, const char *path,
                   uint8_t *dst, uint32_t max)
{
    cow_entry_t *e = lucas_cow_find(session, path);
    if (!e) {
        return -1;
    }
    if (!dst || max == 0) {
        return 0;
    }
    uint32_t n = e->len < max ? e->len : max;
    memcpy(dst, e->data, n);
    return (int)n;
}

int lucas_cow_truncate(uint32_t session, const char *path, uint32_t newlen)
{
    cow_entry_t *e = lucas_cow_find(session, path);
    if (!e) return 0;                       /* no overlay yet → nothing to shrink */
    if (newlen > LUCAS_COW_MAX_BYTES) return -28; /* -ENOSPC */
    if (newlen > e->len) memset(e->data + e->len, 0, newlen - e->len); /* extend → zero-fill */
    e->len = newlen;                        /* shrink → drop the tail (the F3 fix) */
    return 0;
}

void lucas_cow_reap(uint32_t session)
{
    for (int i = 0; i < LUCAS_COW_MAX_ENTRIES; i++) {
        if (g_cow[i].used && g_cow[i].session == session) {
            g_cow[i].used = 0;
        }
    }
}
