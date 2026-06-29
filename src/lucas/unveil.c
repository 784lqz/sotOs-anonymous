/*
 * sotOs · LUCAS · unveil · per-path access restriction.
 *
 * Companion to pledge() (src/lucas/pledge.c).  Pledge narrows OPERATION
 * classes; unveil narrows the PATH set those operations may touch.  Both
 * are LUCAS-private syscalls reached via the fault loop, and both follow
 * monotonic-narrowing semantics:
 *
 *   - First call flips default-permit → default-deny, adds the entry.
 *   - Subsequent calls may add new paths (until locked) or narrow an
 *     existing entry's perms (never widen).
 *   - unveil(NULL, NULL) locks the table · no further mutation.
 *
 * The check helper is invoked from the FS handlers (open/openat/stat/...) ·
 * see handlers_fs.c.
 *
 * Wire format of perms_vaddr: a small NUL-terminated C string built from
 * the characters {r, w, x, c}.  Recognised tokens (case-insensitive):
 *
 *   "r"   → UNVEIL_R
 *   "w"   → UNVEIL_W
 *   "x"   → UNVEIL_X
 *   "c"   → UNVEIL_W   (OpenBSD "create" · we fold into write)
 *   ""    → 0          (explicit revoke · narrows entry to "no access")
 *
 * Characters may appear in any order ("rw", "wr", "rwx", "rwc" all work).
 * Unrecognised characters are ignored.
 */
#include <lucas/unveil.h>
#include <lucas/syscalls.h>
#include "state.h"
#include "handlers.h"
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Linux errno values used here.  EPERM=1, EACCES=13, EFAULT=14, EINVAL=22.
 * Defined locally to avoid widening linux_abi.h's surface (matches the
 * style established by pledge.c). */
#define LX_EPERM_LOCAL   1
#define LX_EACCES_LOCAL  13
#define LX_EFAULT_LOCAL  14
#define LX_EINVAL_LOCAL  22

/* Forward declaration · defined in handlers_fs.c. */
extern int lucas_copy_cstr_from_client(lucas_state_t *st, uintptr_t client_vaddr,
                                        char *buf, size_t buf_size);

/* ────────────────────────────────────────────────────────────────────
 * Perms-string parser.
 *
 * Returns the OR of the recognised UNVEIL_* bits.  Empty string is
 * legal · it returns 0, which when narrowing an existing entry means
 * "revoke all access for this path".
 * ──────────────────────────────────────────────────────────────────── */
static uint32_t unveil_parse_perms(const char *s) {
    uint32_t mask = 0;
    if (s == NULL) return 0;
    for (; *s != '\0'; ++s) {
        char c = *s;
        if (c >= 'A' && c <= 'Z') c = (char)(c + ('a' - 'A'));
        switch (c) {
            case 'r': mask |= UNVEIL_R; break;
            case 'w': mask |= UNVEIL_W; break;
            case 'x': mask |= UNVEIL_X; break;
            case 'c': mask |= UNVEIL_W; break;  /* OpenBSD "create" */
            default:  /* ignore */ break;
        }
    }
    return mask;
}

/* ────────────────────────────────────────────────────────────────────
 * Longest-prefix match helper.
 *
 * Returns the index of the entry whose `path` is the longest prefix of
 * `query`, or -1 if no entry is a prefix.  Prefix matching is byte-exact
 * with the additional rule that the entry boundary must align to either
 * end-of-entry-path or a '/' in the query (so /usr does NOT match
 * /usrbin/foo).
 *
 * A literal '/' entry matches every absolute path.
 * ──────────────────────────────────────────────────────────────────── */
static int unveil_find_match(const lucas_unveil_state_t *uv, const char *query) {
    int best = -1;
    size_t best_len = 0;
    size_t qlen = strlen(query);

    for (uint8_t i = 0; i < uv->count; ++i) {
        const char *e = uv->entries[i].path;
        size_t elen = strlen(e);
        if (elen == 0 || elen > qlen) continue;
        if (memcmp(e, query, elen) != 0) continue;
        /* Boundary check: either the entry consumed the whole query,
         * or the next byte in the query is '/', or the entry itself
         * ended with '/'. */
        if (elen != qlen
            && query[elen] != '/'
            && e[elen - 1] != '/') {
            continue;
        }
        if (elen > best_len) {
            best_len = elen;
            best = (int)i;
        }
    }
    return best;
}

/* ────────────────────────────────────────────────────────────────────
 * Public check API · invoked by FS handlers before backend ops.
 * ──────────────────────────────────────────────────────────────────── */
int lucas_unveil_check(lucas_state_t *st, const char *path, uint32_t want_perms) {
    if (st == NULL || path == NULL) return 0;
    lucas_unveil_state_t *uv = &st->unveil;
    /* Default-permit before the first unveil() call. */
    if (!uv->initialized) return 0;
    /* No want bits → trivially allowed (caller probably mis-mapped flags). */
    if (want_perms == 0) return 0;

    int idx = unveil_find_match(uv, path);
    if (idx < 0) {
        printf("[unveil] pid=%d · deny path=\"%s\" want=0x%x · no match\n",
               st->synthetic_pid, path, (unsigned)want_perms);
        return -LX_EACCES_LOCAL;
    }
    uint32_t have = uv->entries[idx].perms;
    if ((want_perms & have) != want_perms) {
        printf("[unveil] pid=%d · deny path=\"%s\" want=0x%x have=0x%x via \"%s\"\n",
               st->synthetic_pid, path, (unsigned)want_perms,
               (unsigned)have, uv->entries[idx].path);
        return -LX_EACCES_LOCAL;
    }
    return 0;
}

/* ────────────────────────────────────────────────────────────────────
 * Mutation helpers.
 * ──────────────────────────────────────────────────────────────────── */
static int unveil_find_exact(const lucas_unveil_state_t *uv, const char *path) {
    for (uint8_t i = 0; i < uv->count; ++i) {
        if (strcmp(uv->entries[i].path, path) == 0) return (int)i;
    }
    return -1;
}

static void unveil_copy_path(char *dst, const char *src) {
    size_t i = 0;
    for (; i < LUCAS_UNVEIL_PATH_MAX - 1 && src[i] != '\0'; ++i) {
        dst[i] = src[i];
    }
    dst[i] = '\0';
}

/* ────────────────────────────────────────────────────────────────────
 * lucas_sys_unveil(path_vaddr, perms_vaddr, ...)
 *
 * - (0, 0) → lock the table (no further mutation).
 * - Any other combination with the table locked → -EPERM.
 * - Otherwise: read both strings from the client, parse perms, insert
 *   or narrow the entry.  On first call, flip default-permit to
 *   default-deny by setting `initialized`.
 *
 * Returns 0 on success, negated Linux errno on failure.
 * ──────────────────────────────────────────────────────────────────── */
int64_t lucas_sys_unveil(lucas_state_t *st,
                         uint64_t path_vaddr,
                         uint64_t perms_vaddr,
                         uint64_t _a2, uint64_t _a3,
                         uint64_t _a4, uint64_t _a5) {
    (void)_a2; (void)_a3; (void)_a4; (void)_a5;
    lucas_unveil_state_t *uv = &st->unveil;

    /* Lock form · unveil(NULL, NULL). */
    if (path_vaddr == 0 && perms_vaddr == 0) {
        /* First call locking immediately is legal · seal an empty table
         * (effectively "deny everything"). */
        uv->initialized = 1;
        uv->locked      = 1;
        printf("[unveil] pid=%d · locked · count=%u\n",
               st->synthetic_pid, (unsigned)uv->count);
        return 0;
    }

    if (uv->locked) {
        printf("[unveil] pid=%d · refused · table already locked\n",
               st->synthetic_pid);
        return -(int64_t)LX_EPERM_LOCAL;
    }

    /* Both pointers must be non-NULL for a normal add/narrow call. */
    if (path_vaddr == 0 || perms_vaddr == 0) {
        return -(int64_t)LX_EINVAL_LOCAL;
    }

    char path_buf[LUCAS_UNVEIL_PATH_MAX];
    char perms_buf[16];
    if (lucas_copy_cstr_from_client(st, (uintptr_t)path_vaddr,
                                     path_buf, sizeof(path_buf)) < 0) {
        return -(int64_t)LX_EFAULT_LOCAL;
    }
    if (lucas_copy_cstr_from_client(st, (uintptr_t)perms_vaddr,
                                     perms_buf, sizeof(perms_buf)) < 0) {
        return -(int64_t)LX_EFAULT_LOCAL;
    }
    if (path_buf[0] == '\0') {
        return -(int64_t)LX_EINVAL_LOCAL;
    }

    uint32_t new_perms = unveil_parse_perms(perms_buf);

    int idx = unveil_find_exact(uv, path_buf);
    if (idx >= 0) {
        /* Narrow-only · every bit in new_perms must already be set. */
        uint32_t cur = uv->entries[idx].perms;
        if ((new_perms & ~cur) != 0) {
            printf("[unveil] pid=%d · refused widening · path=\"%s\" req=0x%x cur=0x%x\n",
                   st->synthetic_pid, path_buf,
                   (unsigned)new_perms, (unsigned)cur);
            return -(int64_t)LX_EPERM_LOCAL;
        }
        uv->entries[idx].perms = (cur & new_perms);
        uv->initialized = 1;
        printf("[unveil] pid=%d · narrow \"%s\" 0x%x -> 0x%x\n",
               st->synthetic_pid, path_buf,
               (unsigned)cur, (unsigned)uv->entries[idx].perms);
        return 0;
    }

    /* New entry. */
    if (uv->count >= LUCAS_UNVEIL_MAX_ENTRIES) {
        printf("[unveil] pid=%d · refused · table full (%u entries)\n",
               st->synthetic_pid, (unsigned)uv->count);
        return -(int64_t)LX_EPERM_LOCAL;
    }
    unveil_copy_path(uv->entries[uv->count].path, path_buf);
    uv->entries[uv->count].perms = new_perms;
    uv->count++;
    uv->initialized = 1;
    printf("[unveil] pid=%d · add \"%s\" perms=0x%x (count=%u)\n",
           st->synthetic_pid, path_buf,
           (unsigned)new_perms, (unsigned)uv->count);
    return 0;
}
