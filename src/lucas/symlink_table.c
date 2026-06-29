/* Contained per-session symlink store for the Tier-2 honey shell.  See
 * include/lucas/symlink_table.h for the containment rationale (no open-follow →
 * no escape surface). */
#include <lucas/symlink_table.h>
#include <string.h>

#define SLINK_MAX   256  /* a multi-package `apk add` records many soname/applet
                          * links (libncursesw.so.6, rnano, …) per install · 64
                          * overflowed for larger closures · 256·520 B ≈ 133 KiB BSS */
#define SLINK_PATH  256

typedef struct {
    uint8_t  used;
    uint32_t session;
    char     path[SLINK_PATH];     /* absolute link path (the key) */
    char     target[SLINK_PATH];   /* verbatim symlink target (what readlink returns) */
} slink_t;

static slink_t g_slinks[SLINK_MAX];

/* errno values (Linux x86_64) returned as negatives. */
#define SL_EINVAL        22
#define SL_EEXIST        17
#define SL_ENOSPC        28
#define SL_ENAMETOOLONG  36

static int slink_match(const slink_t *s, uint32_t session, const char *path) {
    return s->used && s->session == session && strcmp(s->path, path) == 0;
}

int lucas_symlink_add(uint32_t session, const char *linkpath, const char *target) {
    if (!linkpath || !target) return -SL_EINVAL;
    if (strlen(linkpath) >= SLINK_PATH || strlen(target) >= SLINK_PATH)
        return -SL_ENAMETOOLONG;
    for (int i = 0; i < SLINK_MAX; ++i)
        if (slink_match(&g_slinks[i], session, linkpath)) return -SL_EEXIST;
    for (int i = 0; i < SLINK_MAX; ++i) {
        if (!g_slinks[i].used) {
            g_slinks[i].used    = 1;
            g_slinks[i].session = session;
            strncpy(g_slinks[i].path,   linkpath, SLINK_PATH - 1); g_slinks[i].path[SLINK_PATH - 1]   = '\0';
            strncpy(g_slinks[i].target, target,   SLINK_PATH - 1); g_slinks[i].target[SLINK_PATH - 1] = '\0';
            return 0;
        }
    }
    return -SL_ENOSPC;
}

const char *lucas_symlink_get(uint32_t session, const char *linkpath) {
    if (!linkpath) return 0;
    for (int i = 0; i < SLINK_MAX; ++i)
        if (slink_match(&g_slinks[i], session, linkpath)) return g_slinks[i].target;
    return 0;
}

void lucas_symlink_reap(uint32_t session) {
    for (int i = 0; i < SLINK_MAX; ++i)
        if (g_slinks[i].used && g_slinks[i].session == session) g_slinks[i].used = 0;
}
