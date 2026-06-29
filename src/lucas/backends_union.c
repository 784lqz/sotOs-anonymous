/* /usr union backend.
 *
 * P1.1: the PURE decision core — host-testable, NO seL4 deps (string.h/stddef.h
 * only).  Given the three booleans "does upper have P?", "is P whitened in the
 * upper?", "does base have P?", decide which layer serves a read; and merge two
 * directory listings (upper ∪ base, upper shadows, whiteouts hide).
 *
 * The seL4 vfs_ops (open/read/write/getdents over the real sotfs upper +
 * sysroot base) GROW into this file in P1.2 — keep this TU standalone-buildable
 * with cc for the host unit until then.
 */
#include <stddef.h>
#include <string.h>
#include "lucas/backends_union.h"

/* upper_whiteout hides everything below it (the path was deleted in the upper);
 * else the upper shadows the base; else the base serves; else nothing. */
union_layer_t union_resolve_layer(int upper_has, int upper_whiteout, int base_has)
{
    if (upper_whiteout) return UNION_NONE;
    if (upper_has)      return UNION_UPPER;
    if (base_has)       return UNION_BASE;
    return UNION_NONE;
}

/* Bounded copy of name into the out fixture (≤15 chars + NUL). */
static void union_copy_name(char dst[16], const char *src)
{
    size_t i = 0;
    if (src) {
        for (; i < 15 && src[i]; i++) dst[i] = src[i];
    }
    dst[i] = '\0';
}

static int union_name_in(const char *const *list, int n, const char *name)
{
    if (!list || !name) return 0;
    for (int i = 0; i < n; i++) {
        if (list[i] && strcmp(list[i], name) == 0) return 1;
    }
    return 0;
}

/* out gets every upper name, then every base name that is NOT whitened and NOT
 * already shadowed by an upper name.  Bounded by max. */
int union_merge_dents(const char *const *base, int nbase,
                      const char *const *up,   int nup,
                      const char *const *wh,   int nwh,
                      char out[][16], int max)
{
    int n = 0;

    for (int i = 0; i < nup && n < max; i++) {
        if (!up[i]) continue;
        union_copy_name(out[n++], up[i]);
    }

    for (int i = 0; i < nbase && n < max; i++) {
        if (!base[i]) continue;
        if (union_name_in(wh, nwh, base[i])) continue;   /* whitened → hidden */
        if (union_name_in(up, nup, base[i])) continue;   /* shadowed by upper */
        union_copy_name(out[n++], base[i]);
    }

    return n;
}
