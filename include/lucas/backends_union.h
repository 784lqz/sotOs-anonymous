#ifndef LUCAS_BACKENDS_UNION_H
#define LUCAS_BACKENDS_UNION_H
#include <stddef.h>
typedef enum { UNION_NONE=0, UNION_UPPER=1, UNION_BASE=2, UNION_STATIC=3 } union_layer_t;
/* Which layer serves path P. */
union_layer_t union_resolve_layer(int upper_has, int upper_whiteout, int base_has);
/* Merge dir entries: out gets {upper names} ∪ {base names not whitened, not shadowed}.
 * Returns count written (≤ max). Names ≤ 15 chars for the host test fixture. */
int union_merge_dents(const char *const *base, int nbase,
                      const char *const *up,   int nup,
                      const char *const *wh,   int nwh,
                      char out[][16], int max);
#endif
