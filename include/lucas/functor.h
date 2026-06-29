/*
 * sotOs · deception functor (sotFS-ι · spec §12.6.2).
 *
 * Categorical framing of Tier 0/1/2: F: Graph → Graph with
 *   F_0 = identity (transparent pass-through)
 *   F_1 = silenced (mutations folded to identity; reads unchanged)
 *   F_2 = mirror (shadow graph; mutations isolated)
 *
 * Phase 1: typed object + 3 instances + setter.  Read sites still
 * use st->tier int field; Phase 2 swaps those to st->functor->is_*
 * predicate calls.
 *
 * Each instance is a static const struct.  No allocation; sotboxes
 * hold a const pointer.  Tier transitions are pointer reassignments
 * (the categorical 'natural transformation' η: F_a → F_b is just
 * st->functor = &F_b).
 */

#ifndef LUCAS_FUNCTOR_H
#define LUCAS_FUNCTOR_H

#include <stdint.h>
#include <stdbool.h>

struct lucas_state;

typedef enum {
    FUNCTOR_TIER_0 = 0,   /* Pass-Through */
    FUNCTOR_TIER_1 = 1,   /* Silenced */
    FUNCTOR_TIER_2 = 2,   /* Mirror */
    FUNCTOR_TIER_EGRESS = 3,   /* Tier-0e · pass-through + authorised REAL egress */
} lucas_functor_tier_t;

typedef struct lucas_functor {
    const char           *name;        /* "F_0" / "F_1" / "F_2" */
    lucas_functor_tier_t  tier;        /* matches the legacy int */
    bool                  writes_silenced;    /* true for F_1 · silences write mutations */
    bool                  is_isolated;   /* true for F_2 · diverts reads to canary + isolates writes */
    bool                  is_egress;   /* N1 · true for F_0e · this sandbox reaches the REAL wire */
    /* Future · per-op natural transformations.  Phase 1 keeps these
     * NULL; Phase 2 uses them for the actual functorial behavior. */
    /* void (*on_write)(struct lucas_state *, int fd, const void *buf, size_t n); */
} lucas_functor_t;

extern const lucas_functor_t LUCAS_F_0;
extern const lucas_functor_t LUCAS_F_1;
extern const lucas_functor_t LUCAS_F_2;
extern const lucas_functor_t LUCAS_F_0E;

/* Compat helper · sets BOTH st->tier (int legacy field, still read by
 * call sites) AND st->functor (Phase 2 read sites use this).  Use this
 * everywhere instead of direct `st->tier = N`. */
void lucas_set_tier(struct lucas_state *st, int tier);

/* Lookup the canonical functor for a tier number. */
const lucas_functor_t *lucas_functor_for_tier(int tier);

#endif
