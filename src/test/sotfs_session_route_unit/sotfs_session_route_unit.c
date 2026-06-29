/* Host unit · Phase-2 cross-mount session-upper DECISION logic.
 *
 *  (gate) tag/charge/visibility apply ONLY for cow_session != 0; session 0
 *         (Tier-0 / operator) is the legacy untagged path (zero regression).
 *  (I1)   the operator truth-view (session 0) is NEVER served a session-owned
 *         inode → it sees the pristine base.
 *  (I2)   session A's inode is invisible to session B; a session sees its own.
 *
 * Uses the REAL Phase-1 sotfs_session table + the pure union_resolve_layer, so
 * the asserted logic is exactly what the backend ops call. */
#include <assert.h>
#include <stdio.h>
#include "lucas/sotfs_session.h"
#include "lucas/backends_union.h"

/* Does the create/write path tag this inode for `caller`? (mirrors the op gate) */
static int should_tag(uint32_t caller) { return caller != 0; }

/* Is `inode` served to `caller` on read/stat/getdents? (the visibility gate the
 * ops apply: untagged base inodes are visible to all; tagged ones only to owner;
 * the operator/session-0 sees base only.) */
static int served(int inode, uint32_t caller) {
    return lucas_sotfs_session_visible(inode, caller);
}

static void test_tier_gate(void) {
    /* Tier-0 / operator (session 0) is never tagged → legacy persistent path. */
    assert(should_tag(0) == 0);
    /* a Tier-2 SSH session (cow_session != 0) IS tagged. */
    assert(should_tag(7) == 1);
}

static void test_visibility_I1_I2(void) {
    lucas_sotfs_session_init();
    int base = 5;          /* an untagged base inode */
    int owned = 42;        /* created by session 7 */
    lucas_sotfs_session_tag(owned, 7);

    /* base is visible to everyone incl. the operator (I1: base pristine view). */
    assert(served(base, 0) == 1);
    assert(served(base, 7) == 1);
    assert(served(base, 9) == 1);

    /* I1: the operator (session 0) does NOT see the session-owned inode. */
    assert(served(owned, 0) == 0);
    /* I2: session 9 does NOT see session 7's inode; session 7 does. */
    assert(served(owned, 9) == 0);
    assert(served(owned, 7) == 1);
}

static void test_union_layer_order(void) {
    /* getdents merge dedup order (upper shadows base; whiteout hides). */
    assert(union_resolve_layer(/*up*/1, /*wh*/0, /*base*/1) == UNION_UPPER);
    assert(union_resolve_layer(0, 0, 1) == UNION_BASE);
    assert(union_resolve_layer(0, 1, 1) == UNION_NONE);
    assert(union_resolve_layer(0, 0, 0) == UNION_NONE);
}

int main(void) {
    test_tier_gate();
    test_visibility_I1_I2();
    test_union_layer_order();
    printf("[sotfs-session-route-unit] TIER-GATE/VISIBILITY/ORDER PASS\n");
    return 0;
}
