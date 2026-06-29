/* Host unit · per-session sotfs-upper ownership map: tag an inode to a session,
 * visibility gates the operator (session 0) to base only, reap-iteration walks
 * a session's owned inodes, clear frees the session's ownership. */
#include <assert.h>
#include <stdio.h>
#include "lucas/sotfs_session.h"

static void test_ownership_and_visibility(void) {
    lucas_sotfs_session_init();
    /* unowned inode → base (owner 0), visible to everyone incl. operator */
    assert(lucas_sotfs_session_owner(5) == 0);
    assert(lucas_sotfs_session_visible(5, 0) == 1);   /* operator sees base */
    assert(lucas_sotfs_session_visible(5, 7) == 1);   /* session sees base */
    /* tag inode 5 to session 7 */
    lucas_sotfs_session_tag(5, 7);
    assert(lucas_sotfs_session_owner(5) == 7);
    assert(lucas_sotfs_session_visible(5, 7) == 1);   /* owner sees its own */
    assert(lucas_sotfs_session_visible(5, 9) == 0);   /* other session: hidden */
    assert(lucas_sotfs_session_visible(5, 0) == 0);   /* operator: hidden (base only) */
}

static void test_reap_iteration_and_clear(void) {
    lucas_sotfs_session_init();
    lucas_sotfs_session_tag(3, 7);
    lucas_sotfs_session_tag(8, 7);
    lucas_sotfs_session_tag(4, 9);   /* a different session */
    /* iteration returns session 7's owned inodes in ascending order */
    int id = 0;
    id = lucas_sotfs_session_next_owned(7, id); assert(id == 3);
    id = lucas_sotfs_session_next_owned(7, id); assert(id == 8);
    id = lucas_sotfs_session_next_owned(7, id); assert(id == 0);  /* done */
    /* clear session 7 leaves session 9 untouched */
    lucas_sotfs_session_clear(7);
    assert(lucas_sotfs_session_owner(3) == 0);
    assert(lucas_sotfs_session_owner(8) == 0);
    assert(lucas_sotfs_session_owner(4) == 9);
    assert(lucas_sotfs_session_next_owned(9, 0) == 4);
}

static void test_bounds(void) {
    lucas_sotfs_session_init();
    /* out-of-range inode ids return base and never write out of bounds */
    assert(lucas_sotfs_session_owner(0)    == 0);
    assert(lucas_sotfs_session_owner(1025) == 0);
    lucas_sotfs_session_tag(0, 7);     /* must not write g_owner[-1] */
    lucas_sotfs_session_tag(1025, 7);  /* must not write g_owner[1024] */
    assert(lucas_sotfs_session_owner(0)    == 0);
    assert(lucas_sotfs_session_owner(1025) == 0);
    /* visible() delegates to owner() → same bounds path */
    assert(lucas_sotfs_session_visible(0, 7) == 1);  /* out-of-range → owner 0 → base-visible */
}

static void test_capacity_cap(void) {
    lucas_sotfs_session_init();
    /* charge under the cap succeeds and accumulates */
    assert(lucas_sotfs_session_charge(7, 10u*1024*1024) == 0);
    assert(lucas_sotfs_session_bytes(7) == 10u*1024*1024);
    assert(lucas_sotfs_session_charge(7, 20u*1024*1024) == 0);
    assert(lucas_sotfs_session_bytes(7) == 30u*1024*1024);
    /* a charge that would exceed the cap is rejected (-ENOSPC) and does NOT add.
     * (cap-relative so it stays a real over-cap test as the cap grows) */
    assert(lucas_sotfs_session_charge(7, (LUCAS_SOTFS_SESS_CAP_BYTES - 30u*1024*1024) + 1) == -28);
    assert(lucas_sotfs_session_bytes(7) == 30u*1024*1024);
    /* a different session has its own independent budget */
    assert(lucas_sotfs_session_charge(9, 30u*1024*1024) == 0);
    assert(lucas_sotfs_session_bytes(9) == 30u*1024*1024);
    /* uncharge frees budget back */
    lucas_sotfs_session_uncharge(7, 30u*1024*1024);
    assert(lucas_sotfs_session_bytes(7) == 0);
    /* clear resets accounting for the session */
    lucas_sotfs_session_clear(9);
    assert(lucas_sotfs_session_bytes(9) == 0);

    /* exact-cap boundary: fill a fresh session to EXACTLY the cap → succeeds
     * (the check is strict `>`); one more byte → rejected, bytes unchanged. */
    assert(lucas_sotfs_session_charge(11, LUCAS_SOTFS_SESS_CAP_BYTES) == 0);
    assert(lucas_sotfs_session_bytes(11) == LUCAS_SOTFS_SESS_CAP_BYTES);
    assert(lucas_sotfs_session_charge(11, 1) == -28);
    assert(lucas_sotfs_session_bytes(11) == LUCAS_SOTFS_SESS_CAP_BYTES);

    /* absolute apt-arc case: a 64 MiB charge must FIT — it's well over the old
     * 32 MiB cap but under the 192 MiB one (apt index/cache needs ~100+ MB).
     * This is the case that FAILS under the old cap and PASSES under 192 MiB. */
    assert(lucas_sotfs_session_charge(12, 64u*1024*1024) == 0);
    assert(lucas_sotfs_session_bytes(12) == 64u*1024*1024);

    /* table-full path: 16 distinct non-zero sessions fill all slots (session 0
     * is exempt), then a 17th distinct session has no slot → -28 (anti-DoS). */
    lucas_sotfs_session_init();
    for (uint32_t s = 1; s <= LUCAS_SOTFS_SESS_MAX; s++)
        assert(lucas_sotfs_session_charge(s, 1) == 0);
    assert(lucas_sotfs_session_charge(LUCAS_SOTFS_SESS_MAX + 1, 1) == -28);
}

int main(void) {
    test_ownership_and_visibility();
    test_reap_iteration_and_clear();
    test_bounds();
    test_capacity_cap();
    printf("[sotfs-session-unit] MAP/VISIBILITY/REAP PASS\n");
    return 0;
}
