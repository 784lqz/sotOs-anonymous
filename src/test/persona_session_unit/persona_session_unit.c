/* Host unit · per-session persona context (M3): set/get key the persona by
 * cow_session independently, session 0 is ignored, overwrite reuses the slot,
 * clear isolates one session, the table is bounded (anti-DoS), and the default
 * persona is the canonical Alpine identity. */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "lucas/persona_session.h"

static void test_set_get_per_session(void) {
    lucas_persona_session_init();
    lucas_persona_t a = { .profile = 0, .tier = 2 };
    strcpy(a.name, "alpine-edge"); strcpy(a.host, "prod-db-01");
    lucas_persona_t b = { .profile = 1, .tier = 0 };
    strcpy(b.name, "ubuntu-srv");  strcpy(b.host, "web-07");
    assert(lucas_persona_session_set(7, &a) == 0);
    assert(lucas_persona_session_set(9, &b) == 0);

    lucas_persona_t o;
    assert(lucas_persona_session_get(7, &o) == 1);
    assert(o.profile == 0 && o.tier == 2);
    assert(strcmp(o.name, "alpine-edge") == 0 && strcmp(o.host, "prod-db-01") == 0);
    /* session 9 is INDEPENDENT — different persona, not the global mask */
    assert(lucas_persona_session_get(9, &o) == 1);
    assert(o.profile == 1 && strcmp(o.host, "web-07") == 0);
    /* an unknown session has no persona */
    assert(lucas_persona_session_get(5, &o) == 0);
}

static void test_session0_ignored(void) {
    lucas_persona_session_init();
    lucas_persona_t a = { .profile = 0, .tier = 2 };
    assert(lucas_persona_session_set(0, &a) == 0);   /* ignored, not an error */
    lucas_persona_t o;
    assert(lucas_persona_session_get(0, &o) == 0);   /* session 0 = operator, no ctx */
}

static void test_overwrite_reuses_slot(void) {
    lucas_persona_session_init();
    lucas_persona_t a  = { .profile = 0, .tier = 2 }; strcpy(a.name,  "alpine-edge");
    lucas_persona_t a2 = { .profile = 0, .tier = 1 }; strcpy(a2.name, "alpine-lts");
    assert(lucas_persona_session_set(7, &a)  == 0);
    assert(lucas_persona_session_set(7, &a2) == 0);  /* overwrite same session */
    lucas_persona_t o;
    assert(lucas_persona_session_get(7, &o) == 1);
    assert(o.tier == 1 && strcmp(o.name, "alpine-lts") == 0);
    /* overwrite must NOT have consumed a second slot: fill the rest + 1 over */
    for (uint32_t s = 1; s <= LUCAS_PERSONA_SESS_MAX; s++)
        if (s != 7) (void)lucas_persona_session_set(s, &a);
    /* 16 slots used (1..16 incl. the reused 7) → a 17th distinct session fails */
    assert(lucas_persona_session_set(LUCAS_PERSONA_SESS_MAX + 1, &a) == -28);
}

static void test_clear_isolates(void) {
    lucas_persona_session_init();
    lucas_persona_t a = { .profile = 0 };
    lucas_persona_session_set(7, &a);
    lucas_persona_session_set(9, &a);
    lucas_persona_session_clear(7);
    lucas_persona_t o;
    assert(lucas_persona_session_get(7, &o) == 0);   /* reaped */
    assert(lucas_persona_session_get(9, &o) == 1);   /* sibling untouched */
    lucas_persona_session_clear(0);                  /* no-op, must not crash */
    assert(lucas_persona_session_get(9, &o) == 1);
}

static void test_table_full(void) {
    lucas_persona_session_init();
    lucas_persona_t a = { .profile = 0 };
    for (uint32_t s = 1; s <= LUCAS_PERSONA_SESS_MAX; s++)
        assert(lucas_persona_session_set(s, &a) == 0);
    assert(lucas_persona_session_set(LUCAS_PERSONA_SESS_MAX + 1, &a) == -28);
    /* an existing session can still be overwritten even when full */
    assert(lucas_persona_session_set(1, &a) == 0);
}

static void test_default_is_canonical_alpine(void) {
    lucas_persona_t d;
    lucas_persona_default(&d);
    assert(d.profile == 0 && d.tier == 2);
    assert(strcmp(d.name, "alpine-edge") == 0);
    assert(strcmp(d.host, "prod-db-01")  == 0);
}

static void test_for_profile_two_personas(void) {
    lucas_persona_t a, u, x;
    lucas_persona_for_profile(LUCAS_PERSONA_ALPINE, &a);
    lucas_persona_for_profile(LUCAS_PERSONA_DEBIAN, &u);
    /* the two personas are DISTINCT, each internally coherent */
    assert(a.profile == LUCAS_PERSONA_ALPINE && strcmp(a.host, "prod-db-01") == 0);
    assert(u.profile == LUCAS_PERSONA_DEBIAN && strcmp(u.host, "debian-app-01") == 0);
    assert(strcmp(a.name, u.name) != 0 && strcmp(a.host, u.host) != 0);
    /* an unknown profile falls back to Alpine (the canonical) */
    lucas_persona_for_profile(99, &x);
    assert(x.profile == LUCAS_PERSONA_ALPINE && strcmp(x.host, "prod-db-01") == 0);
}

int main(void) {
    test_set_get_per_session();
    test_session0_ignored();
    test_overwrite_reuses_slot();
    test_clear_isolates();
    test_table_full();
    test_default_is_canonical_alpine();
    test_for_profile_two_personas();
    printf("persona_session_unit: OK\n");
    return 0;
}
