#ifndef LUCAS_PERSONA_SESSION_H
#define LUCAS_PERSONA_SESSION_H
#include <stdint.h>

/*
 * Per-session persona context (M3) — the g_profile→per-session seam.
 *
 * Today the attacker-visible persona is a GLOBAL mask (g_profile + the Tier-2
 * canary table): every concurrent SSH session wears the same identity.  This
 * module is the structural seam that makes the persona a PER-SESSION fact keyed
 * by cow_session, so multi-persona coexistence becomes possible (Alpine is the
 * canonical persona today; a future FULL persona keys off the same table — ONE
 * story per session).  truth-core renders the operator's view from this record;
 * the attacker read path migrates onto it incrementally.
 *
 * Freestanding static-pool module (mirrors sotfs_session.c): no malloc, no
 * seL4/vfs deps — so it compiles standalone with `cc` for the host unit test.
 * The profile is a plain uint8_t (NOT lucas_profile_t) to keep it dep-free; the
 * values match lucas_profile_t (0 = ALPINE, 1 = UBUNTU).
 */
#define LUCAS_PERSONA_SESS_MAX   16   /* concurrent sessions (== sotfs sess max) */
#define LUCAS_PERSONA_NAME_MAX   16   /* operator persona label */
#define LUCAS_PERSONA_HOST_MAX   24   /* attacker-visible nodename */

typedef struct {
    uint8_t profile;                      /* lucas_profile_t value (0=alpine,1=ubuntu) */
    uint8_t tier;                         /* containment tier (2 = the canary surface) */
    char    name[LUCAS_PERSONA_NAME_MAX]; /* operator label, e.g. "alpine-edge" */
    char    host[LUCAS_PERSONA_HOST_MAX]; /* attacker-visible nodename, e.g. "prod-db-01" */
} lucas_persona_t;

void lucas_persona_session_init(void);

/* Register/overwrite `session`'s persona (session 0 is ignored → returns 0).
 * Returns 0 on success, or -28 (-ENOSPC) when the table is full and `session`
 * is new (anti-DoS · an existing session can always be overwritten). */
int  lucas_persona_session_set(uint32_t session, const lucas_persona_t *p);

/* Look up `session`'s persona into *out.  Returns 1 if found, 0 otherwise. */
int  lucas_persona_session_get(uint32_t session, lucas_persona_t *out);

/* Reap a session's persona context (SSH disconnect).  No-op for session 0. */
void lucas_persona_session_clear(uint32_t session);

/* The canonical persona (Alpine).  The SINGLE definition the SSH spawn stamps
 * onto each new session — "what Alpine looks like" lives in ONE place. */
void lucas_persona_default(lucas_persona_t *out);

/* Persona profiles (mirror lucas_profile_t · kept as plain ints here). */
#define LUCAS_PERSONA_ALPINE   0
#define LUCAS_PERSONA_DEBIAN   1

/* The canonical persona for a profile — Alpine (prod-db-01, musl) or Ubuntu
 * (a coherent glibc box).  The round-robin SSH spawn stamps the chosen one.
 * Unknown profiles fall back to Alpine.  host MUST match that persona's
 * /etc/hostname so `uname -n` stays coherent. */
void lucas_persona_for_profile(uint8_t profile, lucas_persona_t *out);

#endif /* LUCAS_PERSONA_SESSION_H */
