/* Per-session persona context (M3) — the g_profile→per-session seam.
 *
 * A side-table mapping cow_session → persona identity (profile/tier/name/host).
 * The SSH spawn stamps each new session's persona here; truth-core renders the
 * operator view from it and the attacker read path migrates onto it over time.
 *
 * Like sotfs_session.c / cow_overlay.c this is a freestanding static-pool module
 * (no malloc, no seL4/vfs deps) so it host-unit-tests with plain `cc`.
 */
#include "lucas/persona_session.h"

typedef struct {
    uint32_t        session;
    uint8_t         used;
    lucas_persona_t p;
} persona_slot_t;

static persona_slot_t g_tab[LUCAS_PERSONA_SESS_MAX];

static int slot_find(uint32_t session)
{
    for (int i = 0; i < LUCAS_PERSONA_SESS_MAX; i++)
        if (g_tab[i].used && g_tab[i].session == session) return i;
    return -1;
}

/* Bounded copy into a fixed char field (no string.h dep). */
static void field_copy(char *dst, int cap, const char *src)
{
    int i = 0;
    if (src) for (; i < cap - 1 && src[i]; i++) dst[i] = src[i];
    dst[i] = '\0';
}

void lucas_persona_session_init(void)
{
    for (int i = 0; i < LUCAS_PERSONA_SESS_MAX; i++) g_tab[i].used = 0;
}

int lucas_persona_session_set(uint32_t session, const lucas_persona_t *p)
{
    if (session == 0 || !p) return 0;          /* session 0 = operator · no ctx */
    int i = slot_find(session);
    if (i < 0) {
        for (int k = 0; k < LUCAS_PERSONA_SESS_MAX; k++)
            if (!g_tab[k].used) { i = k; g_tab[k].used = 1; g_tab[k].session = session; break; }
        if (i < 0) return -28;                 /* -ENOSPC · table full (anti-DoS) */
    }
    g_tab[i].p = *p;
    return 0;
}

int lucas_persona_session_get(uint32_t session, lucas_persona_t *out)
{
    int i = slot_find(session);
    if (i < 0) return 0;
    if (out) *out = g_tab[i].p;
    return 1;
}

void lucas_persona_session_clear(uint32_t session)
{
    if (session == 0) return;
    int i = slot_find(session);
    if (i >= 0) g_tab[i].used = 0;
}

void lucas_persona_for_profile(uint8_t profile, lucas_persona_t *out)
{
    if (!out) return;
    out->tier = 2;                             /* the Tier-2 surface SSH sessions wear */
    if (profile == LUCAS_PERSONA_DEBIAN) {
        out->profile = LUCAS_PERSONA_DEBIAN;
        field_copy(out->name, LUCAS_PERSONA_NAME_MAX, "debian-trixie");
        /* host MUST equal debian_entries' /etc/hostname (uname -n coherence). */
        field_copy(out->host, LUCAS_PERSONA_HOST_MAX, "debian-app-01");
        return;
    }
    out->profile = LUCAS_PERSONA_ALPINE;
    field_copy(out->name, LUCAS_PERSONA_NAME_MAX, "alpine-edge");
    field_copy(out->host, LUCAS_PERSONA_HOST_MAX, "prod-db-01");
}

void lucas_persona_default(lucas_persona_t *out)
{
    lucas_persona_for_profile(LUCAS_PERSONA_ALPINE, out);
}
