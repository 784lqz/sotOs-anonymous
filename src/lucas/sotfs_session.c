/* Per-session sotfs-upper ownership map.
 *
 * The sotfs-backed writable upper layer is keyed per SSH session (cow_session).
 * Each sotfs inode created on behalf of a session is "owned" by it; the operator
 * truth-view (session 0) sees only base (unowned) inodes, so an attacker's
 * install is invisible outside the session and is freed on disconnect (reap).
 *
 * Like cow_overlay.c this is a freestanding static-pool module: NO host malloc,
 * NO seL4/sotfs deps, pure C — so it compiles standalone with `cc` for the host
 * unit test.  The owner map is a side-table (NOT an inode field) because
 * sotfs_inode_t is size-asserted (56 B) and persisted to the blkdev.
 */
#include "lucas/sotfs_session.h"

/* owner[i] = session owning 1-based inode (i+1); 0 = base/unowned. */
static uint32_t g_owner[LUCAS_SOTFS_SESS_MAX_INODES];

typedef struct { uint32_t session; uint32_t bytes; uint8_t used; } sess_acct_t;
static sess_acct_t g_acct[LUCAS_SOTFS_SESS_MAX];

void lucas_sotfs_session_init(void)
{
    for (int i = 0; i < LUCAS_SOTFS_SESS_MAX_INODES; i++) g_owner[i] = 0;
    for (int i = 0; i < LUCAS_SOTFS_SESS_MAX; i++) g_acct[i].used = 0;
}

/* inode_id is 1-based; slot is 0-based. Returns -1 for out-of-range ids. */
static int inode_slot(int inode_id)
{
    if (inode_id <= 0 || inode_id > LUCAS_SOTFS_SESS_MAX_INODES) return -1;
    return inode_id - 1;
}

void lucas_sotfs_session_tag(int inode_id, uint32_t session)
{
    int s = inode_slot(inode_id);
    if (s < 0) return;
    g_owner[s] = session;
}

uint32_t lucas_sotfs_session_owner(int inode_id)
{
    int s = inode_slot(inode_id);
    if (s < 0) return 0;
    return g_owner[s];
}

int lucas_sotfs_session_visible(int inode_id, uint32_t caller_session)
{
    uint32_t owner = lucas_sotfs_session_owner(inode_id);
    if (owner == 0) return 1;                      /* base: visible to all */
    return caller_session != 0 && owner == caller_session ? 1 : 0;
}

int lucas_sotfs_session_next_owned(uint32_t session, int after)
{
    if (session == 0) return 0;                    /* never reap "base" */
    /* `after` is a 1-based inode_id; it also equals the 0-based slot of the
     * next unchecked entry (the previous result sat at slot after-1), so
     * starting at s = after returns the next inode strictly greater than after. */
    for (int s = (after < 0 ? 0 : after); s < LUCAS_SOTFS_SESS_MAX_INODES; s++) {
        if (g_owner[s] == session) return s + 1;   /* 1-based inode id > after */
    }
    return 0;
}

void lucas_sotfs_session_clear(uint32_t session)
{
    if (session == 0) return;
    for (int i = 0; i < LUCAS_SOTFS_SESS_MAX_INODES; i++)
        if (g_owner[i] == session) g_owner[i] = 0;
    for (int i = 0; i < LUCAS_SOTFS_SESS_MAX; i++)
        if (g_acct[i].used && g_acct[i].session == session) g_acct[i].used = 0;
}

/* Find the accounting slot for `session`, or -1 if not present. */
static int acct_find(uint32_t session)
{
    for (int i = 0; i < LUCAS_SOTFS_SESS_MAX; i++)
        if (g_acct[i].used && g_acct[i].session == session) return i;
    return -1;
}

int lucas_sotfs_session_charge(uint32_t session, uint32_t bytes)
{
    if (session == 0) return 0;                    /* base writes are not charged */
    int i = acct_find(session);
    if (i < 0) {
        for (int k = 0; k < LUCAS_SOTFS_SESS_MAX; k++) {
            if (!g_acct[k].used) { i = k; g_acct[k].used = 1;
                                   g_acct[k].session = session; g_acct[k].bytes = 0; break; }
        }
        if (i < 0) return -28;                     /* -ENOSPC: session table full */
    }
    /* Reject if the add would exceed the cap (and guard the uint32 add). */
    if (bytes > LUCAS_SOTFS_SESS_CAP_BYTES ||
        g_acct[i].bytes > LUCAS_SOTFS_SESS_CAP_BYTES - bytes) return -28;
    g_acct[i].bytes += bytes;
    return 0;
}

void lucas_sotfs_session_uncharge(uint32_t session, uint32_t bytes)
{
    int i = acct_find(session);
    if (i < 0) return;
    g_acct[i].bytes = bytes >= g_acct[i].bytes ? 0 : g_acct[i].bytes - bytes;
}

uint32_t lucas_sotfs_session_bytes(uint32_t session)
{
    int i = acct_find(session);
    return i < 0 ? 0 : g_acct[i].bytes;
}
