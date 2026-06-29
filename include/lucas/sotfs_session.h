#ifndef LUCAS_SOTFS_SESSION_H
#define LUCAS_SOTFS_SESSION_H
#include <stdint.h>

/* Mirrors SOTFS_MAX_INODES (sotfs/graph.h) so the owner map covers every inode.
 * Kept as a local constant to keep this module free of sotfs/seL4 deps (so it
 * compiles standalone with `cc` for the host unit test, like cow_overlay.c). */
#define LUCAS_SOTFS_SESS_MAX_INODES 1024
#define LUCAS_SOTFS_SESS_MAX        16                  /* concurrent SSH sessions tracked */
#define LUCAS_SOTFS_SESS_CAP_BYTES  (192u * 1024u * 1024u) /* per-session upper cap · 32->192 MiB (apt arc P1 · trixie `Packages` ~46 MB decompressed + pkgcache.bin · DATA region is 256 MiB, leaves 64 MiB for /tmp + a 2nd small session) */

void     lucas_sotfs_session_init(void);

/* Ownership map.  inode_id is 1-based (as in sotfs_graph). owner 0 = base. */
void     lucas_sotfs_session_tag(int inode_id, uint32_t session);
uint32_t lucas_sotfs_session_owner(int inode_id);

/* Visibility: base (owner 0) is visible to all; an owned inode is visible only
 * to its owning session. caller_session 0 (the operator truth-view) sees base
 * only.  Returns 1 (visible) / 0 (hidden). */
int      lucas_sotfs_session_visible(int inode_id, uint32_t caller_session);

/* Capacity accounting (per session). charge returns 0 / -28 (ENOSPC) when the
 * add would exceed the 32 MiB cap or the session table is full. */
int      lucas_sotfs_session_charge  (uint32_t session, uint32_t bytes);
void     lucas_sotfs_session_uncharge(uint32_t session, uint32_t bytes);
uint32_t lucas_sotfs_session_bytes   (uint32_t session);

/* Reap iteration: returns the next owned inode_id strictly greater than `after`
 * (pass 0 — or any non-positive value — to start), or 0 when none remain.  The graph-side reap uses this to
 * free each owned inode without this module depending on the graph. */
int      lucas_sotfs_session_next_owned(uint32_t session, int after);

/* Clear all ownership + capacity accounting for a session (end of reap). */
void     lucas_sotfs_session_clear(uint32_t session);

/* Graph-side reap: free every sotfs inode owned by `session` — its data blocks
 * (incl. the disk bitmap, via sotfs_free_block), its parent edge, and the inode
 * itself — then clear the session's ownership + accounting.  Lives in
 * backends_sotfs.c because it touches the sotfs graph; declared here so orch can
 * call it at SSH disconnect.  No-op for session 0. */
void lucas_sotfs_session_reap(uint32_t session);

#endif /* LUCAS_SOTFS_SESSION_H */
