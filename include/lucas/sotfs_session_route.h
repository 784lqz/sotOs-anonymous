#ifndef LUCAS_SOTFS_SESSION_ROUTE_H
#define LUCAS_SOTFS_SESSION_ROUTE_H
#include <stdint.h>
#include <stddef.h>
#include <lucas/vfs.h>   /* struct lx_stat */

/* The static `/` backend's reach into the shared sotfs graph for a Tier-2
 * session.  A `/`-rooted path that misses the static base (e.g. "/opt/x",
 * "/root/newfile") is stored under a dedicated graph subtree (root =
 * sotfs_mount_make_root("root")) keyed by the absolute path flattened
 * ('/' -> '_') so a whole-tree create needs no mkdir -p.  Every inode is tagged
 * to the session (Phase-1) + writes charged; reads/stats are owner-gated by the
 * SAME lucas_sotfs_session_visible the sotfs ops use.  session must be != 0. */

int     lucas_sotfs_route_has   (uint32_t session, const char *path);
int     lucas_sotfs_route_create(uint32_t session, const char *path, uint32_t mode); /* 0/-28/-22 */
int     lucas_sotfs_route_mkdir (uint32_t session, const char *path, uint32_t mode); /* 0/-17/-28 */
int64_t lucas_sotfs_route_write (uint32_t session, const char *path,
                                 const void *buf, size_t count, int64_t cursor);
int64_t lucas_sotfs_route_read  (uint32_t session, const char *path,
                                 void *buf, size_t count, int64_t cursor);
int     lucas_sotfs_route_stat  (uint32_t session, const char *path, struct lx_stat *out); /* 0/-2 */
int     lucas_sotfs_route_unlink(uint32_t session, const char *path);                /* 0/-2 */
/* Append this session's direct children of `dirpath` into a name/type buffer,
 * deduped vs the `have` names already present.  Returns the new count. */
int     lucas_sotfs_route_list_children(uint32_t session, const char *dirpath,
                                        char names[][32], uint8_t *types,
                                        int have, int max);
#endif /* LUCAS_SOTFS_SESSION_ROUTE_H */
