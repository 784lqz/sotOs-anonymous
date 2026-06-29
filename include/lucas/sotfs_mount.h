#ifndef LUCAS_SOTFS_MOUNT_H
#define LUCAS_SOTFS_MOUNT_H
/* Per-sotfs-mount state: the graph is shared (g_sotfs); each mount resolves
 * suffixes from its OWN root inode so /tmp, /var, and the /usr upper are
 * distinct subtrees in one graph (no suffix collision). */
typedef struct { int root_id; const char *label; } sotfs_mount_t;
#endif
