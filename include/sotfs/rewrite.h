#ifndef SOTFS_REWRITE_H
#define SOTFS_REWRITE_H

#include <sotfs/graph.h>

typedef enum {
    SOTFS_OK              =  0,
    SOTFS_ERR_EXISTS      = -1,
    SOTFS_ERR_NOENT       = -2,
    SOTFS_ERR_NOTDIR      = -3,
    SOTFS_ERR_ISDIR       = -4,
    SOTFS_ERR_NOTEMPTY    = -5,
    SOTFS_ERR_NOSPACE     = -6,
    SOTFS_ERR_NAMETOOLONG = -7,
    SOTFS_ERR_INVAL       = -8,
} sotfs_err_t;

int sotfs_rewrite_create_file(sotfs_graph_t *g, int parent_id,
                                const char *name, uint32_t mode);
int sotfs_rewrite_mkdir(sotfs_graph_t *g, int parent_id,
                          const char *name, uint32_t mode);
int sotfs_rewrite_unlink(sotfs_graph_t *g, int parent_id, const char *name);
int sotfs_rewrite_rmdir(sotfs_graph_t *g, int parent_id, const char *name);
int sotfs_rewrite_rename(sotfs_graph_t *g, int p_src, const char *old_name,
                           int p_dst, const char *new_name);

int sotfs_file_write(sotfs_graph_t *g, int file_id, uint32_t offset,
                       const uint8_t *buf, uint32_t len);
int sotfs_file_read(const sotfs_graph_t *g, int file_id, uint32_t offset,
                      uint8_t *buf, uint32_t len);

#endif /* SOTFS_REWRITE_H */
