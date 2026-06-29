#ifndef LUCAS_SOTFS_INSTALL_H
#define LUCAS_SOTFS_INSTALL_H

#include <stddef.h>

/* sotFS-ζ · canary-installing API.
 *
 * Install a canary file at the given path with content.
 * Atomic: either the file appears fully with content, or the
 * installing fails and nothing changes.  Returns 0 on success.
 *
 * Internally this is a single STO transaction wrapping
 * create_file + file_write, OR (if the file already exists)
 * an overwrite of its content.
 */
int lucas_sotfs_install(const char *path, const void *content, size_t len);

#endif /* LUCAS_SOTFS_INSTALL_H */
