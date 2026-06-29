#ifndef LUCAS_SYMLINK_TABLE_H
#define LUCAS_SYMLINK_TABLE_H
#include <stdint.h>
/* In-memory CONTAINED symlink store for the Tier-2 honey shell.  Symlinks the
 * attacker creates in writable space (/tmp) are recorded here — NOT on the sotfs
 * blkdev — so readlink/lstat surface them like a real Linux (`ls -l`, `readlink`)
 * WITHOUT following: open() does not consult this table, so there is NO new
 * escape surface vs the prior contained no-op (a symlink to /etc/shadow still
 * `cat`s to ENOENT, never the target).  Keyed by COW session so an attacker's
 * links are isolated and reaped on SSH disconnect (mirrors the COW overlay). */
int  lucas_symlink_add (uint32_t session, const char *linkpath, const char *target); /* 0 / -errno */
const char *lucas_symlink_get(uint32_t session, const char *linkpath);  /* target or NULL */
void lucas_symlink_reap(uint32_t session);
#endif
