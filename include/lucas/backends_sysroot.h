/*
 * sotOs · LUCAS · musl sysroot VFS backend (tcc-libc).
 *
 * Mounts the read-only musl directory tree at "/usr": /usr/include/* and
 * /usr/lib/* are served from the sysroot region baked into sotfs.img
 * [64,112 MiB) (header at SOTFS_SYSROOT_HEADER_OFFSET, entry table, then
 * 4-KiB-aligned file data).  Read-only · sector-by-sector virtio-blk reads.
 *
 * If the on-disk header magic doesn't match or the entry count is zero/
 * oversize, the backend treats the tree as absent (ENOENT for all opens) ·
 * matches the "sysroot not populated" semantics so the rest of the system
 * keeps booting.
 */

#ifndef LUCAS_BACKENDS_SYSROOT_H
#define LUCAS_BACKENDS_SYSROOT_H

#include <lucas/vfs.h>

/* Returns a vfs_mount_t for /usr backed by the musl sysroot tree on
 * sotfs.img.  Reads the sysroot header + entry table on first call
 * (cached).  If the header is invalid (magic mismatch / zero count), the
 * backend returns -ENOENT for all opens · "sysroot not populated". */
vfs_mount_t lucas_sysroot_mount(void);

/* Install-arc · /usr as a writable OVERLAY: a sotfs upper subtree over the
 * read-only sysroot base (this function wraps lucas_sysroot_mount() as the
 * base layer).  Registered at "/usr" in place of the plain sysroot mount. */
vfs_mount_t lucas_usr_union_mount(void);

#endif /* LUCAS_BACKENDS_SYSROOT_H */
