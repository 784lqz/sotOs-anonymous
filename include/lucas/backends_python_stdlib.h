/*
 * sotOs · LUCAS · python_stdlib VFS backend (L11-γ U2).
 *
 * Exposes ONE file at /install/lib/python312.zip · backed by the stdlib
 * region of sotfs.img (header at sector 0, zip starting at offset 4 KiB).
 * Read-only · sector-by-sector virtio-blk reads · no caching.
 *
 * If the on-disk header magic doesn't match or zip_size is zero/oversize,
 * the backend treats the file as absent (ENOENT) · matches the "stdlib
 * not populated" semantics so Python can fall back to whatever is next
 * in sys.path without crashing.
 */

#ifndef LUCAS_BACKENDS_PYTHON_STDLIB_H
#define LUCAS_BACKENDS_PYTHON_STDLIB_H

#include <lucas/vfs.h>

/* Returns a vfs_mount_t for /install/lib backed by python312.zip on sotfs.img.
 * Reads the stdlib header from sotfs.img sector 0 at first call (cached).
 * If the header is invalid (magic mismatch / zero zip_size), the backend
 * returns -ENOENT for all opens · matches "stdlib not populated" semantics. */
vfs_mount_t lucas_python_stdlib_mount(void);

#endif /* LUCAS_BACKENDS_PYTHON_STDLIB_H */
