/*
 * sotOs · LUCAS · Doom WAD VFS backend.
 *
 * Exposes /doom1.wad (the Doom shareware IWAD) as a read-only regular file
 * backed by the binstore region of sotfs.img.
 *
 * Mount prefix: "/doom1.wad"
 * Single exposed file: "/doom1.wad" (suffix "" or "/doom1.wad")
 */

#ifndef LUCAS_BACKENDS_DOOM_WAD_H
#define LUCAS_BACKENDS_DOOM_WAD_H

#include <lucas/vfs.h>

/* Returns a vfs_mount_t with prefix "/doom1.wad" backed by binstore "doom1.wad". */
vfs_mount_t lucas_doom_wad_mount(void);

#endif /* LUCAS_BACKENDS_DOOM_WAD_H */
