/*
 * sotOs · LUCAS · unveil · per-path access restriction.
 *
 * Complementary primitive to pledge() · while pledge narrows the set of
 * operation CLASSES (stdio/rpath/inet/...) a sotBox may use, unveil narrows
 * the set of PATHS those operations may touch.
 *
 * Semantics (OpenBSD-style):
 *   - Before the first unveil() call: default-permit (every path allowed).
 *   - On the first call: the table is initialized · default-permit flips to
 *     default-deny, with the given path inserted as the sole permitted entry.
 *   - Subsequent calls: add new paths or NARROW existing ones (perms can
 *     only shrink, never widen) · widening returns -EPERM.
 *   - unveil(NULL, NULL): lock the table · no further mutation accepted.
 *
 * Matching is longest-prefix · /usr permits /usr/lib if the entry has the
 * needed perms; a more specific /usr/local entry overrides for paths under
 * /usr/local.  Default is deny once initialized.
 *
 * Per-sotBox state lives in lucas_state_t (see src/lucas/state.h next to
 * the pledge field).
 */
#ifndef SOTOS_LUCAS_UNVEIL_H
#define SOTOS_LUCAS_UNVEIL_H

#include <stdint.h>

#define UNVEIL_R 0x1   /* readable */
#define UNVEIL_W 0x2   /* writable */
#define UNVEIL_X 0x4   /* executable */

#define LUCAS_UNVEIL_MAX_ENTRIES 16
#define LUCAS_UNVEIL_PATH_MAX    96

typedef struct lucas_unveil_entry {
    char     path[LUCAS_UNVEIL_PATH_MAX];
    uint32_t perms;
} lucas_unveil_entry_t;

typedef struct lucas_unveil_state {
    lucas_unveil_entry_t entries[LUCAS_UNVEIL_MAX_ENTRIES];
    uint8_t              count;
    uint8_t              locked;      /* set when unveil(NULL,NULL) */
    uint8_t              initialized; /* set on first call */
} lucas_unveil_state_t;

struct lucas_state;

int64_t lucas_sys_unveil(struct lucas_state *st,
                         uint64_t path_vaddr,
                         uint64_t perms_vaddr,
                         uint64_t _a2, uint64_t _a3,
                         uint64_t _a4, uint64_t _a5);

/* want_perms is a mask (UNVEIL_R / UNVEIL_W / UNVEIL_X).
 * Returns 0 if path is permitted with those perms, -EACCES if not.
 * Returns 0 if unveil state is uninitialized (default-permit). */
int lucas_unveil_check(struct lucas_state *st,
                       const char *path,
                       uint32_t want_perms);

#endif /* SOTOS_LUCAS_UNVEIL_H */
