/* sotOs · root · procd↔orch shared-memory cross-vspace mapping.
 *
 * Allocates the 1 MiB procd SHM as 256 explicit frames in root, maps the
 * originals RW into procd's vspace and read-only copies into orch's vspace.
 * Proven explicit-frame recipe (cf. src/orch/fork.c::share_region_ro and
 * src/sotfs/storage_virtio_blk.c) — NOT vspace_share_mem, which faults on
 * root's leaky bootstrap vspace.
 */
#ifndef SOTOS_ROOT_PROCD_SHM_MAP_H
#define SOTOS_ROOT_PROCD_SHM_MAP_H

#include "bootstrap.h"            /* sotos_env_t */
#include <sel4utils/process.h>    /* sel4utils_process_t */
#include <stdint.h>

/* Map the procd SHM: RW into *procd, RO into *orch.  On success returns 0
 * and writes the procd-side RW vaddr to *out_procd_rw and the orch-side RO
 * vaddr to *out_orch_ro.  On any failure returns negative and leaves the
 * out-vaddrs 0 (caller falls back to NTF-only mode). */
int root_map_procd_shm(sotos_env_t *env,
                       sel4utils_process_t *procd,
                       sel4utils_process_t *orch,
                       uintptr_t *out_procd_rw,
                       uintptr_t *out_orch_ro);

#endif /* SOTOS_ROOT_PROCD_SHM_MAP_H */
