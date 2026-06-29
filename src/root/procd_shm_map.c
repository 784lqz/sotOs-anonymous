/* sotOs · root · procd↔orch shared-memory cross-vspace mapping.  See header. */
#include "procd_shm_map.h"

#include <stdio.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <sel4utils/mapping.h>    /* sel4utils_map_page, VSPACE_MAP_PAGING_OBJECTS */
#include <sel4utils/process.h>    /* sel4utils_process_t.pd */
#include <procd/shm.h>            /* PROCD_SHM_BYTES */

#define PROCD_SHM_PAGES   (PROCD_SHM_BYTES / 4096u)   /* 256 */

/* Fixed, 2 MiB-aligned vaddrs for the SHM region in each child.  Chosen far
 * above every ELF image, muslc morecore, orch's client-vspace bump range
 * (0x20000000-0x28000000) and the 0x40000000 mmap area — collision-free by
 * construction.  We map via the child's PD cap with sel4utils_map_page (raw
 * cap ops + vka-allocated paging structures), which — unlike the vspace_t
 * abstraction — never touches root's leaky bookkeeping, so it cannot fault
 * the rootserver.  A genuine collision would surface as a clean map error
 * (caller falls back to NTF-only), not a fault. */
#define PROCD_SHM_RW_VADDR   0x800000000UL   /* procd's RW view (argv[4])          */
#define PROCD_SHM_RO_VADDR   0x900000000UL   /* orch's RO view  (bs.procd_shm_base) */

/* Lifetime = system: the SHM is never torn down, so the frame objects and
 * the RO copy caps must never be reclaimed.  Static storage in root. */
static vka_object_t g_shm_frames[PROCD_SHM_PAGES];
static seL4_CPtr    g_shm_ro_caps[PROCD_SHM_PAGES];

int root_map_procd_shm(sotos_env_t *env,
                       sel4utils_process_t *procd,
                       sel4utils_process_t *orch,
                       uintptr_t *out_procd_rw,
                       uintptr_t *out_orch_ro)
{
    if (!env || !procd || !orch || !out_procd_rw || !out_orch_ro) return -1;
    *out_procd_rw = 0;
    *out_orch_ro  = 0;

    /* Phase A · allocate all 256 frames + RO copies BEFORE any mapping
     * (keeps the allocman pool contiguous; mirrors the virtio-blk batch). */
    for (unsigned i = 0; i < PROCD_SHM_PAGES; ++i) {
        int err = vka_alloc_frame(&env->vka, seL4_PageBits, &g_shm_frames[i]);
        if (err) {
            printf("[root] procd SHM · frame %u alloc failed (err=%d)\n", i, err);
            return -2;
        }
        seL4_CPtr ro_slot = 0;
        if (vka_cspace_alloc(&env->vka, &ro_slot) != 0) {
            printf("[root] procd SHM · ro cslot %u alloc failed\n", i);
            return -3;
        }
        cspacepath_t src_path, dst_path;
        vka_cspace_make_path(&env->vka, g_shm_frames[i].cptr, &src_path);
        vka_cspace_make_path(&env->vka, ro_slot, &dst_path);
        if (vka_cnode_copy(&dst_path, &src_path, seL4_CanRead) != 0) {
            printf("[root] procd SHM · ro cap copy %u failed\n", i);
            vka_cspace_free(&env->vka, ro_slot);
            return -4;
        }
        g_shm_ro_caps[i] = ro_slot;
    }

    /* Phase B · map the originals RW into procd's PD (raw cap op). */
    for (unsigned i = 0; i < PROCD_SHM_PAGES; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        void *vaddr = (void *)(PROCD_SHM_RW_VADDR + (uintptr_t)i * 4096u);
        int err = sel4utils_map_page(&env->vka, procd->pd.cptr,
                                     g_shm_frames[i].cptr, vaddr,
                                     seL4_ReadWrite, 1 /* cacheable */,
                                     paging, &npaging);
        if (err) {
            printf("[root] procd SHM · procd map[%u] @%p failed (err=%d)\n",
                   i, vaddr, err);
            return -5;
        }
    }

    /* Phase C · map the RO copies into orch's PD (raw cap op). */
    for (unsigned i = 0; i < PROCD_SHM_PAGES; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        void *vaddr = (void *)(PROCD_SHM_RO_VADDR + (uintptr_t)i * 4096u);
        int err = sel4utils_map_page(&env->vka, orch->pd.cptr,
                                     g_shm_ro_caps[i], vaddr,
                                     seL4_CanRead, 1 /* cacheable */,
                                     paging, &npaging);
        if (err) {
            printf("[root] procd SHM · orch map[%u] @%p failed (err=%d)\n",
                   i, vaddr, err);
            return -6;
        }
    }

    *out_procd_rw = PROCD_SHM_RW_VADDR;
    *out_orch_ro  = PROCD_SHM_RO_VADDR;
    printf("[root] procd SHM mapped · rw=0x%lx (procd) ro=0x%lx (orch) · %u frames\n",
           (unsigned long)*out_procd_rw, (unsigned long)*out_orch_ro,
           PROCD_SHM_PAGES);
    return 0;
}
