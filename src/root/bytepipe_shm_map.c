/* sotOs · root · byte-channel cross-vspace SHM mapping.  See header.
 * Recipe copied from src/root/procd_shm_map.c (vka_alloc_frame +
 * vka_cnode_copy for the RO view + sel4utils_map_page on the child PD caps);
 * sel4utils_map_page never touches root's leaky bookkeeping, so a genuine
 * collision surfaces as a clean error, not a rootserver fault. */
#include "bytepipe_shm_map.h"

#include <stdio.h>
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <vka/capops.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <sotnet/bytepipe.h>

/* Lifetime = system: the rings are never torn down. */
static vka_object_t g_c2p_frames[BYTEPIPE_REGION_PAGES];
static seL4_CPtr    g_c2p_ro_caps[BYTEPIPE_REGION_PAGES];
static vka_object_t g_p2c_frames[BYTEPIPE_REGION_PAGES];
static seL4_CPtr    g_p2c_ro_caps[BYTEPIPE_REGION_PAGES];

/* N2-T · inbound ring pair · same lifetime/discipline as the outbound arrays. */
static vka_object_t g_in_c2p_frames[BYTEPIPE_REGION_PAGES];
static seL4_CPtr    g_in_c2p_ro_caps[BYTEPIPE_REGION_PAGES];
static vka_object_t g_in_p2c_frames[BYTEPIPE_REGION_PAGES];
static seL4_CPtr    g_in_p2c_ro_caps[BYTEPIPE_REGION_PAGES];

/* SSH canary shell (Phase B) · the decrypted-shell ring pair · same lifetime. */
static vka_object_t g_shell_in_frames[BYTEPIPE_REGION_PAGES];
static seL4_CPtr    g_shell_in_ro_caps[BYTEPIPE_REGION_PAGES];
static vka_object_t g_shell_out_frames[BYTEPIPE_REGION_PAGES];
static seL4_CPtr    g_shell_out_ro_caps[BYTEPIPE_REGION_PAGES];

/* Allocate `pages` frames + an RO copy of each.  Returns 0 / negative. */
static int alloc_ring(sotos_env_t *env, vka_object_t *frames,
                      seL4_CPtr *ro_caps, unsigned pages, const char *tag)
{
    for (unsigned i = 0; i < pages; ++i) {
        if (vka_alloc_frame(&env->vka, seL4_PageBits, &frames[i]) != 0) {
            printf("[root] bytepipe %s · frame %u alloc failed\n", tag, i);
            return -2;
        }
        seL4_CPtr ro_slot = 0;
        if (vka_cspace_alloc(&env->vka, &ro_slot) != 0) {
            printf("[root] bytepipe %s · ro cslot %u alloc failed\n", tag, i);
            return -3;
        }
        cspacepath_t src_path, dst_path;
        vka_cspace_make_path(&env->vka, frames[i].cptr, &src_path);
        vka_cspace_make_path(&env->vka, ro_slot, &dst_path);
        if (vka_cnode_copy(&dst_path, &src_path, seL4_CanRead) != 0) {
            printf("[root] bytepipe %s · ro cap copy %u failed\n", tag, i);
            vka_cspace_free(&env->vka, ro_slot);
            return -4;
        }
        ro_caps[i] = ro_slot;
    }
    return 0;
}

/* Map `pages` caps into `proc`'s PD at base+i*4096 with `rights`.  Pass the RW
 * originals via `objs` (RO copies via `caps`); exactly one is non-NULL.
 * 0 / negative. */
static int map_ring(sotos_env_t *env, sel4utils_process_t *proc,
                    const seL4_CPtr *caps, const vka_object_t *objs,
                    uintptr_t base, seL4_CapRights_t rights,
                    unsigned pages, const char *tag)
{
    for (unsigned i = 0; i < pages; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        seL4_CPtr cap = objs ? objs[i].cptr : caps[i];
        void *vaddr = (void *)(base + (uintptr_t)i * 4096u);
        int err = sel4utils_map_page(&env->vka, proc->pd.cptr, cap, vaddr,
                                     rights, 1 /* cacheable */, paging, &npaging);
        if (err) {
            printf("[root] bytepipe %s · map[%u] @%p failed (err=%d)\n",
                   tag, i, vaddr, err);
            return -5;
        }
    }
    return 0;
}

int root_map_bytepipe_shm(sotos_env_t *env,
                          sel4utils_process_t *orch,
                          sel4utils_process_t *responder)
{
    if (!env || !orch || !responder) return -1;

    if (alloc_ring(env, g_c2p_frames, g_c2p_ro_caps,
                   BYTEPIPE_REGION_PAGES, "c2p") != 0) return -2;
    if (alloc_ring(env, g_p2c_frames, g_p2c_ro_caps,
                   BYTEPIPE_REGION_PAGES, "p2c") != 0) return -3;

    /* c2p: RW originals -> orch, RO copies -> responder. */
    if (map_ring(env, orch, NULL, g_c2p_frames, BYTEPIPE_C2P_VADDR,
                 seL4_ReadWrite, BYTEPIPE_REGION_PAGES, "c2p->orch(rw)") != 0)
        return -4;
    if (map_ring(env, responder, g_c2p_ro_caps, NULL, BYTEPIPE_C2P_VADDR,
                 seL4_CanRead, BYTEPIPE_REGION_PAGES, "c2p->resp(ro)") != 0)
        return -5;

    /* p2c: RW originals -> responder, RO copies -> orch. */
    if (map_ring(env, responder, NULL, g_p2c_frames, BYTEPIPE_P2C_VADDR,
                 seL4_ReadWrite, BYTEPIPE_REGION_PAGES, "p2c->resp(rw)") != 0)
        return -6;
    if (map_ring(env, orch, g_p2c_ro_caps, NULL, BYTEPIPE_P2C_VADDR,
                 seL4_CanRead, BYTEPIPE_REGION_PAGES, "p2c->orch(ro)") != 0)
        return -7;

    printf("[root] bytepipe SHM mapped · c2p@0x%lx p2c@0x%lx · %u+%u frames\n",
           (unsigned long)BYTEPIPE_C2P_VADDR, (unsigned long)BYTEPIPE_P2C_VADDR,
           BYTEPIPE_REGION_PAGES, BYTEPIPE_REGION_PAGES);
    return 0;
}

/* N2-T · inbound framed transport · a SECOND ring pair mapped exactly like the
 * outbound pair (reuses alloc_ring/map_ring verbatim · SAME RW/RO direction):
 *   in_c2p (orch -> synth): RW originals -> orch, RO copies -> responder.
 *   in_p2c (synth -> orch): RW originals -> responder, RO copies -> orch. */
int root_map_bytepipe_shm2(sotos_env_t *env,
                           sel4utils_process_t *orch,
                           sel4utils_process_t *responder)
{
    if (!env || !orch || !responder) return -1;
    if (alloc_ring(env, g_in_c2p_frames, g_in_c2p_ro_caps,
                   BYTEPIPE_REGION_PAGES, "in_c2p") != 0) return -2;
    if (alloc_ring(env, g_in_p2c_frames, g_in_p2c_ro_caps,
                   BYTEPIPE_REGION_PAGES, "in_p2c") != 0) return -3;
    /* in_c2p: RW -> orch (producer), RO -> responder. */
    if (map_ring(env, orch, NULL, g_in_c2p_frames, BYTEPIPE_IN_C2P_VADDR,
                 seL4_ReadWrite, BYTEPIPE_REGION_PAGES, "in_c2p->orch(rw)") != 0) return -4;
    if (map_ring(env, responder, g_in_c2p_ro_caps, NULL, BYTEPIPE_IN_C2P_VADDR,
                 seL4_CanRead, BYTEPIPE_REGION_PAGES, "in_c2p->resp(ro)") != 0) return -5;
    /* in_p2c: RW -> responder (producer), RO -> orch. */
    if (map_ring(env, responder, NULL, g_in_p2c_frames, BYTEPIPE_IN_P2C_VADDR,
                 seL4_ReadWrite, BYTEPIPE_REGION_PAGES, "in_p2c->resp(rw)") != 0) return -6;
    if (map_ring(env, orch, g_in_p2c_ro_caps, NULL, BYTEPIPE_IN_P2C_VADDR,
                 seL4_CanRead, BYTEPIPE_REGION_PAGES, "in_p2c->orch(ro)") != 0) return -7;
    printf("[root] inbound bytepipe SHM mapped · in_c2p@0x%lx in_p2c@0x%lx\n",
           (unsigned long)BYTEPIPE_IN_C2P_VADDR, (unsigned long)BYTEPIPE_IN_P2C_VADDR);
    return 0;
}

/* SSH canary shell (Phase B) · a THIRD ring pair carrying the decrypted shell
 * stream, mapped exactly like the inbound pair (reuses alloc_ring/map_ring).
 *   shell_in  (net-synth -> orch/busybox): RW originals -> responder, RO -> orch.
 *   shell_out (orch/busybox -> net-synth): RW originals -> orch,      RO -> responder. */
int root_map_bytepipe_shm3(sotos_env_t *env,
                           sel4utils_process_t *orch,
                           sel4utils_process_t *responder)
{
    if (!env || !orch || !responder) return -1;
    if (alloc_ring(env, g_shell_in_frames, g_shell_in_ro_caps,
                   BYTEPIPE_REGION_PAGES, "shell_in") != 0) return -2;
    if (alloc_ring(env, g_shell_out_frames, g_shell_out_ro_caps,
                   BYTEPIPE_REGION_PAGES, "shell_out") != 0) return -3;
    /* shell_in: RW -> responder (net-synth is the producer), RO -> orch. */
    if (map_ring(env, responder, NULL, g_shell_in_frames, BYTEPIPE_SHELL_IN_VADDR,
                 seL4_ReadWrite, BYTEPIPE_REGION_PAGES, "shell_in->resp(rw)") != 0) return -4;
    if (map_ring(env, orch, g_shell_in_ro_caps, NULL, BYTEPIPE_SHELL_IN_VADDR,
                 seL4_CanRead, BYTEPIPE_REGION_PAGES, "shell_in->orch(ro)") != 0) return -5;
    /* shell_out: RW -> orch (busybox is the producer), RO -> responder. */
    if (map_ring(env, orch, NULL, g_shell_out_frames, BYTEPIPE_SHELL_OUT_VADDR,
                 seL4_ReadWrite, BYTEPIPE_REGION_PAGES, "shell_out->orch(rw)") != 0) return -6;
    if (map_ring(env, responder, g_shell_out_ro_caps, NULL, BYTEPIPE_SHELL_OUT_VADDR,
                 seL4_CanRead, BYTEPIPE_REGION_PAGES, "shell_out->resp(ro)") != 0) return -7;
    printf("[root] shell bytepipe SHM mapped · shell_in@0x%lx shell_out@0x%lx\n",
           (unsigned long)BYTEPIPE_SHELL_IN_VADDR, (unsigned long)BYTEPIPE_SHELL_OUT_VADDR);
    return 0;
}
