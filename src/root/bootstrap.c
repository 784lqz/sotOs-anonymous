#include "bootstrap.h"

#include <sel4platsupport/bootinfo.h>
#include <simple-default/simple-default.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>
#include <vka/capops.h>
#include <sel4utils/vspace.h>
#include <sel4utils/process.h>
#include <sel4utils/process_config.h>
#include <sel4/constants.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* L11-β-2 · Option C probe · bump from 1 MiB → 16 MiB so root can track
 * the ~6500 frame caps needed to load sotOs-lucas-orch.elf (26 MiB after
 * embedding CPython 3.12 static into its CPIO archive).
 * Untyped memory itself is plenty (QEMU gives ~1 GB); the bottleneck was
 * allocman's metadata pool, not the actual frame backing store. */
#define ALLOCATOR_STATIC_POOL_SIZE (16 << 20)
static char allocator_mem_pool[ALLOCATOR_STATIC_POOL_SIZE] __attribute__((aligned(4096)));

int sotos_bootstrap(sotos_env_t *env)
{
    env->boot_info = platsupport_get_bootinfo();
    if (!env->boot_info) {
        printf("[root] platsupport_get_bootinfo failed\n");
        return -1;
    }

    simple_default_init_bootinfo(&env->simple, env->boot_info);

    env->allocman = bootstrap_use_current_simple(
        &env->simple,
        ALLOCATOR_STATIC_POOL_SIZE,
        allocator_mem_pool);
    if (!env->allocman) {
        printf("[root] allocator bootstrap failed\n");
        return -1;
    }

    allocman_make_vka(&env->vka, env->allocman);

    int err = sel4utils_bootstrap_vspace_with_bootinfo_leaky(
        &env->vspace, &env->vspace_data,
        simple_get_pd(&env->simple),
        &env->vka, env->boot_info);
    if (err) {
        printf("[root] vspace bootstrap failed (err=%d)\n", err);
        return -1;
    }

    printf("[root] bootstrap OK · root task environment ready\n");
    return 0;
}

seL4_CPtr sotos_spawn_child(sotos_env_t *env, const char *elf_name,
                            const char *child_name,
                            seL4_CPtr ep, seL4_Word badge)
{
    (void)child_name;

    /* If caller provided an endpoint, use it (client pattern). Otherwise
     * allocate a new one and return it (server pattern). */
    seL4_CPtr listen_ep = ep;
    if (listen_ep == 0) {
        vka_object_t ep_obj;
        int err_ep = vka_alloc_endpoint(&env->vka, &ep_obj);
        if (err_ep) {
            printf("[root] spawn(%s): vka_alloc_endpoint failed (err=%d)\n",
                   elf_name, err_ep);
            return 0;
        }
        listen_ep = ep_obj.cptr;
    }

    /* Configure the child with priority seL4_MaxPrio (same as root).
     * Round-robin scheduling kicks in for threads of equal priority, so
     * seL4_Yield() from root effectively cedes to children. Setting
     * children below root's priority means root preempts them and they
     * never run (we measured this: prio=0 or prio=254 both starve). */
    sel4utils_process_config_t config = process_config_default_simple(
        &env->simple, elf_name, seL4_MaxPrio);
    config = process_config_mcp(config, seL4_MaxPrio);

    sel4utils_process_t process;
    int err = sel4utils_configure_process_custom(&process, &env->vka, &env->vspace,
                                                 config);
    if (err) {
        printf("[root] spawn(%s): configure_process_custom failed (err=%d)\n",
               elf_name, err);
        return 0;
    }

    cspacepath_t ep_path;
    vka_cspace_make_path(&env->vka, listen_ep, &ep_path);
    seL4_CPtr child_slot = sel4utils_mint_cap_to_process(
        &process, ep_path,
        seL4_AllRights,
        badge);
    if (child_slot == 0) {
        printf("[root] spawn(%s): mint_cap_to_process failed\n", elf_name);
        return 0;
    }

    char slot_str[32];
    snprintf(slot_str, sizeof(slot_str), "%lu", (unsigned long)child_slot);
    char *argv[] = { (char *)elf_name, slot_str };

    err = sel4utils_spawn_process_v(&process, &env->vka, &env->vspace,
                                     2, argv, 1 /* resume */);
    if (err) {
        printf("[root] spawn(%s): spawn_process_v failed (err=%d)\n",
               elf_name, err);
        return 0;
    }

    printf("[root] spawned %s (badge=%lu, child_slot=%lu, prio=%d, ep=%lu)\n",
           elf_name, (unsigned long)badge, (unsigned long)child_slot,
           seL4_MaxPrio, (unsigned long)listen_ep);
    return listen_ep;
}

int sotos_spawn_orch(sotos_env_t *env, const char *elf_name,
                      const char *child_name,
                      sel4utils_process_t *out_proc,
                      seL4_CPtr *out_ep, seL4_Word badge)
{
    (void)child_name;

    /* Always allocate a fresh endpoint for the orchestrator. */
    vka_object_t ep_obj;
    int err_ep = vka_alloc_endpoint(&env->vka, &ep_obj);
    if (err_ep) {
        printf("[root] spawn_orch(%s): vka_alloc_endpoint failed (err=%d)\n",
               elf_name, err_ep);
        return err_ep;
    }

    /* L11-β-2 · Configure with a larger CNode.  17 bits (131072 slots) held
     * Python, but `apt-get update` over the FULL trixie index is the heavy-tail
     * consumer: its 256 MiB arena holds a ~156 MiB pkgCache = ~40k frame cslots
     * BORROWED from this CNode (arena.c heavy_cspace_alloc → orch allocman), and
     * when apt fork()s, the child eager-copies ~30k more cache pages = ~30k more
     * borrowed cslots → 131072 exhausts ("heavy cspace_alloc failed · allocman
     * cslots exhausted" → orch abort in perform_reservation).  18 bits = 262144
     * slots covers apt + a forking child + orch base.  COST: the 4 MiB CNode
     * needs a -m 4096 baseline (the -m 2048 headless boot wedges into "orch
     * shell-loop captive").  All three CNode-size sites must agree (this,
     * orch/spawn.c orch_simple_cnode_size, orch/bootstrap.c free_end + allocman). */
    sel4utils_process_config_t config = process_config_default_simple(
        &env->simple, elf_name, seL4_MaxPrio);
    config = process_config_mcp(config, seL4_MaxPrio);
    config = process_config_create_cnode(config, 18);

    sel4utils_process_t process;
    int err = sel4utils_configure_process_custom(&process, &env->vka, &env->vspace,
                                                 config);
    if (err) {
        printf("[root] spawn_orch(%s): configure_process_custom failed (err=%d)\n",
               elf_name, err);
        return err;
    }

    cspacepath_t ep_path;
    vka_cspace_make_path(&env->vka, ep_obj.cptr, &ep_path);
    seL4_CPtr child_slot = sel4utils_mint_cap_to_process(
        &process, ep_path,
        seL4_AllRights,
        badge);
    if (child_slot == 0) {
        printf("[root] spawn_orch(%s): mint_cap_to_process failed\n", elf_name);
        return -1;
    }

    char slot_str[32];
    snprintf(slot_str, sizeof(slot_str), "%lu", (unsigned long)child_slot);
    char *argv[] = { (char *)elf_name, slot_str };

    err = sel4utils_spawn_process_v(&process, &env->vka, &env->vspace,
                                     2, argv, 1 /* resume */);
    if (err) {
        printf("[root] spawn_orch(%s): spawn_process_v failed (err=%d)\n",
               elf_name, err);
        return err;
    }

    printf("[root] spawned orch %s (badge=%lu, child_slot=%lu, prio=%d, ep=%lu, cnode_bits=18)\n",
           elf_name, (unsigned long)badge, (unsigned long)child_slot,
           seL4_MaxPrio, (unsigned long)ep_obj.cptr);

    *out_proc = process;
    *out_ep   = ep_obj.cptr;
    return 0;
}
