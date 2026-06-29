/*
 * sotOs root task · bootstrap utilities
 *
 * El root task recibe el bootinfo de seL4 y desde ahí establece:
 *   - allocator de caps (allocman)
 *   - allocator de virtual memory (vka)
 *   - abstracción simple del bootinfo (simple-default)
 *   - spawning de procesos hijos (sto server, test client)
 */

#ifndef SOTOS_ROOT_BOOTSTRAP_H
#define SOTOS_ROOT_BOOTSTRAP_H

#include <sel4/sel4.h>
#include <vka/vka.h>
#include <simple/simple.h>
#include <allocman/allocman.h>
#include <sel4utils/process.h>
#include <vspace/vspace.h>

typedef struct sotos_env {
    simple_t              simple;
    vka_t                 vka;
    allocman_t           *allocman;
    seL4_BootInfo        *boot_info;
    vspace_t              vspace;
    sel4utils_alloc_data_t vspace_data;
} sotos_env_t;

/* Initialize the root task environment from bootinfo. */
int sotos_bootstrap(sotos_env_t *env);

/* Spawn a child process from an ELF embedded in the CPIO archive.
 *
 * If `ep` is 0, allocates a fresh endpoint and mints it into the child
 * with `badge`. Returns the root's CPtr to that new endpoint (the server
 * pattern: the spawned process owns the listening side).
 *
 * If `ep` is non-zero, mints a badged copy of the given endpoint into the
 * child (the client pattern: a peer connects to an existing server's EP).
 * Returns `ep` unchanged on success.
 *
 * In both modes:
 *   - The child finds the cap in its own CSpace at the slot index passed
 *     via argv[1] (decimal string).
 *   - The badge applied is `badge`; this is what the server's
 *     seL4_Recv(&badge) surfaces — i.e. the kernel-enforced caller ID.
 *
 * Returns 0 on failure. */
seL4_CPtr sotos_spawn_child(sotos_env_t *env, const char *elf_name,
                            const char *child_name,
                            seL4_CPtr ep, seL4_Word badge);

/* Variant of sotos_spawn_child that bumps the child's CNode size so caps
 * can be delegated into it, and EXPOSES the process_t struct so the
 * caller can copy untypeds via sel4utils_copy_cap_to_process. */
int sotos_spawn_orch(sotos_env_t *env, const char *elf_name,
                      const char *child_name,
                      sel4utils_process_t *out_proc,
                      seL4_CPtr *out_ep, seL4_Word badge);

#endif /* SOTOS_ROOT_BOOTSTRAP_H */
