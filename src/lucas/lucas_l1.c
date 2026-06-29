/*
 * sotOs · LUCAS L1 entry implementation.
 *
 * Phase 1: receive host env + ELF bytes from root.
 * Phase 2: validate ELF, walk PT_LOAD segments (Task 6-7).
 * Phase 3: allocate client vspace, map segments, set up stack (Task 8-9).
 * Phase 4: allocate client TCB, fault EP, configure (Task 10).
 * Phase 5: enter fault loop until client exits (Tasks 11-21).
 */

#include "lucas_l1.h"
#include "state.h"
#include "elf_loader.h"
#include "stack_setup.h"
#include "client_setup.h"
#include "fault_loop.h"

#include <lucas/vfs.h>
#include <sel4utils/vspace.h>
#include <vka/object.h>
#include <stdio.h>
#include <string.h>

/* Slot allocator supplied by the orchestrator (sotbox_table.c).
 * The lucas library is always statically linked into orch, so these
 * symbols resolve at link time from src/orch/sotbox_table.c. */
extern int  sotbox_alloc_slot(lucas_state_t *st);
extern void sotbox_free_slot(int slot);

/* LUCAS_DYN_BIN_BASE / _INTERP_BASE / _BRK_BASE are defined in state.h
 * (shared with the MSYSCALL text-range check in fault_loop.c). */

/* Interp bytes come from the binstore (mirrors execve.c busybox fetch). */
extern void *orch_spawn_stage(size_t bytes);
extern long  binstore_lookup(const char *name, uint64_t *offset_out);
extern long  binstore_read(const char *name, void *buf, size_t cap);

int create_client_vspace(lucas_state_t *st) {
    /* Allocate VSpace root (PML4 on x86_64). */
    vka_object_t vspace_root_obj;
    int err = vka_alloc_vspace_root(st->vka, &vspace_root_obj);
    if (err) {
        printf("[lucas] vka_alloc_vspace_root failed (err=%d)\n", err);
        return err;
    }
    st->client_vspace = vspace_root_obj.cptr;
    st->client_vspace_obj = vspace_root_obj;   /* P2a · capture for teardown (needs .ut) */

    /* Assign an ASID to the PML4 so the kernel marks it as valid.
     * seL4_X86_ASIDPool_Assign sets capPML4IsMapped=1 which is required
     * by isValidNativeRoot() before any page can be mapped into this vspace.
     * process.c skips this for x86_64 (it configures ASID via TCBSetSpace),
     * but we need it here because we map pages before creating a TCB. */
    seL4_CPtr asid_pool = simple_get_init_cap(st->simple,
                                              seL4_CapInitThreadASIDPool);
    seL4_Error asid_err = seL4_X86_ASIDPool_Assign(asid_pool, st->client_vspace);
    if (asid_err != seL4_NoError) {
        printf("[lucas] seL4_X86_ASIDPool_Assign failed (err=%d)\n", (int)asid_err);
        return (int)asid_err;
    }

    err = sel4utils_get_vspace(st->parent_vspace,
                               &st->client_vspace_abs,
                               &st->client_vspace_data,
                               st->vka,
                               st->client_vspace,
                               NULL, NULL);
    if (err) {
        printf("[lucas] sel4utils_get_vspace failed (err=%d)\n", err);
        return err;
    }

    printf("[lucas] client vspace ready (cptr=%lu)\n",
           (unsigned long)st->client_vspace);
    return 0;
}

/*
 * lucas_elf_load_program — load a validated program (static OR dynamic) into
 * the ALREADY-CREATED client vspace, setting st->entry_point and, for dynamic
 * binaries, the auxv state (bin_* and interp_base) and brk_base.
 *
 * Shared by lucas_run_l1 (initial slot-0 boot) and sotbox_init (spawn.c, the
 * fixture-spawn path) so both honour PT_INTERP.  Static path is unchanged
 * (sel4utils_elf_load at fixed vaddrs); dynamic path loads the PIE at
 * LUCAS_DYN_BIN_BASE + ld-musl at LUCAS_DYN_INTERP_BASE and jumps to ld-musl.
 */
int lucas_elf_load_program(lucas_state_t *st, const void *elf_bytes,
                           unsigned long elf_size)
{
    st->is_dynamic = lucas_elf_is_dynamic(elf_bytes);

    if (!st->is_dynamic) {
        /* Static ET_EXEC: unchanged path (sel4utils_elf_load, fixed vaddrs). */
        st->entry_point = lucas_elf_entry(elf_bytes);
        if (lucas_elf_load_into_client(st, elf_bytes, elf_size) != 0) {
            printf("[lucas] segment mapping failed\n");
            return -1;
        }
        return 0;
    }

    /* Dynamic PIE: load the binary at BIN_BASE, then ld-musl at INTERP_BASE,
     * then jump to ld-musl's entry. */
    char interp[128] = {0};
    if (!lucas_elf_get_interp(elf_bytes, (size_t)elf_size,
                              interp, sizeof(interp))) {
        printf("[lucas] dynamic ELF but no PT_INTERP path\n");
        return -1;
    }
    printf("[lucas] dynamic ELF · interp='%s'\n", interp);

    /* 1. Load the main binary at BIN_BASE and capture its phdr/entry BEFORE
     *    re-staging clobbers elf_bytes. */
    if (lucas_elf_load_at_base(st, elf_bytes, elf_size,
                               LUCAS_DYN_BIN_BASE) != 0) {
        printf("[lucas] binary base-load failed\n");
        return -1;
    }
    st->bin_base        = LUCAS_DYN_BIN_BASE;
    st->bin_phdr_vaddr  = LUCAS_DYN_BIN_BASE + lucas_elf_phdr_vaddr(elf_bytes);
    st->bin_phnum       = lucas_elf_phnum(elf_bytes);
    st->bin_phent       = lucas_elf_phentsize(elf_bytes);
    st->bin_entry_vaddr = LUCAS_DYN_BIN_BASE + lucas_elf_entry(elf_bytes);

    /* 2. Fetch ld-musl from the binstore by its basename.  The INTERP path is
     *    an absolute "/lib/..." string; the binstore is keyed by basename. */
    const char *base = interp;
    for (const char *p = interp; *p; ++p) if (*p == '/') base = p + 1;
    uint64_t ld_off = 0;
    long ld_size = binstore_lookup(base, &ld_off);
    if (ld_size <= 0) {
        printf("[lucas] interp '%s' not in binstore\n", base);
        return -1;
    }
    void *ld_buf = orch_spawn_stage((size_t)ld_size);
    if (!ld_buf || binstore_read(base, ld_buf, (size_t)ld_size) != ld_size) {
        printf("[lucas] interp '%s' binstore read failed\n", base);
        return -1;
    }
    if (!lucas_elf_validate(ld_buf, (size_t)ld_size)) {
        printf("[lucas] interp failed ELF validation\n");
        return -1;
    }

    /* 3. Load ld-musl at INTERP_BASE and set the entry to its entrypoint. */
    if (lucas_elf_load_at_base(st, ld_buf, (size_t)ld_size,
                               LUCAS_DYN_INTERP_BASE) != 0) {
        printf("[lucas] interp base-load failed\n");
        return -1;
    }
    st->interp_base = LUCAS_DYN_INTERP_BASE;
    st->entry_point = LUCAS_DYN_INTERP_BASE + lucas_elf_entry(ld_buf);
    st->brk_base    = LUCAS_DYN_BRK_BASE;
    st->brk_top     = st->brk_base;
    printf("[lucas] dynamic ready · bin_base=0x%lx interp_base=0x%lx "
           "entry=0x%lx phdr=0x%lx phnum=%u\n",
           (unsigned long)st->bin_base, (unsigned long)st->interp_base,
           (unsigned long)st->entry_point, (unsigned long)st->bin_phdr_vaddr,
           st->bin_phnum);
    return 0;
}

int lucas_run_l1(simple_t *simple,
                 vka_t *vka,
                 vspace_t *parent_vspace,
                 const void *elf_bytes,
                 unsigned long elf_size,
                 const char *const argv[])
{
    lucas_state_t st;
    memset(&st, 0, sizeof(st));
    st.simple        = simple;
    st.vka           = vka;
    st.parent_vspace = parent_vspace;

    int slot = sotbox_alloc_slot(&st);
    if (slot < 0) {
        printf("[lucas] sotbox_alloc_slot failed · table full\n");
        return -1;
    }
    st.slot_index = slot;
    printf("[lucas] sotbox slot=%d allocated\n", slot);

    printf("[lucas] L1 starting · elf=%p size=%lu · environment borrowed from root\n",
           elf_bytes, elf_size);

    if (!lucas_elf_validate(elf_bytes, elf_size)) {
        printf("[lucas] ELF validation failed · aborting client\n");
        return -1;
    }
    if (create_client_vspace(&st) != 0) {
        printf("[lucas] client vspace setup failed · halting\n");
        return -1;
    }

    /* vDSO arc · Task 4 · map [vvar][vdso] at SOTOS_VDSO_BASE into the fresh
     * guest vspace.  Non-fatal: a miss only means guest libc uses the
     * clock_gettime syscall fallback instead of the vDSO fast-path. */
    if (lucas_map_vdso(&st) != 0)
        printf("[lucas] vDSO map failed · guest libc uses syscall fallback\n");

    if (lucas_elf_load_program(&st, elf_bytes, elf_size) != 0) {
        printf("[lucas] program load failed · halting\n");
        return -1;
    }
    printf("[lucas] all segments mapped · entry=0x%lx\n",
           (unsigned long)st.entry_point);

    static const char *envp[] = { "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "TERM=xterm", NULL };
    if (lucas_stack_setup(&st, argv, envp) != 0) {
        printf("[lucas] stack setup failed · halting\n");
        return -1;
    }

    if (lucas_client_setup(&st) != 0) {
        printf("[lucas] client TCB setup failed · halting\n");
        return -1;
    }

    /* Install default VFS mounts (T2-T4 backends). */
    vfs_install_defaults(&st);

    /* Pre-install stdin/stdout/stderr in the fd table.  Their is_std
     * flag short-circuits the read/write handlers to the stdio path
     * (write goes straight to seL4_DebugPutChar). */
    for (int i = 0; i < 3; ++i) {
        st.fds[i].kind   = LUCAS_FD_STDIO;
        st.fds[i].is_std = true;
        st.fds[i].mount  = NULL;
        st.fds[i].handle = NULL;
        st.fds[i].cursor = 0;
        st.fds[i].flags  = 0;
        st.fds[i].pipe   = NULL;
    }

    if (lucas_client_resume(&st) != 0) {
        printf("[lucas] client resume failed · halting\n");
        return -1;
    }

    lucas_fault_loop(&st);
    printf("[lucas] L1 demo complete · final state code=%d\n", st.exit_code);
    sotbox_free_slot(st.slot_index);
    printf("[lucas] sotbox slot=%d freed\n", st.slot_index);
    return st.exit_code;
}
