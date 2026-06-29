/*
 * sotOs · LUCAS L1 · initial stack setup.
 *
 * Builds the Linux x86_64 process-entry stack frame:
 *
 *   [ argc          ]  <- RSP (lowest addr after setup)
 *   [ argv[0]       ]
 *   [ argv[argc-1]  ]
 *   [ NULL          ]  <- argv terminator
 *   [ envp[0]       ]
 *   [ envp[envc-1]  ]
 *   [ NULL          ]  <- envp terminator
 *   [ AT_RANDOM     ]
 *   [ random_vaddr  ]
 *   [ AT_NULL       ]
 *   [ 0             ]  <- auxv terminator
 *   [ strings...    ]  <- high end (written first)
 *   [ random_bytes  ]  <- 16 bytes for AT_RANDOM
 *
 * API note: sel4utils_stack_write(parent_vspace, target_vspace, vka,
 *                                  buf, len, &sp)
 * decrements sp by len, then copies buf into the client vspace at the new sp.
 * So items written last end up at the lowest address (RSP).
 *
 * Uses vspace_new_sized_stack to allocate the stack in the client vspace.
 */

#include "stack_setup.h"
#include "state.h"
#include "elf_loader.h"   /* lucas_elf64_phdr_t · for AT_PHENT default */

#include <sel4utils/helpers.h>
#include <vspace/vspace.h>
#include <sotos/random.h>
#include <string.h>
#include <stdio.h>

#define LX_AT_NULL     0
#define LX_AT_PHDR     3
#define LX_AT_PHENT    4
#define LX_AT_PHNUM    5
#define LX_AT_PAGESZ   6
#define LX_AT_BASE     7
#define LX_AT_ENTRY    9
#define LX_AT_PLATFORM 15
#define LX_AT_CLKTCK   17
#define LX_AT_RANDOM   25
#define LX_AT_SYSINFO_EHDR 33   /* vDSO arc · Task 4 · vDSO ELF header vaddr */

/* Number of 4K pages for the client initial stack (must be >= 1).
 * L1 used 1 page (4 KiB) which sufficed for hello.S.
 * L2 bumped to 16 pages (64 KiB) for musl __init_libc / __init_tls.
 * L9-STACK bumps to 256 pages (1 MiB) because Python's init exceeded
 * 64 KiB by ~1.1 KiB · observed VMFault at addr=0x10000a18 with
 * stack base=0x10000ec0 (rsp=0x10000a20).  Memory cost: +960 KiB
 * per sotBox; QEMU -m 2048 absorbs this comfortably.  Future work:
 * lazy stack growth via VMFault handler (Linux semantics) would
 * eliminate the static reservation. */
#define STACK_PAGES   256    /* 1 MiB · sufficient for Python init */

int lucas_stack_setup(struct lucas_state *st,
                       const char *const argv[],
                       const char *const envp[])
{
    uintptr_t sp;

    if (st->stack_region_top != 0) {
        /* In-place path (post-fork execve): reuse the existing stack region.
         * stack_region_top is the return value of vspace_new_sized_stack from
         * the previous setup — the highest usable vaddr in the stack region.
         * We just start writing from there (overwriting old content). */
        sp = st->stack_region_top;
        printf("[lucas] stack: in-place reuse · starting sp=0x%lx\n",
               (unsigned long)sp);
    } else {
        /* Fresh vspace: allocate a new stack. */
        void *stack_top_vaddr = vspace_new_sized_stack(&st->client_vspace_abs, STACK_PAGES);
        if (!stack_top_vaddr) {
            printf("[lucas] stack: vspace_new_sized_stack failed\n");
            return -1;
        }
        sp = (uintptr_t)stack_top_vaddr;
        /* Save the region top for potential in-place reuse later. */
        st->stack_region_top = sp;
    }

    /* sp tracks the current stack pointer in client vspace. Start at top. */

    /* Count argv/envp lengths. */
    int argc = 0;
    while (argv[argc]) ++argc;
    int envc = 0;
    while (envp[envc]) ++envc;

    /* Wine M1 · capture an ABSOLUTE argv[0] as the program's exe path (for
     * /proc/self/exe).  Only absolute paths (a real exec carries one) — a bare
     * "sh"/"busybox" argv[0] leaves exe_path empty so the /proc/self/exe
     * deception default (/bin/busybox) stands for the attacker shell. */
    if (argc > 0 && argv[0] && argv[0][0] == '/') {
        size_t i = 0;
        for (; argv[0][i] && i < sizeof(st->exe_path) - 1; ++i)
            st->exe_path[i] = argv[0][i];
        st->exe_path[i] = '\0';
    }

    /* ------------------------------------------------------------------ *
     * Step 1: write AT_RANDOM 16-byte block (strings area, high on stack) *
     * obsd-β: filled with CSPRNG output instead of hardcoded magic bytes. *
     * ------------------------------------------------------------------ */
    uint8_t random_bytes[16];
    sotos_arc4random_buf(random_bytes, sizeof(random_bytes));
    int err = sel4utils_stack_write(st->parent_vspace,
                                    &st->client_vspace_abs,
                                    st->vka,
                                    (void *)random_bytes,
                                    sizeof(random_bytes),
                                    &sp);
    if (err) {
        printf("[lucas] stack: write AT_RANDOM bytes failed (%d)\n", err);
        return err;
    }
    uintptr_t random_vaddr = sp;  /* client vaddr where 16 bytes now live */

    /* ------------------------------------------------------------------ *
     * Step 1b: write AT_PLATFORM string ("x86_64\0", 7 bytes)            *
     * AT_PLATFORM is consulted by glibc/musl for CPU dispatch decisions. *
     * ------------------------------------------------------------------ */
    static const char platform_str[] = "x86_64";
    err = sel4utils_stack_write(st->parent_vspace,
                                &st->client_vspace_abs,
                                st->vka,
                                (void *)platform_str,
                                sizeof(platform_str),
                                &sp);
    if (err) {
        printf("[lucas] stack: write AT_PLATFORM string failed (%d)\n", err);
        return err;
    }
    uintptr_t platform_vaddr = sp;

    /* ------------------------------------------------------------------ *
     * Step 2: write string data for envp[envc-1..0], argv[argc-1..0]     *
     * (strings are written top-to-bottom; order doesn't matter for data  *
     *  as long as we record the correct pointers)                         *
     * ------------------------------------------------------------------ */

    /* We need separate arrays for argv and envp client-side pointers. */
    uintptr_t argv_ptrs[32];
    uintptr_t envp_ptrs[32];

    if (argc > 32 || envc > 32) {
        printf("[lucas] stack: argc/envc exceed internal limit (32)\n");
        return -1;
    }

    /* Write envp strings (we write last-to-first so we record pointers in order). */
    for (int i = envc - 1; i >= 0; --i) {
        size_t l = strlen(envp[i]) + 1;
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, (void *)envp[i], l, &sp);
        if (err) {
            printf("[lucas] stack: write envp[%d] failed (%d)\n", i, err);
            return err;
        }
        envp_ptrs[i] = sp;
    }

    /* Write argv strings. */
    for (int i = argc - 1; i >= 0; --i) {
        size_t l = strlen(argv[i]) + 1;
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, (void *)argv[i], l, &sp);
        if (err) {
            printf("[lucas] stack: write argv[%d] failed (%d)\n", i, err);
            return err;
        }
        argv_ptrs[i] = sp;
    }

    /* ------------------------------------------------------------------ *
     * Step 3: align sp down to 8 bytes before writing pointer-sized data  *
     * ------------------------------------------------------------------ */
    sp = sp & ~(uintptr_t)7;

    /* ------------------------------------------------------------------ *
     * Step 4: compute alignment padding so final RSP (after writing argc) *
     * is 16-byte aligned per the SysV ABI.                               *
     *                                                                     *
     * Items we will write below (from high to low, i.e. last to first):  *
     *   argc          (8 bytes)                                           *
     *   argv[0..argc-1] (argc * 8 bytes)                                 *
     *   NULL          (8 bytes)                                           *
     *   envp[0..envc-1] (envc * 8 bytes)                                 *
     *   NULL          (8 bytes)                                           *
     *   AT_RANDOM     (8 bytes)                                           *
     *   random_vaddr  (8 bytes)                                           *
     *   AT_PLATFORM   (8 bytes)                                           *
     *   platform_vaddr(8 bytes)                                           *
     *   AT_CLKTCK     (8 bytes)                                           *
     *   100           (8 bytes)  <- USER_HZ                               *
     *   AT_PAGESZ     (8 bytes)                                           *
     *   4096          (8 bytes)                                           *
     *   AT_ENTRY      (8 bytes)  <- MS-M3 prep                            *
     *   entry_point   (8 bytes)                                           *
     *   AT_BASE       (8 bytes)  <- MS-M3 prep · 0 for static             *
     *   0             (8 bytes)                                           *
     *   AT_PHDR       (8 bytes)  <- MS-M3 prep                            *
     *   phdr_vaddr    (8 bytes)                                           *
     *   AT_NULL       (8 bytes)                                           *
     *   0             (8 bytes)  <- auxv terminator value                 *
     *                                                                     *
     *   AT_PHNUM      (8 bytes)  <- D1                                   *
     *   phnum         (8 bytes)                                           *
     *   AT_PHENT      (8 bytes)  <- D1                                   *
     *   phent         (8 bytes)                                           *
     *                                                                     *
     * Total qwords: 1 + argc + 1 + envc + 1 + 10*2 = argc+envc+23        *
     * Total bytes:  (argc+envc+23) * 8                                   *
     *                                                                     *
     * We need final RSP to be 16-byte aligned.                            *
     * ------------------------------------------------------------------ */
    size_t total_qwords = (size_t)(argc + envc) + 25;  /* +4 AT_PHNUM/AT_PHENT, +2 AT_SYSINFO_EHDR */
    size_t total_bytes  = total_qwords * 8;
    uintptr_t final_sp  = sp - total_bytes;
    if (final_sp & 0xf) {
        /* Pad by 8 to fix alignment. */
        uint64_t pad = 0;
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, &pad, 8, &sp);
        if (err) {
            printf("[lucas] stack: alignment pad write failed (%d)\n", err);
            return err;
        }
    }

    /* ------------------------------------------------------------------ *
     * Step 5: write structure items in REVERSE order (last item first    *
     * because sel4utils_stack_write decrements sp before writing).       *
     *                                                                     *
     * Write order (each write goes BELOW what was written before):       *
     *   1. auxv AT_NULL value (0)                                         *
     *   2. auxv AT_NULL type  (0)                                         *
     *   3. auxv AT_RANDOM value (random_vaddr)                            *
     *   4. auxv AT_RANDOM type  (25)                                      *
     *   5. NULL (envp terminator)                                         *
     *   6. envp[envc-1..0] pointers (last to first)                      *
     *   7. NULL (argv terminator)                                         *
     *   8. argv[argc-1..0] pointers (last to first)                      *
     *   9. argc                                                            *
     * ------------------------------------------------------------------ */
    uint64_t val;

    /* auxv AT_NULL terminator pair (written first = lives highest). */
    val = 0;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_NULL;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* vDSO arc · Task 4 · auxv AT_SYSINFO_EHDR pair · the vDSO ELF header
     * vaddr (SOTOS_VDSO_BASE + 0x1000).  lucas_map_vdso maps the [vvar][vdso]
     * pair there at spawn; musl/glibc parse this ELF to resolve __vdso_*.
     * Order within the auxv is irrelevant (libc scans by type), so it rides
     * just under the AT_NULL terminator.
     * Guard: only emit AT_SYSINFO_EHDR when lucas_map_vdso succeeded (st->vdso_base
     * non-zero); if the mapping failed, the pages are unmapped and the guest
     * dereferencing the address would fault. */
    if (st->vdso_base != 0) {
        val = (uint64_t)st->vdso_base;
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, &val, 8, &sp);
        if (err) return err;
        val = LX_AT_SYSINFO_EHDR;
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, &val, 8, &sp);
        if (err) return err;
    }

    /* MS-M3 prep · auxv AT_PHDR / AT_BASE / AT_ENTRY.  For static
     * binaries these are informational (ld-musl uses AT_BASE=0 as
     * "statically linked, no interpreter").  Future dynamic loader
     * support will populate real phdr/base/entry from the parsed ELF. */
    /* D1 · dynamic binaries carry real phdr/base/entry from the loaded PIE +
     * interpreter; static binaries keep the informational defaults
     * (AT_BASE=0 = "no interpreter"). */
    /* bin_phdr_vaddr/phnum/phent are now set for BOTH dynamic (lucas_l1.c) and
     * static (elf_segments.c lucas_elf_load_into_client) loads.  Fall back to the
     * historical static defaults if a load path left them zero, so this can only
     * ADD a correct AT_PHNUM (glibc needs it), never regress musl. */
    const uint64_t phdr_vaddr  = st->bin_phdr_vaddr ? (uint64_t)st->bin_phdr_vaddr
                                                    : 0x400000ULL + 0x40ULL;
    const uint64_t base_vaddr  = st->is_dynamic ? (uint64_t)st->interp_base : 0;
    const uint64_t entry_vaddr = st->is_dynamic
                                 ? (uint64_t)st->bin_entry_vaddr
                                 : (uint64_t)st->entry_point;
    const uint64_t phnum_val   = (uint64_t)st->bin_phnum;
    const uint64_t phent_val   = st->bin_phent ? (uint64_t)st->bin_phent
                                               : sizeof(lucas_elf64_phdr_t);

    /* auxv AT_ENTRY pair. */
    val = entry_vaddr;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_ENTRY;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_BASE pair · 0 for static binaries. */
    val = base_vaddr;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_BASE;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_PHDR pair · client vaddr of the program header array. */
    val = phdr_vaddr;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_PHDR;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_PHNUM pair (number of program headers). */
    val = phnum_val;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_PHNUM;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_PHENT pair (size of one program header). */
    val = phent_val;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_PHENT;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    printf("[lucas] auxv: AT_BASE=0x%lx AT_PHDR=0x%lx AT_ENTRY=0x%lx phnum=%lu\n",
           (unsigned long)base_vaddr, (unsigned long)phdr_vaddr,
           (unsigned long)entry_vaddr, (unsigned long)phnum_val);

    /* auxv AT_PAGESZ pair · MUST be 4096 for Linux x86_64. */
    val = 4096;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_PAGESZ;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_CLKTCK pair · MUST be 100 (Linux USER_HZ); divergent
     * values are sandbox-detection markers per the spec's section 7.5. */
    val = 100;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_CLKTCK;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_PLATFORM pair · points to "x86_64\0" string on the stack. */
    val = (uint64_t)platform_vaddr;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_PLATFORM;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* auxv AT_RANDOM pair. */
    val = (uint64_t)random_vaddr;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;
    val = LX_AT_RANDOM;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* NULL envp terminator. */
    val = 0;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* envp pointers (last to first so envp[0] ends up at lowest addr). */
    for (int i = envc - 1; i >= 0; --i) {
        val = (uint64_t)envp_ptrs[i];
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, &val, 8, &sp);
        if (err) return err;
    }

    /* NULL argv terminator. */
    val = 0;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* argv pointers (last to first so argv[0] ends up at lowest addr). */
    for (int i = argc - 1; i >= 0; --i) {
        val = (uint64_t)argv_ptrs[i];
        err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                    st->vka, &val, 8, &sp);
        if (err) return err;
    }

    /* argc (written last = lives at the lowest address = RSP). */
    val = (uint64_t)argc;
    err = sel4utils_stack_write(st->parent_vspace, &st->client_vspace_abs,
                                st->vka, &val, 8, &sp);
    if (err) return err;

    /* Final RSP must be 16-byte aligned per SysV x86_64 ABI. */
    if (sp & 0xf) {
        printf("[lucas] stack: WARNING: RSP 0x%lx is not 16-byte aligned!\n",
               (unsigned long)sp);
    }

    st->stack_top = sp;
    printf("[lucas] stack ready · top=0x%lx (argc=%d, envc=%d)\n",
           (unsigned long)st->stack_top, argc, envc);
    return 0;
}
