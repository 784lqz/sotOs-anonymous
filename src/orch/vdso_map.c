/*
 * sotOs · vDSO arc · Task 4 · map [vvar][vdso] into a guest vspace.
 *
 * The vdso.so blob (a freestanding PIC shared object built by src/vdso/) is
 * embedded into the orchestrator image via vdso_blob.o (.incbin, mirroring
 * the children_archive CPIO embed).  At guest spawn the orchestrator maps:
 *
 *   SOTOS_VDSO_BASE          .. +0x1000   [vvar]  (sotos_vvar clock page)
 *   SOTOS_VDSO_BASE + 0x1000 .. +N*0x1000 [vdso]  (the vdso.so ELF image)
 *
 * contiguously, with the vvar page fixed one page BELOW the vDSO ELF header so
 * the in-guest vDSO code (Task F2) finds its data at ehdr-0x1000.  The ELF
 * header (what AT_SYSINFO_EHDR points at · stack_setup.c) is at
 * SOTOS_VDSO_EHDR == SOTOS_VDSO_BASE + 0x1000.
 *
 * lucas_map_vdso is resolved at orch link time from lucas_l1.c / spawn.c /
 * fork.c / execve.c (the lucas library is always statically linked into orch),
 * exactly like sotbox_alloc_slot.
 *
 * The page-by-page reserve → new_pages_at_vaddr → dup_and_map → memcpy →
 * unmap_dup mechanism mirrors lucas_elf_load_at_base (elf_segments.c) — the
 * canonical way to place frames with content at a fixed guest vaddr.
 */

#include "state.h"
#include "vdso/sotos_vvar.h"

#include <sel4/sel4.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <vspace/vspace.h>
#include <string.h>
#include <stdio.h>

/* Embedded vdso.so blob (vdso_blob.o · generated .incbin in orch's CMake). */
extern char _sotos_vdso_blob_start[];
extern char _sotos_vdso_blob_end[];

int lucas_map_vdso(lucas_state_t *st)
{
    /* I2 · non-fatal remap: clear the recorded span FIRST so any early
     * `return -1` below leaves these zero.  stack_setup.c only emits the
     * AT_SYSINFO_EHDR auxv pair when st->vdso_base != 0, so a failed map (this
     * st is reused by execve, and copied by fork) suppresses the auxv instead
     * of pointing the guest at an unmapped page → fault.  Previously these kept
     * stale non-zero values from a prior spawn and the guard wrongly passed.
     *
     * Fork caveat: a fork CHILD inherits the parent's already-built stack (which
     * already carries AT_SYSINFO_EHDR) and libc's cached __vdso_* pointers, so
     * if a child's remap here fails it cannot fully fall back to trapping
     * syscalls — the inherited auxv/cached pointer still names the (now absent)
     * vDSO.  In practice the child remaps into the SAME fixed window the parent
     * used, so success is the norm; this is documented, not over-engineered. */
    st->vvar_base       = 0;
    st->vdso_base       = 0;
    st->vdso_code_pages = 0;

    const size_t blob_size  = (size_t)(_sotos_vdso_blob_end - _sotos_vdso_blob_start);
    const size_t code_pages = (blob_size + 0xFFFUL) / 0x1000UL;
    if (code_pages == 0) {
        printf("[vdso] embedded blob is empty · vDSO map skipped\n");
        return -1;
    }

    const uintptr_t vvar_va  = SOTOS_VDSO_BASE;             /* [vvar] page      */
    const uintptr_t vdso_va  = SOTOS_VDSO_EHDR;             /* [vdso] ELF header */
    const size_t    res_size = (1 /* vvar */ + code_pages) * 0x1000UL;

    /* I1 · W^X · the GUEST view of [vvar][vdso] is mapped READ-ONLY (no
     * CanWrite).  Was seL4_AllRights, which let a guest write to vvar/vdso and
     * succeed — a deception tell (real Linux SEGVs; both regions are read-only
     * there: vvar r--p, vdso r-xp) and a W^X violation on the code page.
     *
     * seL4_CanRead = capAllowRead only → the kernel masks the frame to
     * VMReadOnly (maskVMRights, src/arch/x86/kernel/vspace.c) so the PTE's
     * read_write bit is 0.  Execution of the code page is preserved because on
     * x86_64 seL4 the PTE execute-disable bit is HARDCODED to 0
     * (makeUserPTE, src/arch/x86/64/kernel/vspace.c — `xd = 0`); execute is NOT
     * gated by the rights cap, so CanRead pages remain executable.  This is why
     * we do NOT (and cannot) set seL4_X86_ExecuteNever: that VMAttribute does
     * not exist on x86_64 (it is ARM/RISC-V only), and x86_64 seL4 cannot map a
     * page NX at all.  So vvar is read-only but, like every x86_64 seL4 user
     * page, technically executable; the only achievable W^X property here is the
     * write removal, which is the security-relevant one (the write-succeeds
     * tell).  /proc/self/maps still presents vvar r--p / vdso r-xp.
     *
     * The orch fills content through a SEPARATE RW alias (sel4utils_dup_and_map
     * below) which vka_cnode_copy's the frame with seL4_AllRights and maps the
     * copy RW into the orch's own vspace — wholly independent of this read-only
     * client reservation, so the fill is unaffected. */
    reservation_t res = vspace_reserve_range_at(
        &st->client_vspace_abs, (void *)vvar_va, res_size,
        seL4_CanRead, 1 /* cacheable */);
    if (res.res == NULL) {
        printf("[vdso] reserve_range_at(0x%lx,%zu) failed\n",
               (unsigned long)vvar_va, res_size);
        return -1;
    }

    /* Page 0 · vvar (shared sotos_vvar clock params). */
    {
        int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                            (void *)vvar_va, 1, seL4_PageBits, res);
        if (err) {
            printf("[vdso] vvar new_pages_at_vaddr(0x%lx) err=%d\n",
                   (unsigned long)vvar_va, err);
            return -1;
        }
        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)vvar_va);
        if (!frame) { printf("[vdso] vvar: no frame at 0x%lx\n", (unsigned long)vvar_va); return -1; }
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                            frame, seL4_PageBits);
        if (!local) { printf("[vdso] vvar dup_and_map failed\n"); return -1; }
        memset(local, 0, 0x1000);
        lucas_vvar_fill((struct sotos_vvar *)local);
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
    }

    /* Pages 1..code_pages · the vdso.so ELF image, copied from the blob. */
    for (size_t i = 0; i < code_pages; ++i) {
        uintptr_t pv = vdso_va + (uintptr_t)i * 0x1000UL;
        int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                            (void *)pv, 1, seL4_PageBits, res);
        if (err) {
            printf("[vdso] code new_pages_at_vaddr(0x%lx) err=%d\n",
                   (unsigned long)pv, err);
            return -1;
        }
        seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
        if (!frame) { printf("[vdso] code: no frame at 0x%lx\n", (unsigned long)pv); return -1; }
        void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                            frame, seL4_PageBits);
        if (!local) { printf("[vdso] code dup_and_map(0x%lx) failed\n", (unsigned long)pv); return -1; }

        size_t off = i * 0x1000UL;
        size_t n   = (blob_size - off < 0x1000UL) ? (blob_size - off) : 0x1000UL;
        memset(local, 0, 0x1000);                       /* zero the tail page slack */
        memcpy(local, _sotos_vdso_blob_start + off, n);
        sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
    }

    st->vvar_base       = vvar_va;
    st->vdso_base       = vdso_va;
    st->vdso_code_pages = (uint32_t)code_pages;
    printf("[vdso] mapped · vvar=0x%lx vdso=0x%lx code_pages=%zu (blob=%zuB)\n",
           (unsigned long)vvar_va, (unsigned long)vdso_va, code_pages, blob_size);
    return 0;
}
