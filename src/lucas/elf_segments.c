/*
 * sotOs · LUCAS L1 · ELF segment mapping into client vspace.
 *
 * Uses sel4utils_elf_load (seL4_libs libsel4utils) which handles page
 * reservation, frame allocation, and data copy via the loader vspace.
 *
 * API divergence from plan: plan referenced sel4utils_copy_data_to_vspace
 * and vspace_new_pages_at_vaddr(vspace, vaddr, n, bits, rights) – neither
 * exists with those signatures.  Replaced with sel4utils_elf_load which is
 * the canonical high-level loader and already handles BSS zeroing.
 */

#include "elf_loader.h"
#include "state.h"

#include <sel4utils/elf.h>
#include <sel4utils/vspace.h>
#include <sel4utils/mapping.h>
#include <vspace/vspace.h>
#include <elf/elf.h>
#include <stdio.h>
#include <string.h>

int lucas_elf_load_into_client(struct lucas_state *st, const void *elf_bytes,
                                size_t elf_size)
{
    elf_t elf;
    int err = elf_newFile(elf_bytes, elf_size, &elf);
    if (err) {
        printf("[lucas]   elf_newFile failed (err=%d)\n", err);
        return err;
    }

    int num_regions = sel4utils_elf_num_regions(&elf);
    printf("[lucas]   sel4utils_elf_load: %d PT_LOAD region(s)\n", num_regions);

    void *entry = sel4utils_elf_load(&st->client_vspace_abs,
                                      st->parent_vspace,
                                      st->vka,
                                      st->vka,
                                      &elf);
    if (entry == NULL) {
        printf("[lucas]   sel4utils_elf_load failed\n");
        return -1;
    }

    printf("[lucas]   sel4utils_elf_load ok · entry=%p\n", entry);

    /* glibc-compat · record the program-header triple so stack_setup emits a
     * correct AT_PHNUM for STATIC binaries too.  musl-static tolerated AT_PHNUM=0
     * (it locates PT_TLS via __ehdr_start), but glibc-static walks AT_PHDR with
     * AT_PHNUM to find PT_TLS in __libc_setup_tls — with phnum=0 it never sets up
     * the TLS slotinfo list and _dl_allocate_tls_init NULL-derefs.  Non-PIE static
     * ELFs link at 0x400000 (p_offset 0 → p_vaddr 0x400000), so the phdrs sit at
     * 0x400000 + e_phoff. */
    st->bin_phnum      = lucas_elf_phnum(elf_bytes);
    st->bin_phent      = lucas_elf_phentsize(elf_bytes);
    st->bin_phdr_vaddr = (uintptr_t)(0x400000UL + lucas_elf_phoff(elf_bytes));
    return 0;
}

/* DOOM-DBG · re-read every file-backed PT_LOAD page from the client vspace and
 * compare to the ELF file bytes.  Ground-truth showed a large static binary
 * (chocodoom) loads correctly (this returns 0 right after the load) yet has a
 * text page clobbered with foreign frame content by the time it runs — a frame
 * gets reused/aliased in the load→resume window.  Called at two points
 * (post-stack-setup verify, pre-resume verify+repair) to pin the window and
 * heal the text so the box executes the real code.  repair!=0 re-copies the
 * correct bytes on mismatch.  Returns the mismatched-page count. */
int lucas_verify_text_pages(struct lucas_state *st, const void *elf_bytes,
                            int repair, const char *tag)
{
    extern int lucas_copy_from_client(lucas_state_t *, uintptr_t, void *, size_t);
    extern int lucas_copy_to_client(lucas_state_t *, uintptr_t, const void *, size_t);
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);
    size_t total_mismatch = 0, repaired = 0;
    static uint8_t pg[4096];
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_LOAD) continue;
        uint64_t vaddr = ph[i].p_vaddr, filesz = ph[i].p_filesz;
        const uint8_t *src = (const uint8_t *)elf_bytes + ph[i].p_offset;
        for (uint64_t off = 0; off < filesz; off += 4096) {
            size_t n = (filesz - off < 4096) ? (size_t)(filesz - off) : 4096;
            /* ROUND 11 · for the known-corrupt text page, print the ELF SOURCE
             * (loader input) vs a RELIABLE frame read → load-contamination (a)
             * vs vspace-divergence (b). */
            if ((vaddr + off) == 0x54b000UL) {
                extern int lucas_reliable_read(lucas_state_t *, uintptr_t, void *, size_t);
                uint8_t rel[8] = {0}; int rr = lucas_reliable_read(st, 0x54b000UL, rel, 8);
                printf("[doom-r11] %s 0x54b000 ELF-src: %02x %02x %02x %02x %02x %02x %02x %02x | reliable-frame(rc=%d): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                       tag, src[off],src[off+1],src[off+2],src[off+3],src[off+4],src[off+5],src[off+6],src[off+7],
                       rr, rel[0],rel[1],rel[2],rel[3],rel[4],rel[5],rel[6],rel[7]);
            }
            if (lucas_copy_from_client(st, (uintptr_t)(vaddr + off), pg, n) != 0)
                continue;
            if (memcmp(pg, src + off, n) != 0) {
                if (total_mismatch < 8)
                    printf("[doom-dbg] %s MISMATCH vaddr=0x%lx (file[0]=%02x mem[0]=%02x)\n",
                           tag, (unsigned long)(vaddr + off), src[off], pg[0]);
                ++total_mismatch;
                if (repair && lucas_copy_to_client(st, (uintptr_t)(vaddr + off),
                                                   src + off, n) == 0)
                    ++repaired;
            }
            /* DOOM-DBG BISECT · after processing each page, re-read 0x54b000 to
             * pin the exact iteration it "flips" to mtio.h.  On the first hit,
             * MULTI-SAMPLE: read 0x54b000 three times + 0x400000 (control, known
             * "7f 45 4c 46") to tell a stale dup_and_map window (reads disagree)
             * from real frame corruption (reads agree + control still correct). */
            if ((vaddr + off) != 0x54b000UL) {
                static int bis_done = 0;
                uint8_t v8[8];
                if (!bis_done &&
                    lucas_copy_from_client(st, 0x54b000UL, v8, 8) == 0 &&
                    memcmp(v8, "#ifndef ", 8) == 0) {
                    bis_done = 1;
                    uint8_t a[8], b[8], c[8], hdr[8];
                    int ra = lucas_copy_from_client(st, 0x54b000UL, a, 8);
                    int rb = lucas_copy_from_client(st, 0x54b000UL, b, 8);
                    int rc = lucas_copy_from_client(st, 0x54b000UL, c, 8);
                    int rh = lucas_copy_from_client(st, 0x400000UL, hdr, 8);
                    printf("[doom-dbg] BISECT-TRIP after page 0x%lx (%s)\n",
                           (unsigned long)(vaddr + off), tag);
                    printf("[doom-dbg]   0x54b000 #1(%d): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                           ra, a[0],a[1],a[2],a[3],a[4],a[5],a[6],a[7]);
                    printf("[doom-dbg]   0x54b000 #2(%d): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                           rb, b[0],b[1],b[2],b[3],b[4],b[5],b[6],b[7]);
                    printf("[doom-dbg]   0x54b000 #3(%d): %02x %02x %02x %02x %02x %02x %02x %02x\n",
                           rc, c[0],c[1],c[2],c[3],c[4],c[5],c[6],c[7]);
                    printf("[doom-dbg]   0x400000 ctl(%d): %02x %02x %02x %02x (expect 7f 45 4c 46)\n",
                           rh, hdr[0],hdr[1],hdr[2],hdr[3]);
                    seL4_CPtr cb = vspace_get_cap(&st->client_vspace_abs, (void *)0x54b000UL);
                    uint64_t pab = 0;
                    if (cb) { seL4_X86_Page_GetAddress_t r = seL4_X86_Page_GetAddress(cb);
                              if (!r.error) pab = (uint64_t)r.paddr; }
                    printf("[doom-dbg]   iter0 0x54b000 → cap=%lu paddr=0x%lx (end-of-verify prints 376/0x3158000)\n",
                           (unsigned long)cb, (unsigned long)pab);
                }
            }
        }
    }
    /* Log the physical frame backing 0x54b000 at this checkpoint, so the
     * fault-time paddr can be compared: same paddr + correct content here =>
     * the frame is overwritten externally later; different paddr => the
     * client vspace remapped that vaddr to another frame. */
    {
        seL4_CPtr c = vspace_get_cap(&st->client_vspace_abs, (void *)0x54b000UL);
        uint64_t pa = 0;
        if (c) { seL4_X86_Page_GetAddress_t r = seL4_X86_Page_GetAddress(c);
                 if (!r.error) pa = (uint64_t)r.paddr; }
        printf("[doom-dbg] %s paddr(0x54b000)=0x%lx cap=%lu\n",
               tag, (unsigned long)pa, (unsigned long)c);
        /* Rounds 10/11 instrumentation DISABLED — corruption root cause
         * (binstore/sysroot overlap) is fixed. The per-syscall doom probe
         * (armed by lucas_doom_watch_set) was a big perf hit on Chocolate.
         * Re-arm only to re-investigate. */
        (void)pa;
    }
    printf("[doom-dbg] %s verify · mismatched=%zu repaired=%zu\n",
           tag, total_mismatch, repaired);
    return (int)total_mismatch;
}

/*
 * lucas_elf_reload_data — L3b-T6 in-place execve optimisation.
 *
 * Re-copies the DATA PT_LOAD segment from elf_bytes into the EXISTING frames
 * already mapped in st->client_vspace_abs.  The TEXT segment is skipped (it
 * is identical and already correct in the cloned vspace).  This avoids
 * creating a new vspace + allocating new frame objects for the TEXT region.
 *
 * Only the DATA segment (PF_W set in p_flags) is overwritten.  BSS (p_filesz
 * < p_memsz) is zeroed.
 *
 * Returns 0 on success, -1 on failure (caller falls back to full reload).
 */
int lucas_elf_reload_data(lucas_state_t *st,
                           const void *elf_bytes, size_t elf_size)
{
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);

    int reloaded = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_LOAD) continue;

        /* Skip TEXT (read-only, no PF_W) — it's the same in all copies. */
        if (!(ph[i].p_flags & 0x2 /* PF_W */)) continue;

        uintptr_t seg_vaddr = (uintptr_t)ph[i].p_vaddr;
        uint64_t  filesz    = ph[i].p_filesz;
        uint64_t  memsz     = ph[i].p_memsz;
        const uint8_t *src  = (const uint8_t *)elf_bytes + ph[i].p_offset;

        printf("[execve] reload DATA seg vaddr=0x%lx filesz=%lu memsz=%lu\n",
               (unsigned long)seg_vaddr, (unsigned long)filesz, (unsigned long)memsz);

        /* Walk page by page through the segment. */
        uintptr_t page_base = seg_vaddr & ~0xFFFUL;
        uintptr_t seg_end   = (seg_vaddr + memsz + 0xFFFUL) & ~0xFFFUL;

        for (uintptr_t pv = page_base; pv < seg_end; pv += 4096) {
            seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
            if (!frame) {
                printf("[execve] reload_data: no frame at 0x%lx\n",
                       (unsigned long)pv);
                return -1;
            }

            void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                                 frame, seL4_PageBits);
            if (!local) {
                printf("[execve] reload_data: dup_and_map failed at 0x%lx\n",
                       (unsigned long)pv);
                return -1;
            }

            /* Compute overlap of this page with [seg_vaddr, seg_vaddr+filesz). */
            uintptr_t page_start = pv;
            uintptr_t page_end   = pv + 4096;

            /* File data portion. */
            if (page_start < seg_vaddr + filesz && page_end > seg_vaddr) {
                uintptr_t copy_start = (page_start < seg_vaddr) ? seg_vaddr : page_start;
                uintptr_t copy_end   = (page_end > seg_vaddr + filesz)
                                       ? seg_vaddr + filesz : page_end;
                size_t    off_in_page = copy_start - pv;
                size_t    off_in_file = copy_start - seg_vaddr;
                size_t    len         = copy_end - copy_start;
                memcpy((uint8_t *)local + off_in_page, src + off_in_file, len);
            }

            /* BSS portion (zero). */
            if (page_start < seg_vaddr + memsz && page_end > seg_vaddr + filesz) {
                uintptr_t bss_start = (page_start < seg_vaddr + filesz)
                                      ? seg_vaddr + filesz : page_start;
                uintptr_t bss_end   = (page_end > seg_vaddr + memsz)
                                      ? seg_vaddr + memsz : page_end;
                size_t    off_in_page = bss_start - pv;
                size_t    len         = bss_end - bss_start;
                if (len > 0)
                    memset((uint8_t *)local + off_in_page, 0, len);
            }

            sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
        }
        ++reloaded;
    }

    if (reloaded == 0) {
        printf("[execve] reload_data: no DATA segments found\n");
        return -1;
    }
    printf("[execve] reload_data: %d DATA segment(s) refreshed\n", reloaded);
    return 0;
}

/*
 * N3/D1 · lucas_elf_load_at_base — map every PT_LOAD of elf_bytes at
 * (base + p_vaddr) into st->client_vspace_abs.
 *
 * sel4utils_elf_load maps 1-to-1 at the file vaddrs and asserts entry<4GB, so
 * it cannot place a PIE at a chosen base.  This loader reserves each segment's
 * page range at base+vaddr, allocates frames there, then copies file bytes via
 * a temporary loader-side mapping (sel4utils_dup_and_map).  seL4 hands out
 * zero'd frames, so BSS (memsz>filesz) needs no explicit zeroing.
 *
 * Rights: pages are mapped seL4_AllRights for D1 simplicity; ld-musl mprotects
 * text to R-X at runtime.  (Tightening load-time rights is a D2/D3 item.)
 */
int lucas_elf_load_at_base(struct lucas_state *st, const void *elf_bytes,
                           size_t elf_size, uint64_t base)
{
    (void)elf_size;
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);

    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_LOAD) continue;

        uint64_t seg_vaddr = base + ph[i].p_vaddr;
        uint64_t filesz    = ph[i].p_filesz;
        uint64_t memsz     = ph[i].p_memsz;
        const uint8_t *src = (const uint8_t *)elf_bytes + ph[i].p_offset;

        uintptr_t page_base = (uintptr_t)(seg_vaddr & ~0xFFFUL);
        uintptr_t seg_end   = (uintptr_t)((seg_vaddr + memsz + 0xFFFUL) & ~0xFFFUL);
        size_t    res_size  = (size_t)(seg_end - page_base);

        printf("[lucas] dyn seg %u · vaddr=0x%lx filesz=%lu memsz=%lu pages=%zu\n",
               i, (unsigned long)seg_vaddr, (unsigned long)filesz,
               (unsigned long)memsz, res_size / 4096);

        /* Reserve the page range at the fixed base. */
        reservation_t res = vspace_reserve_range_at(
            &st->client_vspace_abs, (void *)page_base, res_size,
            seL4_AllRights, 1 /* cacheable */);
        if (res.res == NULL) {
            printf("[lucas] dyn seg %u · reserve_range_at(0x%lx,%zu) failed\n",
                   i, (unsigned long)page_base, res_size);
            return -1;
        }

        for (uintptr_t pv = page_base; pv < seg_end; pv += 4096) {
            int err = vspace_new_pages_at_vaddr(&st->client_vspace_abs,
                                                (void *)pv, 1, seL4_PageBits, res);
            if (err) {
                printf("[lucas] dyn seg %u · new_pages_at_vaddr(0x%lx) err=%d\n",
                       i, (unsigned long)pv, err);
                return -1;
            }

            seL4_CPtr frame = vspace_get_cap(&st->client_vspace_abs, (void *)pv);
            if (!frame) {
                printf("[lucas] dyn seg %u · no frame at 0x%lx\n",
                       i, (unsigned long)pv);
                return -1;
            }
            void *local = sel4utils_dup_and_map(st->vka, st->parent_vspace,
                                                frame, seL4_PageBits);
            if (!local) {
                printf("[lucas] dyn seg %u · dup_and_map(0x%lx) failed\n",
                       i, (unsigned long)pv);
                return -1;
            }

            /* Copy the file-backed portion of this page (BSS is already 0). */
            if (pv < seg_vaddr + filesz && pv + 4096 > seg_vaddr) {
                uintptr_t cstart = (pv < seg_vaddr) ? (uintptr_t)seg_vaddr : pv;
                uintptr_t cend   = (pv + 4096 > seg_vaddr + filesz)
                                   ? (uintptr_t)(seg_vaddr + filesz) : pv + 4096;
                size_t off_in_page = cstart - pv;
                size_t off_in_file = cstart - (uintptr_t)seg_vaddr;
                size_t len         = cend - cstart;
                memcpy((uint8_t *)local + off_in_page, src + off_in_file, len);
            }

            sel4utils_unmap_dup(st->vka, st->parent_vspace, local, seL4_PageBits);
        }
    }
    printf("[lucas] dyn load complete · base=0x%lx\n", (unsigned long)base);
    return 0;
}
