#include "elf_loader.h"
#include <string.h>
#include <stdio.h>

static const uint8_t lucas_elf_magic[4] = { 0x7f, 'E', 'L', 'F' };

bool lucas_elf_validate(const void *elf_bytes, size_t size) {
    if (size < sizeof(lucas_elf64_ehdr_t)) {
        printf("[lucas] elf: too small (%zu bytes)\n", size);
        return false;
    }
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;

    if (memcmp(eh->e_ident, lucas_elf_magic, 4) != 0) {
        printf("[lucas] elf: bad magic\n");
        return false;
    }
    if (eh->e_ident[4] != 2) {       /* ELFCLASS64 */
        printf("[lucas] elf: not 64-bit\n");
        return false;
    }
    if (eh->e_ident[5] != 1) {       /* ELFDATA2LSB */
        printf("[lucas] elf: not little-endian\n");
        return false;
    }
    if (eh->e_type != LUCAS_ET_EXEC && eh->e_type != LUCAS_ET_DYN) {
        printf("[lucas] elf: unsupported e_type=%u\n", eh->e_type);
        return false;
    }
    if (eh->e_machine != LUCAS_EM_X86_64) {
        printf("[lucas] elf: not x86_64 (machine=%u)\n", eh->e_machine);
        return false;
    }
    if (eh->e_phentsize != sizeof(lucas_elf64_phdr_t)) {
        printf("[lucas] elf: unexpected phentsize=%u\n", eh->e_phentsize);
        return false;
    }
    if (eh->e_phoff + (uint64_t)eh->e_phnum * eh->e_phentsize > size) {
        printf("[lucas] elf: phdr table out of bounds\n");
        return false;
    }

    /* PT_INTERP (dynamic ELF): D1 supports this via the base-relocating
     * loader + ld-musl interpreter.  Validation no longer rejects it; the
     * dynamic-vs-static decision is made in lucas_run_l1 via
     * lucas_elf_is_dynamic(). */

    printf("[lucas] elf: valid 64-bit x86_64 %s, entry=0x%lx, phnum=%u\n",
           eh->e_type == LUCAS_ET_EXEC ? "EXEC" : "DYN",
           (unsigned long)eh->e_entry, eh->e_phnum);
    return true;
}

uint64_t lucas_elf_entry(const void *elf_bytes) {
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    return eh->e_entry;
}

bool lucas_elf_is_dynamic(const void *elf_bytes) {
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i)
        if (ph[i].p_type == LUCAS_PT_INTERP) return true;
    return false;
}

bool lucas_elf_get_interp(const void *elf_bytes, size_t size,
                          char *out, size_t out_sz) {
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_INTERP) continue;
        uint64_t off = ph[i].p_offset, fsz = ph[i].p_filesz;
        if (fsz == 0 || off > (uint64_t)size || fsz > (uint64_t)size - off)
            return false;
        size_t n = (size_t)fsz;
        if (n > out_sz - 1) n = out_sz - 1;
        memcpy(out, (const uint8_t *)elf_bytes + off, n);
        out[n] = '\0';
        return true;
    }
    return false;
}

uint64_t lucas_elf_phoff(const void *elf_bytes) {
    return ((const lucas_elf64_ehdr_t *)elf_bytes)->e_phoff;
}
uint16_t lucas_elf_phnum(const void *elf_bytes) {
    return ((const lucas_elf64_ehdr_t *)elf_bytes)->e_phnum;
}
uint16_t lucas_elf_phentsize(const void *elf_bytes) {
    return ((const lucas_elf64_ehdr_t *)elf_bytes)->e_phentsize;
}

/* Load-bias-RELATIVE vaddr of the program-header table, computed the way ld.so /
 * the kernel do it.  The naive bin_base + e_phoff is only valid when the first
 * PT_LOAD maps file offset 0 at relative vaddr 0; a binary whose first PT_LOAD
 * starts at a non-zero vaddr (Go / large-aligned ELFs, e.g. `micro` at 0x400000)
 * has its phdrs at a DIFFERENT relative vaddr → a wrong AT_PHDR makes ld-musl read
 * the program headers from unmapped memory and VMFault at startup.  Resolution:
 *   1. PT_PHDR if present → its p_vaddr (the linker's authoritative answer).
 *   2. else the PT_LOAD that file-contains e_phoff → p_vaddr + (e_phoff - p_offset).
 *   3. else fallback to e_phoff (the legacy value · first-PT_LOAD-at-0 case). */
uint64_t lucas_elf_phdr_vaddr(const void *elf_bytes) {
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i)
        if (ph[i].p_type == LUCAS_PT_PHDR) return ph[i].p_vaddr;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_LOAD) continue;
        if (eh->e_phoff >= ph[i].p_offset &&
            eh->e_phoff <  ph[i].p_offset + ph[i].p_filesz)
            return ph[i].p_vaddr + (eh->e_phoff - ph[i].p_offset);
    }
    return eh->e_phoff;
}

/* Returns the first page-aligned address after the last byte mapped by
 * any PT_LOAD segment, accounting for each segment's p_align so the
 * result matches what sel4utils_elf_load actually maps.
 *
 * sel4utils_elf_load aligns each segment's mapped region down to the
 * segment's p_align boundary (typically 2 MiB for statically-linked
 * x86_64 ELFs), then maps up to align_up(p_vaddr + p_memsz, p_align).
 * brk_base must be at or beyond this boundary to avoid colliding with
 * frames that are already reserved in the client vspace. */
uint64_t lucas_elf_load_end(const void *elf_bytes) {
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);
    uint64_t end = 0;
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_LOAD) continue;
        uint64_t align = ph[i].p_align;
        if (align < 0x1000UL) align = 0x1000UL;   /* minimum page alignment */
        uint64_t seg_end = ph[i].p_vaddr + ph[i].p_memsz;
        /* Round up to the segment's alignment boundary (matches sel4utils). */
        seg_end = (seg_end + align - 1) & ~(align - 1);
        if (seg_end > end) end = seg_end;
    }
    return end;
}

bool lucas_elf_walk_pt_load(const void *elf_bytes,
                             lucas_pt_load_cb cb,
                             void *user) {
    const lucas_elf64_ehdr_t *eh = (const lucas_elf64_ehdr_t *)elf_bytes;
    const lucas_elf64_phdr_t *ph =
        (const lucas_elf64_phdr_t *)((const uint8_t *)elf_bytes + eh->e_phoff);
    for (uint16_t i = 0; i < eh->e_phnum; ++i) {
        if (ph[i].p_type != LUCAS_PT_LOAD) continue;
        const void *seg_data = (const uint8_t *)elf_bytes + ph[i].p_offset;
        if (!cb(&ph[i], seg_data, user)) return false;
    }
    return true;
}
