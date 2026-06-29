/*
 * sotOs · LUCAS L1 · static x86_64 ELF loader.
 *
 * No dynamic linker. No interpreter. No relocations.
 * Validates the header and exposes PT_LOAD iteration.
 */

#ifndef SOTOS_LUCAS_ELF_LOADER_H
#define SOTOS_LUCAS_ELF_LOADER_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/* Subset of Elf64_Ehdr; matches the on-disk layout exactly. */
typedef struct __attribute__((packed)) {
    uint8_t   e_ident[16];
    uint16_t  e_type;
    uint16_t  e_machine;
    uint32_t  e_version;
    uint64_t  e_entry;
    uint64_t  e_phoff;
    uint64_t  e_shoff;
    uint32_t  e_flags;
    uint16_t  e_ehsize;
    uint16_t  e_phentsize;
    uint16_t  e_phnum;
    uint16_t  e_shentsize;
    uint16_t  e_shnum;
    uint16_t  e_shstrndx;
} lucas_elf64_ehdr_t;

/* Subset of Elf64_Phdr. */
typedef struct __attribute__((packed)) {
    uint32_t  p_type;
    uint32_t  p_flags;
    uint64_t  p_offset;
    uint64_t  p_vaddr;
    uint64_t  p_paddr;
    uint64_t  p_filesz;
    uint64_t  p_memsz;
    uint64_t  p_align;
} lucas_elf64_phdr_t;

#define LUCAS_PT_NULL    0
#define LUCAS_PT_LOAD    1
#define LUCAS_PT_INTERP  3
#define LUCAS_PT_PHDR    6

#define LUCAS_PF_X       0x1
#define LUCAS_PF_W       0x2
#define LUCAS_PF_R       0x4

#define LUCAS_ET_EXEC    2
#define LUCAS_ET_DYN     3

#define LUCAS_EM_X86_64  62

/* Validate the file is a static x86_64 ELF we can load.
 * Returns true on OK, false with a printf-logged reason on failure. */
bool lucas_elf_validate(const void *elf_bytes, size_t size);

/* Get the entry point virtual address from a validated ELF. */
uint64_t lucas_elf_entry(const void *elf_bytes);

/* Returns the first page-aligned address past all PT_LOAD segments.
 * Use this as brk_base after ELF loading so the heap doesn't collide
 * with the stack or other fixed-address regions. */
uint64_t lucas_elf_load_end(const void *elf_bytes);

/* True if the ELF has a PT_INTERP segment (dynamically linked). */
bool lucas_elf_is_dynamic(const void *elf_bytes);

/* Copy the PT_INTERP path into out (NUL-terminated, bounded by out_sz).
 * Returns true if a PT_INTERP was found and copied. */
bool lucas_elf_get_interp(const void *elf_bytes, size_t size,
                          char *out, size_t out_sz);

/* Program-header table accessors (for building the auxv). */
uint64_t lucas_elf_phoff(const void *elf_bytes);

/* Load-bias-RELATIVE vaddr of the program headers (for AT_PHDR).  NOT the naive
 * e_phoff — that's only right when the first PT_LOAD maps file offset 0 at vaddr 0.
 * Resolves PT_PHDR, else the PT_LOAD that file-contains e_phoff (handles Go /
 * large-aligned ELFs like `micro` whose first PT_LOAD starts at vaddr 0x400000). */
uint64_t lucas_elf_phdr_vaddr(const void *elf_bytes);
uint16_t lucas_elf_phnum(const void *elf_bytes);
uint16_t lucas_elf_phentsize(const void *elf_bytes);

/* Callback called for each PT_LOAD segment. Return false to abort. */
typedef bool (*lucas_pt_load_cb)(const lucas_elf64_phdr_t *ph,
                                  const void *segment_data,
                                  void *user);

/* Walk PT_LOAD segments of a validated ELF. */
bool lucas_elf_walk_pt_load(const void *elf_bytes,
                             lucas_pt_load_cb cb,
                             void *user);

/* Forward declaration so we don't pull seL4 headers into a pure-ELF API. */
struct lucas_state;

/* Allocate a fresh client vspace inside `st->client_vspace_abs`, then
 * map each PT_LOAD segment of `elf_bytes` into it. Returns 0 on success. */
int lucas_elf_load_into_client(struct lucas_state *st, const void *elf_bytes, size_t elf_size);

/* N3/D1 · Load every PT_LOAD of a validated ELF at (base + p_vaddr) into the
 * client vspace.  For ET_DYN/PIE, base is the chosen load base; for ET_EXEC
 * pass base=0.  Zero-fills BSS (memsz>filesz).  Returns 0 on success. */
int lucas_elf_load_at_base(struct lucas_state *st, const void *elf_bytes,
                           size_t elf_size, uint64_t base);

/* N3/D1 · Load a validated program (static OR dynamic) into the ALREADY-CREATED
 * client vspace.  Sets st->entry_point; for dynamic ELFs also loads ld-musl and
 * sets the auxv state (bin_* and interp_base) + brk_base.  Returns 0 on success.
 * Shared by lucas_run_l1 and sotbox_init (spawn.c). */
int lucas_elf_load_program(struct lucas_state *st, const void *elf_bytes,
                           unsigned long elf_size);

#endif /* SOTOS_LUCAS_ELF_LOADER_H */
