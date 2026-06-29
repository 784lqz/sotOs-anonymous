/* SOTOS vDSO linker script · x86-64
 *
 * Produces a freestanding PIC shared object laid out like the Linux
 * kernel's arch/x86/entry/vdso layout:
 *   - one r-x PT_LOAD covering all sections
 *   - PT_DYNAMIC segment for the dynamic linker
 *   - dynamic symbol table (.hash, .gnu.hash, .dynsym, .dynstr)
 *   - versioning stubs (.gnu.version*)
 *   - executable text last
 *
 * SONAME is injected via -Wl,-soname,linux-vdso.so.1 at link time.
 * All sections that could introduce external relocations are discarded.
 */

OUTPUT_FORMAT("elf64-x86-64")
OUTPUT_ARCH(i386:x86-64)

VERSION {
  LINUX_2.6 {
    global:
      clock_gettime; __vdso_clock_gettime;
      gettimeofday; __vdso_gettimeofday;
      time; __vdso_time;
      clock_getres; __vdso_clock_getres;
      getcpu; __vdso_getcpu;
    local: *;
  };
}

PHDRS
{
    text    PT_LOAD     FLAGS(5);       /* r-x  (READ | EXEC) */
    dynamic PT_DYNAMIC  FLAGS(4);       /* r--  (READ)        */
}

SECTIONS
{
    . = 0;

    /* Hidden vvar anchor (the Linux way · no GOT) ─────────────────────────
     * The vDSO is PIC; reaching an external symbol normally goes through the
     * GOT (an R_X86_64_GLOB_DAT reloc) which the readelf gate forbids.  Linux
     * instead defines a HIDDEN symbol for the shared data page at a FIXED
     * negative offset from the image, so the C reference compiles to a plain
     * RIP-relative LEA/MOV (R_X86_64_PC32, resolved fully at link time — no
     * dynamic reloc).  We do the same with `_sotos_vvar` (read in vdso_time.c).
     *
     * Offset rationale (this tree's layout — verified empirically):
     *   At runtime the orchestrator (src/orch/vdso_map.c) lays out:
     *       SOTOS_VDSO_BASE          [vvar]  ← _sotos_vvar must resolve here
     *       SOTOS_VDSO_BASE + 0x1000 [vdso]  ELF header (= AT_SYSINFO_EHDR)
     *   This linker script does NOT pull the ELF header/phdrs into the text
     *   PT_LOAD (no FILEHDR/PHDRS keyword), so PT_LOAD has p_offset=0x1000,
     *   p_vaddr=0 → the guest load_bias = ehdr_va + 0x1000 = BASE + 0x2000.
     *   A RIP-relative access lands at load_bias + (symbol VMA); for that to
     *   equal the vvar page at BASE the symbol VMA must be -0x2000:
     *       load_bias + (-0x2000) = (BASE + 0x2000) - 0x2000 = BASE  ✓
     *   (Standard Linux vDSOs include FILEHDR/PHDRS so load_bias == ehdr_va
     *   and the offset is one page; here the omitted header page adds 0x1000.)
     * Defined while `.` is still 0 (before any section) so it is image-anchored
     * and ld resolves the PC32 reference without emitting a GOT/GLOB_DAT slot. */
    _sotos_vvar = . - 0x2000;

    /* Dynamic symbol resolution tables */
    .hash           : { *(.hash) }          :text
    .gnu.hash       : { *(.gnu.hash) }      :text
    .dynsym         : { *(.dynsym) }        :text
    .dynstr         : { *(.dynstr) }        :text

    /* Symbol version tables (empty but present for ABI completeness) */
    .gnu.version    : { *(.gnu.version) }   :text
    .gnu.version_d  : { *(.gnu.version_d) } :text
    .gnu.version_r  : { *(.gnu.version_r) } :text

    /* Executable text */
    .text           : { *(.text .text.*) }  :text

    /* Read-only data (string literals etc.) */
    .rodata         : { *(.rodata .rodata.*) } :text

    /* Dynamic section — assigned to both PT_DYNAMIC and the text PT_LOAD
     * so the r-x segment physically covers it while PT_DYNAMIC tells the
     * dynamic linker where to find it. */
    .dynamic        : { *(.dynamic) }       :dynamic :text

    /* Discard anything that would pull in external relocations or
     * unnecessary metadata. */
    /DISCARD/ : {
        *(.note.gnu.property)
        *(.note.gnu.build-id)
        *(.note.ABI-tag)
        *(.note*)
        *(.comment)
        *(.eh_frame)
        *(.eh_frame_hdr)
        *(.gcc_except_table*)
        *(.got)
        *(.got.plt)
        *(.plt)
        *(.plt.*)
        *(.plt.got)
        *(.plt.sec)
        *(.bss*)
        *(.data*)
        *(.sdata*)
        *(.tbss*)
        *(.tdata*)
    }
}
