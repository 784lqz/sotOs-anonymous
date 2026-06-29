/* vdso_probe.c — sotOs vDSO fastpath probe (Task 5, F1)
 *
 * Reads AT_SYSINFO_EHDR from the aux vector, manually parses the mapped
 * vDSO ELF (Ehdr -> PT_LOAD -> load_bias -> PT_DYNAMIC -> DT_SYMTAB/STRTAB/
 * DT_HASH/DT_GNU_HASH), locates __vdso_clock_gettime by name, and calls it
 * for both CLOCK_REALTIME (0) and CLOCK_MONOTONIC (1).
 *
 * Build (standard Alpine musl, no-PIE):
 *   MUSL=$REPO/src/test/musl-x86_64
 *   GCCINC=$(gcc -print-file-name=include)
 *   gcc -O2 -no-pie -fno-pic -nostdlib -nostdinc -static -fno-stack-protector \
 *       -Wl,--build-id=none \
 *       -isystem $MUSL/include -isystem $GCCINC \
 *       -o vdso_probe.bin \
 *       $MUSL/lib/crt1.o $MUSL/lib/crti.o \
 *       vdso_probe.c \
 *       $MUSL/lib/libc.a $MUSL/lib/crtn.o && strip vdso_probe.bin
 *
 * NOTE: use src/test/musl-x86_64 (standard Alpine musl, direct syscall
 * instruction).  Do NOT use the in-tree seL4 musl-gcc which routes all
 * syscalls through __sysinfo (AT_SYSINFO auxv); sotOs guests use the
 * standard Linux syscall instruction handled by LUCAS UnknownSyscall.
 *
 * Success output (gate marker):
 *   [vdso-probe] resolved=0x<addr> mono=<sec>.<nsec> real=<sec>
 *
 * Failure output:
 *   [vdso-probe] FAIL <reason>
 *
 * ELF layout of the sotOs vdso.so (verified via readelf):
 *   The linker script places all sections at VMA 0.  The ELF file has the
 *   header at file offset 0 and the PT_LOAD content starting at file
 *   offset 0x1000 (p_vaddr=0).  The orch maps the blob verbatim at
 *   AT_SYSINFO_EHDR, so:
 *     load_bias = AT_SYSINFO_EHDR + PT_LOAD.p_offset - PT_LOAD.p_vaddr
 *               = AT_SYSINFO_EHDR + 0x1000
 *   Runtime address of any VMA v: load_bias + v.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <elf.h>
#include <sys/auxv.h>

/* Minimal timespec / timeval (avoid sys/time.h header variations). */
struct vts { long tv_sec; long tv_nsec; };
struct vtv { long tv_sec; long tv_usec; };  /* for gettimeofday */

/* ── getauxval with /proc/self/auxv fallback ─────────────────────────────── */
static unsigned long xgetauxval(unsigned long type)
{
    unsigned long v = getauxval(type);
    if (v) return v;

    /* getauxval may return 0 for an unknown type; re-check via procfs. */
    FILE *f = fopen("/proc/self/auxv", "rb");
    if (!f) return 0;
    unsigned long pair[2];
    while (fread(pair, sizeof(pair), 1, f) == 1) {
        if (pair[0] == type) { fclose(f); return pair[1]; }
        if (pair[0] == 0) break;
    }
    fclose(f);
    return 0;
}

int main(void)
{
    /* 1. AT_SYSINFO_EHDR (33) = the guest VA where the vDSO ELF header lives. */
    unsigned long ehdr_va = xgetauxval(AT_SYSINFO_EHDR);
    if (!ehdr_va) {
        printf("[vdso-probe] FAIL AT_SYSINFO_EHDR=0\n");
        return 1;
    }

    Elf64_Ehdr *ehdr = (Elf64_Ehdr *)(uintptr_t)ehdr_va;

    /* Sanity: ELF magic. */
    if (ehdr->e_ident[EI_MAG0] != ELFMAG0 ||
        ehdr->e_ident[EI_MAG1] != ELFMAG1 ||
        ehdr->e_ident[EI_MAG2] != ELFMAG2 ||
        ehdr->e_ident[EI_MAG3] != ELFMAG3) {
        printf("[vdso-probe] FAIL bad magic %02x%02x%02x%02x ehdr=0x%lx\n",
               (unsigned)ehdr->e_ident[0], (unsigned)ehdr->e_ident[1],
               (unsigned)ehdr->e_ident[2], (unsigned)ehdr->e_ident[3],
               ehdr_va);
        return 1;
    }

    /* 2. Walk program headers to find PT_LOAD (compute load_bias) and
     *    PT_DYNAMIC (locate the dynamic section VMA).
     *
     *    The vdso.so blob is mapped verbatim at AT_SYSINFO_EHDR.
     *    File offset p_offset lands at guest VA (ehdr_va + p_offset).
     *    That guest VA corresponds to VMA p_vaddr, so:
     *      load_bias = ehdr_va + p_offset - p_vaddr                    */
    Elf64_Phdr *phdrs = (Elf64_Phdr *)(uintptr_t)(ehdr_va + ehdr->e_phoff);
    unsigned long load_bias = 0;
    int got_bias = 0;
    Elf64_Addr dyn_vaddr = 0;

    for (int i = 0; i < (int)ehdr->e_phnum; i++) {
        Elf64_Phdr *ph = &phdrs[i];
        if (ph->p_type == PT_LOAD && !got_bias) {
            load_bias = ehdr_va + (unsigned long)ph->p_offset
                        - (unsigned long)ph->p_vaddr;
            got_bias = 1;
        }
        if (ph->p_type == PT_DYNAMIC) {
            dyn_vaddr = ph->p_vaddr;
        }
    }

    if (!got_bias) {
        printf("[vdso-probe] FAIL no PT_LOAD phdr\n");
        return 1;
    }
    if (!dyn_vaddr) {
        printf("[vdso-probe] FAIL no PT_DYNAMIC phdr\n");
        return 1;
    }

    /* 3. Parse the dynamic section.  DT_ pointer values are VMAs. */
    Elf64_Dyn *dyn = (Elf64_Dyn *)(uintptr_t)(load_bias + (unsigned long)dyn_vaddr);

    Elf64_Addr symtab_vma   = 0;
    Elf64_Addr strtab_vma   = 0;
    Elf64_Xword syment      = 24;   /* sizeof(Elf64_Sym) */
    Elf64_Addr hash_vma     = 0;    /* DT_HASH  (SysV)  */
    Elf64_Addr gnu_hash_vma = 0;    /* DT_GNU_HASH      */

    for (Elf64_Dyn *d = dyn; d->d_tag != DT_NULL; d++) {
        switch ((Elf64_Sxword)d->d_tag) {
        case DT_SYMTAB:    symtab_vma   = d->d_un.d_ptr; break;
        case DT_STRTAB:    strtab_vma   = d->d_un.d_ptr; break;
        case DT_SYMENT:    syment       = d->d_un.d_val;  break;
        case DT_HASH:      hash_vma     = d->d_un.d_ptr;  break;
        case DT_GNU_HASH:  gnu_hash_vma = d->d_un.d_ptr;  break;
        }
    }

    if (!symtab_vma || !strtab_vma) {
        printf("[vdso-probe] FAIL SYMTAB=0x%lx STRTAB=0x%lx bias=0x%lx\n",
               (unsigned long)symtab_vma, (unsigned long)strtab_vma,
               load_bias);
        return 1;
    }

    /* DT_ pointer values are VMAs; guest VA = load_bias + vma.
     * Guard: if already above load_bias treat as absolute (future-proof). */
#define VMA_PTR(vma) ((uintptr_t)((vma) < (Elf64_Addr)load_bias \
                                  ? (load_bias + (unsigned long)(vma)) \
                                  : (unsigned long)(vma)))

    Elf64_Sym  *symtab = (Elf64_Sym  *)VMA_PTR(symtab_vma);
    const char *strtab = (const char *)VMA_PTR(strtab_vma);

    /* 4. Determine symbol count.
     *    DT_HASH (SysV): uint32 nbucket, uint32 nchain; nchain = sym count.
     *    DT_GNU_HASH: walk buckets+chains to find max index.
     *    Fallback: scan up to 64 entries.                                */
    unsigned nsym = 0;

    if (hash_vma) {
        uint32_t *htab = (uint32_t *)VMA_PTR(hash_vma);
        /* htab[0] = nbucket, htab[1] = nchain */
        nsym = (unsigned)htab[1];
    } else if (gnu_hash_vma) {
        uint32_t *g = (uint32_t *)VMA_PTR(gnu_hash_vma);
        uint32_t nbuckets = g[0];
        uint32_t symndx   = g[1];
        uint32_t bloom_sz = g[2];
        /* buckets follow bloom words (64-bit each) */
        uint32_t *buckets = g + 4 + bloom_sz * 2;
        uint32_t maxidx = symndx;
        for (uint32_t b = 0; b < nbuckets; b++) {
            if (buckets[b] > maxidx) maxidx = buckets[b];
        }
        /* chain[i] has bit0 = end-of-chain indicator; walk to find last */
        uint32_t *chains = buckets + nbuckets;
        uint32_t idx = maxidx;
        while (!(chains[idx - symndx] & 1)) idx++;
        nsym = (unsigned)(idx + 1);
    }
    if (nsym < 2 || nsym > 256) nsym = 64;   /* safe fallback */

    /* 5. Linear scan — collect __vdso_clock_gettime + the 3 new fast-path syms. */
    unsigned long resolved   = 0;  /* __vdso_clock_gettime */
    unsigned long gtod_addr  = 0;  /* __vdso_gettimeofday  */
    unsigned long time_addr  = 0;  /* __vdso_time          */
    unsigned long getres_addr = 0; /* __vdso_clock_getres  */

    for (unsigned i = 1; i < nsym; i++) {
        Elf64_Sym *sym = (Elf64_Sym *)((unsigned char *)symtab + i * syment);
        if (sym->st_value == 0) continue;
        const char *name = strtab + sym->st_name;
        unsigned long va = load_bias + (unsigned long)sym->st_value;
        if      (strcmp(name, "__vdso_clock_gettime") == 0) resolved    = va;
        else if (strcmp(name, "__vdso_gettimeofday")  == 0) gtod_addr   = va;
        else if (strcmp(name, "__vdso_time")          == 0) time_addr   = va;
        else if (strcmp(name, "__vdso_clock_getres")  == 0) getres_addr = va;
    }

    if (!resolved) {
        printf("[vdso-probe] FAIL __vdso_clock_gettime not found nsym=%u bias=0x%lx\n",
               nsym, load_bias);
        return 1;
    }

    /* 6. Call __vdso_clock_gettime: CLOCK_MONOTONIC (1) + CLOCK_REALTIME (0). */
    typedef long (*cgt_fn)(int, struct vts *);
    cgt_fn fn = (cgt_fn)(uintptr_t)resolved;

    struct vts mono = {0, 0};
    struct vts real = {0, 0};
    long r1 = fn(1, &mono);   /* CLOCK_MONOTONIC */
    long r2 = fn(0, &real);   /* CLOCK_REALTIME  */

    if (r1 != 0 || r2 != 0) {
        printf("[vdso-probe] FAIL clock_gettime rc mono=%ld real=%ld\n", r1, r2);
        return 1;
    }

    /* 7. No-trap proof: time ONE __vdso_clock_gettime(CLOCK_MONOTONIC) call
     *    with rdtsc fences around it.  A trapping (syscall) call costs ~8000-
     *    17000 cyc on this host; a real in-guest vDSO call is hundreds. */
    struct vts t0v = {0, 0};
    unsigned lo, hi;
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi));
    unsigned long c0 = ((unsigned long)hi << 32) | lo;
    long rc = fn(1, &t0v);    /* CLOCK_MONOTONIC — the timed call */
    __asm__ __volatile__("lfence; rdtsc" : "=a"(lo), "=d"(hi));
    unsigned long c1 = ((unsigned long)hi << 32) | lo;
    unsigned long cgt_cycles = c1 - c0;

    if (rc != 0) {
        printf("[vdso-probe] FAIL timed clock_gettime rc=%ld\n", rc);
        return 1;
    }

    /* 8. Monotonicity: two back-to-back CLOCK_MONOTONIC reads must strictly
     *    increase (proves the fast-path returns live, advancing time). */
    struct vts m1 = {0, 0}, m2 = {0, 0};
    fn(1, &m1);
    fn(1, &m2);
    long long ns1 = (long long)m1.tv_sec * 1000000000LL + m1.tv_nsec;
    long long ns2 = (long long)m2.tv_sec * 1000000000LL + m2.tv_nsec;
    int mono_inc = (ns2 > ns1) ? 1 : 0;

    /* 9. Canonical gate marker (extended with no-trap evidence). */
    printf("[vdso-probe] resolved=0x%lx mono=%ld.%09ld real=%ld "
           "cgt_cycles=%lu mono_inc=%d\n",
           resolved, mono.tv_sec, mono.tv_nsec, real.tv_sec,
           cgt_cycles, mono_inc);

    /* 10. Deception gate (Task 13): /proc/self/maps [vdso] line must point to
     *     a region that is REALLY mapped and contains a valid ELF, and must
     *     agree with AT_SYSINFO_EHDR (the auxv and the maps line tell the
     *     same story — no phantom vDSO address in maps).
     *
     *     Output: [vdso-deception] maps_vdso=0x%lx auxv_ehdr=0x%lx
     *                              elf_magic=OK|BAD match=1|0
     */
    {
        unsigned long maps_vdso = 0;

        FILE *mf = fopen("/proc/self/maps", "r");
        if (mf) {
            char line[256];
            while (fgets(line, sizeof(line), mf)) {
                if (strstr(line, "[vdso]")) {
                    /* format: "<start>-<end> ..." */
                    maps_vdso = strtoul(line, NULL, 16);
                    break;
                }
            }
            fclose(mf);
        }

        /* Read the first 4 bytes at the maps [vdso] base. */
        const unsigned char *p = (const unsigned char *)(uintptr_t)maps_vdso;
        int elf_ok = (maps_vdso &&
                      p[0] == 0x7f && p[1] == 'E' &&
                      p[2] == 'L'  && p[3] == 'F');
        int match  = (maps_vdso != 0 && maps_vdso == ehdr_va);

        printf("[vdso-deception] maps_vdso=0x%lx auxv_ehdr=0x%lx elf_magic=%s match=%d\n",
               maps_vdso, ehdr_va,
               elf_ok ? "OK" : "BAD",
               match);
    }

    /* 12. gettimeofday / time / clock_getres fast-path check. */
    if (gtod_addr && time_addr && getres_addr) {
        typedef long (*gtod_f)(struct vtv *, void *);
        typedef long (*time_f)(long *);
        typedef long (*getres_f)(int, struct vts *);

        gtod_f   fn_gtod   = (gtod_f)(uintptr_t)gtod_addr;
        time_f   fn_time   = (time_f)(uintptr_t)time_addr;
        getres_f fn_getres = (getres_f)(uintptr_t)getres_addr;

        struct vtv gtod_tv = {0, 0};
        long time_val = 0;
        struct vts res_ts = {0, 0};

        fn_gtod(&gtod_tv, NULL);
        fn_time(&time_val);
        fn_getres(0, &res_ts);  /* CLOCK_REALTIME */

        printf("[vdso-probe] gtod=%ld.%06ld time=%ld res=%ld.%09ld\n",
               gtod_tv.tv_sec, gtod_tv.tv_usec, time_val,
               res_ts.tv_sec, res_ts.tv_nsec);
    } else {
        printf("[vdso-probe] FAIL missing syms gtod=0x%lx time=0x%lx getres=0x%lx\n",
               gtod_addr, time_addr, getres_addr);
    }

    return 0;
}
