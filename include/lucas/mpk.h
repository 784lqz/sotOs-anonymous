/*
 * sotOs · LUCAS · Intel MPK (Memory Protection Keys) glue.
 *
 * OBSD-η · userland integration for the MPK kernel patch (sibling Unit
 * M1 · KernelLucasMPK cmake flag → CONFIG_X86_MPK).  Provides:
 *
 *   1. wrpkru / rdpkru wrappers (PKRU is per-thread).
 *   2. lucas_pkru_init() · called once at orch startup to configure
 *      PKRU so key 1 = Access-Disable (AD).  Combined with attaching
 *      key 1 to PROT_EXEC mappings (see handlers_mem.c), this gives
 *      pure execute-only: malware can JUMP to .text but cannot READ
 *      its bytes back (defeats ROP gadget scouting).
 *   3. lucas_pkru_save_and_unlock / lucas_pkru_restore · helpers for
 *      LUCAS handlers that need to TEMPORARILY read a sotbox's .text
 *      page (e.g., DNS interceptor parsing UDP packet contents).
 *
 * When CONFIG_X86_MPK is NOT defined (default · M1 patch absent), all
 * helpers expand to no-ops so the code compiles cleanly.  The kernel's
 * per-thread PKRU save/restore (Unit M1) handles the rest.
 *
 * PKRU layout (Intel SDM Vol. 3A §4.6.2):
 *   Each 4-bit nibble encodes (AD_k<<1 | WD_k) for key k:
 *     bits 0-1 = key 0  (default · 0b00 = full access)
 *     bits 2-3 = key 1  (we set 0b11 = AD + WD = no read, no write)
 *     bits 4-31 = keys 2-15 (default · 0b00 = full access)
 *   Instruction fetch is gated by XD alone (MPK doesn't apply to
 *   ifetch), so pages tagged key 1 stay executable while data reads
 *   and writes fault.  This is the OpenBSD-amd64 pmap pattern.
 */
#pragma once

#include <stdint.h>

#ifdef CONFIG_X86_MPK

static inline void wrpkru(uint32_t val) {
    /* WRPKRU writes EAX into PKRU; ECX and EDX must be zero (Intel
     * SDM Vol. 2C "WRPKRU" §5.7).  No memory operands · pure register
     * instruction · no clobbers beyond the input registers. */
    __asm__ volatile("wrpkru" : : "a"(val), "c"(0), "d"(0));
}

static inline uint32_t rdpkru(void) {
    /* RDPKRU reads PKRU into EAX; ECX must be zero, EDX gets cleared. */
    uint32_t val;
    __asm__ volatile("rdpkru" : "=a"(val) : "c"(0) : "rdx");
    return val;
}

/* Configure PKRU so key 1 = Access-Disable (AD + WD).
 * Key 0 (default · 0b00) stays full access.
 * Keys 2-15 stay full access.
 *
 * Called once per orch thread at startup (PKRU is per-thread; the
 * kernel's PKRU save/restore handles per-thread state).  For sotOs's
 * single fault-loop architecture, one call at orch startup is enough. */
static inline void lucas_pkru_init(void) {
    /* bits 0-1: key 0 = 0b00 (full access)
     * bits 2-3: key 1 = 0b11 (AD=1 + WD=1) = 0xC at nibble offset 2
     * bits 4-31: keys 2-15 = 0 (full access)
     * Total value: 0x0000_000C. */
    wrpkru(0x0000000Cu);
}

/* Save current PKRU and unlock all keys.  Use this when LUCAS needs
 * to temporarily READ from a sotbox's PROT_EXEC page (key 1 = AD by
 * default after lucas_pkru_init).  Callers MUST pair with
 * lucas_pkru_restore() to re-engage the deny-read policy. */
static inline uint32_t lucas_pkru_save_and_unlock(void) {
    uint32_t prev = rdpkru();
    wrpkru(0);   /* all keys = 0b00 = full access */
    return prev;
}

static inline void lucas_pkru_restore(uint32_t saved) {
    wrpkru(saved);
}

#else   /* CONFIG_X86_MPK not defined · M1 kernel patch absent */

/* No-op stubs so callers compile cleanly without the kernel patch.
 * The XONLY rights downgrade from OBSD-ε continues to apply at the
 * vspace_reserve_range_at level; we just lose the pure execute-only
 * data-fault behaviour until the kernel patch lands. */
static inline void lucas_pkru_init(void) {
    /* nothing · CR4.PKE is off without M1, WRPKRU would #UD */
}

#define lucas_pkru_save_and_unlock() ((uint32_t)0)
#define lucas_pkru_restore(x)        ((void)(x))

#endif  /* CONFIG_X86_MPK */
