/*
 * sotOs · lucas-orchestrator · build allocman/vka from delegated untypeds.
 *
 * T3 had root copy N untypeds into the orchestrator's CSpace at slots
 * [bs.cnode_slot_first .. bs.cnode_slot_first + bs.untyped_count - 1].
 *
 * Here we:
 *   1. bootstrap_use_current_1level over our existing 14-bit CNode,
 *      reserving slots from (cnode_slot_first + untyped_count) onward
 *      as the free pool the allocman can hand out.
 *   2. (A1-Robust) Configure mspace watermark chunks so that if/when
 *      bootstrap_configure_virtual_pool is ever called, the re-entrancy
 *      path (_add_page → utspace_alloc → mspace_alloc) has pre-reserved
 *      buffers available in the static pool.
 *   3. allocman_utspace_add_uts with our delegated untypeds.
 *   4. allocman_make_vka so the rest of the orchestrator has a vka_t.
 *   5. Sanity-check by allocating one endpoint.
 *
 * A1-Robust (mspace watermark pre-reservation):
 *   allocman_configure_mspace_reserve pre-populates watermark chunks for
 *   the sizes that are requested during the recursive re-entrancy path:
 *     _add_page → _utspace_split_alloc → allocman_mspace_alloc (for
 *     utspace_split_node tracking structs and cspacepath_t temp objects).
 *
 *   These chunks are drawn from the 512 KiB static pool at bootstrap and
 *   held in the watermark reservoir.  When mspace_alloc is blocked by the
 *   re-entrancy guard (mspace_alloc_depth > 0), the watermark pool satisfies
 *   the request without going through the outer alloc path.
 *
 * A1-Robust (bootstrap_configure_virtual_pool investigation):
 *   Attaching the virtual pool (bootstrap_configure_virtual_pool) was
 *   investigated but found to break vka_alloc_endpoint with
 *   seL4_FailedLookup (error 6: "Destination cap invalid or read-only")
 *   during subsequent utspace_split retypes.  The failure is reproducible
 *   regardless of whether virtual_pool is attached before or after
 *   allocman_utspace_add_uts.  Root cause appears to be a kernel-level
 *   restriction on non-root processes performing utspace_reserve fills for
 *   paging structures (Page + PageTable + PageDirectory + PDPT) which
 *   modifies allocman state in a way that invalidates subsequent retypes.
 *   bootstrap_configure_virtual_pool is intentionally NOT called here;
 *   the 512 KiB static pool provides sufficient capacity for all current
 *   features.  The mspace watermark chunks are pre-reserved for future use
 *   when this is revisited.
 */

#include <orch/proto.h>
#include <orch/sotbox.h>
#include <orch/arena.h>
#include <orch/tpm.h>
#include <sotos/random.h>
#include <sotos/sha256.h>
#include <lucas/anomaly.h>
#include <lucas/mpk.h>
#include <sotnet/dns.h>
#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include <sel4utils/process.h>           /* SEL4UTILS_CNODE_SLOT */
#include <allocman/allocman.h>
#include <allocman/bootstrap.h>
#include <allocman/vka.h>
#include <allocman/utspace/utspace.h>    /* ALLOCMAN_UT_KERNEL */
#include <allocman/utspace/split.h>      /* struct utspace_split_node */
#include <vka/object.h>
#include <vka/capops.h>

/* A1-Robust: 512 KiB static pool is the floor for orch's allocman.
 * Mspace watermark chunks (see A1-Robust comment above) are pre-reserved
 * inside this pool so that if/when the virtual pool is attached later the
 * re-entrancy path has buffers available. */
/* L11-β-2 · bumped 512 KiB → 16 MiB to handle CPython 3.12 sotbox spawn
 * (24 MiB ELF = ~6000 frames per LOAD segments · allocman tracks each
 * frame cap in its metadata pool).  Untyped memory budget is plentiful
 * (orch gets 256+ MiB delegated from root); the bottleneck was just the
 * tracking-pool size. */
#define ORCH_ALLOCMAN_POOL_BYTES   (16u << 20)  /* 16 MiB */

static char allocman_pool[ORCH_ALLOCMAN_POOL_BYTES] __attribute__((aligned(4096)));

/* Singletons accessed via orch_vka() / orch_allocman(). */
static allocman_t *g_allocman = NULL;
static vka_t       g_vka;

int orch_bootstrap_init(const orch_bootstrap_info_t *bs)
{
    if (bs->untyped_count == 0) {
        printf("[orch] BOOTSTRAP: zero untypeds delegated · cannot build allocman\n");
        return -1;
    }

    /* OBSD-η · configure PKRU so key 1 = Access-Disable on this thread.
     * PKRU is per-thread; this is the orch fault-loop thread.  Combined
     * with attaching key 1 to PROT_EXEC mappings in lucas_sys_mmap, this
     * gives pure execute-only (malware can jump to .text but cannot read
     * its bytes).  No-op when CONFIG_X86_MPK is unset (M1 patch absent). */
    lucas_pkru_init();
#ifdef CONFIG_X86_MPK
    printf("[orch] OBSD-η · PKRU configured · key 1 = Access-Disable\n");
#endif

    seL4_CPtr free_start = bs->cnode_slot_first + bs->untyped_count;
    /* virtio-blk Phase 2b: root may have placed extra caps (IOPort) into
     * orch's CSpace immediately after the untyped caps.  Advance free_start
     * past any such cap so allocman does not hand out an occupied slot. */
    if (bs->io_port_slot != 0 && (seL4_CPtr)bs->io_port_slot >= free_start) {
        free_start = (seL4_CPtr)bs->io_port_slot + 1;
    }
    /* Path D: root may have placed the anomaly event EP into orch's CSpace.
     * Advance free_start past it so allocman does not hand out an occupied slot. */
    if (bs->anomaly_event_ep_slot != 0
        && (seL4_CPtr)bs->anomaly_event_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->anomaly_event_ep_slot + 1;
    }
    /* sotNet-γ Phase 3-A: root may have placed the synth event EP into orch's CSpace.
     * Advance free_start past it so allocman does not hand out an occupied slot. */
    if (bs->synth_event_ep_slot != 0
        && (seL4_CPtr)bs->synth_event_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->synth_event_ep_slot + 1;
    }
    /* procd PR 4: root may have placed the procd event NTF cap into orch's CSpace.
     * Advance free_start past it so allocman does not hand out an occupied slot. */
    if (bs->procd_event_ntf_slot != 0
        && (seL4_CPtr)bs->procd_event_ntf_slot >= free_start) {
        free_start = (seL4_CPtr)bs->procd_event_ntf_slot + 1;
    }
    /* procd PR 5: root may have placed the procd listen EP cap into orch's CSpace
     * (used by orch_procd_spawn for OP_SPAWN announce).  Same free_start dance. */
    if (bs->procd_listen_ep_slot != 0
        && (seL4_CPtr)bs->procd_listen_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->procd_listen_ep_slot + 1;
    }
    /* procd PR 10: root may have placed the BADGED procd listen EP into
     * orch's CSpace (used by lucas_set_tier → orch_procd_set_tier for the
     * OP_SET_TIER dual-write).  Same free_start dance. */
    if (bs->procd_set_tier_ep_slot != 0
        && (seL4_CPtr)bs->procd_set_tier_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->procd_set_tier_ep_slot + 1;
    }
    /* β · PR 5: root may have placed the sotinit listen EP into orch's
     * CSpace (orch forwards it to sotShell so the operator can drive
     * `systemctl <action> <unit>` against sotinit's IPC loop).  Same
     * free_start dance · don't let allocman reuse the slot. */
    if (bs->sotinit_listen_ep_slot != 0
        && (seL4_CPtr)bs->sotinit_listen_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->sotinit_listen_ep_slot + 1;
    }
    /* β · PR 9: root may have placed the sotcron listen EP into orch's
     * CSpace (orch forwards it to sotShell so the operator can drive
     * `cron list` / `cron now <timer>` against sotcron's non-blocking
     * IPC drain).  Same free_start dance · without this, allocman's
     * first untyped retype lands on the occupied slot and bootstrap
     * dies with seL4_DeleteFirst (rc=8). */
    if (bs->sotcron_listen_ep_slot != 0
        && (seL4_CPtr)bs->sotcron_listen_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->sotcron_listen_ep_slot + 1;
    }
    /* L12-alpha: root may have placed the Wayland compositor listen EP into
     * orch's CSpace. Reserve the slot for the future AF_UNIX route. */
    if (bs->wayland_listen_ep_slot != 0
        && (seL4_CPtr)bs->wayland_listen_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->wayland_listen_ep_slot + 1;
    }
    /* L13-A1: root may have placed the compositor PD (PML4) cap into orch's
     * CSpace for SHM frame mapping.  Reserve the slot so allocman does not
     * clobber it during untyped retype. */
    if (bs->wayland_pd_slot != 0
        && (seL4_CPtr)bs->wayland_pd_slot >= free_start) {
        free_start = (seL4_CPtr)bs->wayland_pd_slot + 1;
    }
    /* L14a-A1: root may have placed the shadow compositor listen EP into orch's
     * CSpace for hostile-client routing.  Reserve the slot so allocman does not
     * clobber it during untyped retype. */
    if (bs->wayland_canary_ep_slot != 0
        && (seL4_CPtr)bs->wayland_canary_ep_slot >= free_start) {
        free_start = (seL4_CPtr)bs->wayland_canary_ep_slot + 1;
    }
    /* IRQ-driven virtio-net RX: root may have placed the virtio-net IRQ
     * Notification + IRQHandler caps into orch's CSpace.  Reserve both slots so
     * allocman's first untyped retype does not clobber them. */
    if (bs->virtio_net_irq_ntf_slot != 0
        && (seL4_CPtr)bs->virtio_net_irq_ntf_slot >= free_start) {
        free_start = (seL4_CPtr)bs->virtio_net_irq_ntf_slot + 1;
    }
    if (bs->virtio_net_irq_handler_slot != 0
        && (seL4_CPtr)bs->virtio_net_irq_handler_slot >= free_start) {
        free_start = (seL4_CPtr)bs->virtio_net_irq_handler_slot + 1;
    }
    /* Same for the 2nd (lwIP egress) NIC's IRQ Notification + IRQHandler. */
    if (bs->lwip_net_irq_ntf_slot != 0
        && (seL4_CPtr)bs->lwip_net_irq_ntf_slot >= free_start) {
        free_start = (seL4_CPtr)bs->lwip_net_irq_ntf_slot + 1;
    }
    if (bs->lwip_net_irq_handler_slot != 0
        && (seL4_CPtr)bs->lwip_net_irq_handler_slot >= free_start) {
        free_start = (seL4_CPtr)bs->lwip_net_irq_handler_slot + 1;
    }
    if (bs->lwip_pit_irq_handler_slot != 0
        && (seL4_CPtr)bs->lwip_pit_irq_handler_slot >= free_start) {
        free_start = (seL4_CPtr)bs->lwip_pit_irq_handler_slot + 1;
    }

    /* ---- P2a · select arena untypeds + reserve their cslot ranges BEFORE the
     * allocman bootstrap consumes free_start, and BEFORE the add-loop excludes
     * them.  Declared at function scope so the add-loop (line ~252) and the
     * pool registration (after allocman_make_vka) can see them. ----
     *
     * Only the SINGLE primary sotbox is arena-backed (g_primary_inited → one at a
     * time; fork children use the global allocman).  The primary revokes+releases
     * its arena each reap and re-acquires next spawn, so a pool of 2 (1 active +
     * 1 spare) is ample.  Reserve SMALL untypeds (smallest ≥ the floor) so the
     * allocman keeps its big blocks for orch's long-lived objects (blocker 4). */
    #define SOTBOX_ARENA_COUNT  SOTBOX_MAX_SLOTS
    bool      is_arena[ORCH_MAX_DELEGATED_UNTYPEDS] = { false };
    seL4_CPtr arena_uts[SOTBOX_ARENA_COUNT];
    size_t    arena_sb [SOTBOX_ARENA_COUNT];
    int       arena_n = 0;
    /* Log the full delegated size_bits distribution so the window is validatable. */
    printf("[orch] P2a delegated untypeds (%u):", bs->untyped_count);
    for (uint32_t i = 0; i < bs->untyped_count; ++i)
        printf(" %s%zu", bs->ut_is_device[i] ? "dev" : "", (size_t)bs->ut_size_bits[i]);
    printf("\n");
    /* Two passes: prefer the SMALLEST non-device untypeds at/above the floor so
     * we never strand the allocman's large blocks.  (Simple selection-min ×N.) */
    for (int pick = 0; pick < SOTBOX_ARENA_COUNT; ++pick) {
        int best = -1; size_t best_sb = (size_t)-1;
        for (uint32_t i = 0; i < bs->untyped_count; ++i) {
            if (is_arena[i] || bs->ut_is_device[i]) continue;
            size_t sb = (size_t)bs->ut_size_bits[i];
            if (sb < SOTBOX_ARENA_MIN_BITS) continue;     /* must hold a whole sotbox */
            if (sb < best_sb) { best_sb = sb; best = (int)i; }
        }
        if (best < 0) break;
        is_arena[best]       = true;
        arena_uts[arena_n]   = (seL4_CPtr)bs->cnode_slot_first + (uint32_t)best;
        arena_sb [arena_n]   = best_sb;
        ++arena_n;
    }
    seL4_CPtr arena_cslot_base = free_start;
    free_start += (seL4_CPtr)SOTBOX_ARENA_COUNT * SOTBOX_ARENA_CSLOTS;
    printf("[orch] P2a arenas: %d/%d reserved (floor szbits=%d) + cslots [%lu..%lu) · free_start=%lu (CNode 1<<17=%u)\n",
           arena_n, SOTBOX_ARENA_COUNT, SOTBOX_ARENA_MIN_BITS,
           (unsigned long)arena_cslot_base, (unsigned long)free_start,
           (unsigned long)free_start, (unsigned)(1u << 18));
    if (arena_n == 0)
        printf("[orch] WARNING P2a: NO arena untypeds found ≥ szbits %d · teardown disabled (leak)\n",
               SOTBOX_ARENA_MIN_BITS);

    seL4_CPtr free_end   = (seL4_CPtr)1u << 18;   /* T3 created an 18-bit cnode · apt pkgCache cslots */

    g_allocman = bootstrap_use_current_1level(
        SEL4UTILS_CNODE_SLOT,    /* root_cnode cap is at slot 1 in our cspace */
        18,                       /* cnode_size_bits · 17->18 · matches root/bootstrap.c */
        free_start,               /* start_slot · first free slot */
        free_end,                 /* end_slot · one past last */
        sizeof(allocman_pool),
        allocman_pool);

    if (!g_allocman) {
        printf("[orch] bootstrap_use_current_1level returned NULL\n");
        return -1;
    }

    /* A1-Robust · pre-reserve mspace watermark chunks BEFORE adding untypeds.
     * These chunks are drawn from the static pool now, while no re-entrancy
     * guard is active, and held in the watermark reservoir.  If/when the
     * virtual pool (_add_page path) needs mspace_alloc from inside a
     * mspace_alloc context, _try_watermark_mspace serves the request.
     *
     * Chunk sizes cover the allocation sizes seen during the recursive path:
     *   _add_page → _utspace_split_alloc → allocman_mspace_alloc:
     *
     *   sizeof(struct utspace_split_node) = cspacepath_t(56) + 6×ptr(48)
     *                                     + uintptr_t(8) = 112 bytes
     *   sizeof(cspacepath_t)              = 7 × seL4_Word = 56 bytes
     *   64, 128                           · misc rounded allocs
     */
    {
        struct allocman_mspace_chunk mspace_reserves[] = {
            { .size = sizeof(struct utspace_split_node), .count = 32 },
            { .size = sizeof(cspacepath_t),              .count = 8  },
            { .size = 64,                                .count = 16 },
            { .size = 128,                               .count = 8  },
        };
        for (size_t ri = 0;
             ri < sizeof(mspace_reserves) / sizeof(mspace_reserves[0]);
             ++ri) {
            int rc = allocman_configure_mspace_reserve(g_allocman,
                                                       mspace_reserves[ri]);
            if (rc != 0) {
                printf("[orch] mspace_reserve[%zu] size=%zu count=%zu FAILED rc=%d\n",
                       ri,
                       mspace_reserves[ri].size,
                       mspace_reserves[ri].count,
                       rc);
            } else {
                printf("[orch] mspace reserved · size=%zu count=%zu\n",
                       mspace_reserves[ri].size,
                       mspace_reserves[ri].count);
            }
        }
    }

    /* Build the parallel arrays for add_uts.  We split the batch into two
     * passes so we can tag device untypeds (ALLOCMAN_UT_DEV) separately from
     * RAM untypeds (ALLOCMAN_UT_KERNEL).  Device untypeds will only be used
     * by allocman when the caller explicitly requests a specific paddr — this
     * is exactly the access pattern of the OBSD-η TPM driver
     * (vka_alloc_frame_at(0xFED40000)). */
    cspacepath_t paths_k [ORCH_MAX_DELEGATED_UNTYPEDS];
    size_t       sizes_k [ORCH_MAX_DELEGATED_UNTYPEDS];
    uintptr_t    paddrs_k[ORCH_MAX_DELEGATED_UNTYPEDS];
    cspacepath_t paths_d [ORCH_MAX_DELEGATED_UNTYPEDS];
    size_t       sizes_d [ORCH_MAX_DELEGATED_UNTYPEDS];
    uintptr_t    paddrs_d[ORCH_MAX_DELEGATED_UNTYPEDS];
    uint32_t nk = 0, nd = 0;

    for (uint32_t i = 0; i < bs->untyped_count; ++i) {
        seL4_CPtr ut_slot = (seL4_CPtr)bs->cnode_slot_first + i;
        if (bs->ut_is_device[i]) {
            paths_d [nd] = allocman_cspace_make_path(g_allocman, ut_slot);
            sizes_d [nd] = (size_t)bs->ut_size_bits[i];
            paddrs_d[nd] = (uintptr_t)bs->ut_paddr[i];
            ++nd;
        } else if (!is_arena[i]) {
            paths_k [nk] = allocman_cspace_make_path(g_allocman, ut_slot);
            sizes_k [nk] = (size_t)bs->ut_size_bits[i];
            paddrs_k[nk] = (uintptr_t)bs->ut_paddr[i];
            ++nk;
        }
    }

    int err = allocman_utspace_add_uts(g_allocman, (size_t)nk,
                                         paths_k, sizes_k, paddrs_k,
                                         ALLOCMAN_UT_KERNEL);
    if (err) {
        printf("[orch] allocman_utspace_add_uts (kernel) failed (err=%d)\n", err);
        return -1;
    }
    if (nd > 0) {
        err = allocman_utspace_add_uts(g_allocman, (size_t)nd,
                                         paths_d, sizes_d, paddrs_d,
                                         ALLOCMAN_UT_DEV);
        if (err) {
            printf("[orch] allocman_utspace_add_uts (device) failed (err=%d)\n", err);
            /* Non-fatal · TPM driver will degrade gracefully. */
        } else {
            printf("[orch] %u device untyped(s) delegated for MMIO\n", nd);
        }
    }

    allocman_make_vka(&g_vka, g_allocman);

    for (int a = 0; a < arena_n; ++a) {
        sotbox_arena_pool_add(arena_uts[a], arena_sb[a],
                              arena_cslot_base + (seL4_CPtr)a * SOTBOX_ARENA_CSLOTS);
    }
    printf("[orch] P2a arena pool ready · %d arenas free\n", sotbox_arena_pool_count_free());

    /* obsd-β: seed arc4random immediately after allocman is ready.
     * Sources: rdtsc (always available on x86_64) + low bytes of
     * delegated untyped physical addresses (layout-dependent entropy)
     * + rdrand (if CPUID flags bit 30 of ECX for CPUID.1). */
    {
        uint8_t seed[40];
        uint64_t ts;
        /* Source 1: rdtsc timestamp (least significant bytes). */
        asm volatile("rdtsc" : "=A"(ts));
        __builtin_memcpy(seed, &ts, 8);
        /* Source 2: physical addresses of delegated untypeds. */
        size_t off = 8;
        for (uint32_t i = 0; i < bs->untyped_count && off < 32; ++i) {
            seed[off++] = (uint8_t)(bs->ut_paddr[i] >> 12);
        }
        /* Fill up to byte 32 with more rdtsc if fewer untypeds than needed. */
        while (off < 32) {
            asm volatile("rdtsc" : "=A"(ts));
            seed[off++] = (uint8_t)ts;
        }
        /* Source 3: rdrand if CPUID supports it (bit 30 of ECX, CPUID.1). */
        {
            uint32_t eax, ebx, ecx, edx;
            asm volatile("cpuid"
                         : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                         : "a"(1));
            if (ecx & (1u << 30)) {
                uint64_t r = 0;
                unsigned char ok = 0;
                asm volatile("rdrand %0; setc %1" : "=r"(r), "=qm"(ok));
                if (ok) __builtin_memcpy(seed + 32, &r, 8);
            }
        }
        /* Fill remaining bytes (seed[32..39]) with rdtsc if rdrand unavailable. */
        while (off < 40) {
            asm volatile("rdtsc" : "=A"(ts));
            seed[off++] = (uint8_t)ts;
        }
        sotos_arc4random_init(seed, sizeof(seed));
        __builtin_memset(seed, 0, sizeof(seed));
        printf("[orch] arc4random seeded (40 bytes from rdtsc + UT paddrs + rdrand)\n");
    }

    /* Sanity check: allocate one endpoint via the vka.  Proves we can
     * carve from the delegated untypeds. */
    vka_object_t ep_obj;
    err = vka_alloc_endpoint(&g_vka, &ep_obj);
    if (err) {
        printf("[orch] sanity vka_alloc_endpoint failed (err=%d)\n", err);
        return err;
    }
    printf("[orch] vka ready · sanity EP cap=%lu (from delegated untypeds)\n",
           (unsigned long)ep_obj.cptr);

    /* L3b-T1: allocate the shared fault EP (one EP services ALL sotBoxes,
     * dispatched by badge = slot_index + 1). */
    vka_object_t fault_ep_obj;
    err = vka_alloc_endpoint(&g_vka, &fault_ep_obj);
    if (err) {
        printf("[orch] shared fault EP alloc failed (err=%d)\n", err);
        return err;
    }
    orch_set_fault_ep(fault_ep_obj.cptr);
    printf("[orch] shared fault EP cap=%lu\n",
           (unsigned long)fault_ep_obj.cptr);

    /* sotFS-β-Phase-B · if root delegated a pre-existing STO endpoint (future
     * path where root spawns sotOs-sto before orch), capture it now.
     * In the current deployment, root does NOT spawn sotOs-sto; orch spawns
     * it from its own CPIO after this bootstrap call returns (in main.c). */
    if (bs->sto_ep_slot != 0) {
        extern void orch_set_sto_ep(seL4_CPtr ep);
        orch_set_sto_ep((seL4_CPtr)bs->sto_ep_slot);
        printf("[orch] STO endpoint delegated by root · slot=%lu\n",
               (unsigned long)bs->sto_ep_slot);
    }

    /* virtio-blk Phase 2b · capture the delegated x86 IOPort cap, then
     * probe PCI bus 0 to discover and identify the virtio-blk device. */
    if (bs->io_port_slot != 0) {
        extern void orch_set_io_port_cap(seL4_CPtr cap);
        orch_set_io_port_cap((seL4_CPtr)bs->io_port_slot);
        printf("[orch] IOPort cap received from root · slot=%lu\n",
               (unsigned long)bs->io_port_slot);
    }

    /* sotNet-γ Phase 3-A · capture the synth event EP delegated by root.
     * synth_record_redirect() sends ORCH_OP_SYNTH_REDIRECT on this EP
     * to the sotOs-net-synth server process. */
    if (bs->synth_event_ep_slot != 0) {
        extern void orch_set_synth_event_ep(seL4_CPtr ep);
        orch_set_synth_event_ep((seL4_CPtr)bs->synth_event_ep_slot);
        printf("[orch] synth event EP received from root · slot=%lu (Phase 3-A active)\n",
               (unsigned long)bs->synth_event_ep_slot);
    }

    /* Path D · capture the anomaly event EP delegated by root.
     * Orch sends ORCH_OP_ANOMALY_EVENT on this badged EP to the anomaly
     * process whenever lucas_sys_write fires anomaly_on_write(). */
    if (bs->anomaly_event_ep_slot != 0) {
        extern void orch_set_anomaly_ep(seL4_CPtr ep);
        orch_set_anomaly_ep((seL4_CPtr)bs->anomaly_event_ep_slot);
        printf("[orch] anomaly event EP received from root · slot=%lu (Path D active)\n",
               (unsigned long)bs->anomaly_event_ep_slot);

        /* A3-Z · synthetic trigger removed.  The round-trip is now driven
         * purely by real Linux sotbox writes: anomaly_on_write() in
         * src/lucas/anomaly.c forwards ANOMALY_EV_WRITE for every real
         * write syscall, and the external anomaly (threshold > 50 ·
         * S-THRESH) fires ORCH_OP_PROMOTE_TIER when a sotbox crosses 51
         * writes organically. */
    }

    printf("[orch] wayland listen EP slot=%lu (%s)\n",
           (unsigned long)bs->wayland_listen_ep_slot,
           bs->wayland_listen_ep_slot ? "active" : "absent · wayland-0 disabled");
    /* Captured sotfs.img sector-0 bytes, used later for PCR 10 measured-boot.
     * 512 B is enough to fingerprint the on-disk header without hammering
     * virtio-blk with thousands of follow-up reads at bootstrap time. */
    static uint8_t bs_sotfs_sector0[512];
    int bs_sotfs_sector0_valid = 0;
    {
        extern int  virtio_blk_probe(void);
        extern int  virtio_blk_present(void);
        extern int  virtio_blk_init_queue(void);
        extern int  virtio_blk_read_sector(uint64_t sector, void *out_buf);
        virtio_blk_probe();
        /* virtio-blk Phase 2c: set up the virtqueue and read sector 0. */
        if (virtio_blk_present()) {
            if (virtio_blk_init_queue() == 0) {
                if (virtio_blk_read_sector(0, bs_sotfs_sector0) == 0) {
                    bs_sotfs_sector0_valid = 1;
                }
            }
        }
    }
    /* SP2 PR2 · binstore region self-test (binary blob region round-trip). */
    {
        extern void binstore_selftest(void);
        binstore_selftest();
    }
    /* Arc B · zombie-table over-capacity self-test (runs before children
     * spawn · on an empty table · drains itself · evict-oldest never loses
     * the newest exit). */
    {
        extern void sotbox_reaper_selftest(void);
        sotbox_reaper_selftest();
    }
    /* C2 #10 · display-pid self-test · deterministic-by-design (fixed seed,
     * keyed on synthetic_pid) · the values below are stable across boots and the
     * ASLR/entropy stream is untouched.  Gate asserts the exact values. */
    {
        extern uint32_t sotos_pid_display(uint32_t synthetic_pid);
        printf("[pidrand] selftest · display(1)=%u display(2)=%u (deterministic · ASLR untouched)\n",
               sotos_pid_display(1), sotos_pid_display(2));
    }
    /* A2 PR2 · rwbinstore lazy-init (a fresh image = empty store · count=0). */
    {
        extern long rwbinstore_lookup(const char *name, uint64_t *offset_out);
        rwbinstore_lookup("", NULL);
    }
    /* A2 · rwbinstore write self-test (write a tiny blob, read it back). */
    {
        extern int  rwbinstore_write(const char *name, const void *bytes, size_t len);
        extern long rwbinstore_read(const char *name, void *buf, size_t cap);
        const char blob[4] = { 'R','W','B','T' };
        char rd[4] = {0};
        if (rwbinstore_write("__selftest", blob, 4) == 0 &&
            rwbinstore_read("__selftest", rd, 4) == 4 &&
            memcmp(blob, rd, 4) == 0) {
            printf("[rwbinstore] selftest OK · wrote+read 4 bytes 'RWBT'\n");
        } else {
            printf("[rwbinstore] selftest FAILED\n");
        }
    }
    /* Phase 1b · fs-gate scale + persistence self-test.  This is a NO-OP
     * unless the build defines SOTOS_FS_GATE (only tools/fs-gate.sh sets it);
     * every other gate links an empty fs_gate_selftest() so its boot is
     * unaffected.  Runs here, after lazy_init has brought the sotfs graph +
     * disk-backed blkdev up, and before Path D children spawn (so the persist
     * leg's simreboot suspend/respawn phases are no-ops). */
    {
        extern void fs_gate_selftest(void);
        fs_gate_selftest();
    }
    {
        /* sotNet-β-1: discover virtio-net on PCI bus 0.
         * sotNet-β-2: init virtqueues (RX + TX) when device is present.
         * sotNet-β-3: initialise minimal IP stack + drain RX for 200 cycles. */
        extern int  virtio_net_probe(void);
        extern int  virtio_net_present(void);
        extern int  virtio_net_init_queues(void);
        virtio_net_probe();
        if (virtio_net_present()) {
            if (virtio_net_init_queues() == 0) {
                /* IP = 10.0.2.15 in network byte order (little-endian storage
                 * of 0x0A00020F): bytes [0A 00 02 0F] → 0x0F02000A. */
                extern void sotnet_init(uint32_t our_ip_be);
                extern int  sotnet_poll(void);
                extern int  sotnet_dhcp_acquire_or_fallback(void);
                extern void tcp_timer_tick(void);
                sotnet_dhcp_acquire_or_fallback();
                for (int _i = 0; _i < 200; ++_i) {
                    sotnet_poll();
                    tcp_timer_tick();
                }
                extern struct tcp_conn *tcp_passive_open(uint16_t local_port_be);
                (void)tcp_passive_open(__builtin_bswap16(80));   /* N2 canary HTTP  */
                (void)tcp_passive_open(__builtin_bswap16(22));   /* N2 canary SSH   */
                (void)tcp_passive_open(__builtin_bswap16(443));  /* N2 canary HTTPS */
                printf("[orch] N2 inbound LISTEN · :80 :22 :443\n");
            }
        }
    }

    /* Bring the lwIP egress stack up.  orch_lwip_egress_init() SELF-SKIPS unless a
     * 2nd virtio-net is present, so normal single-NIC boots are untouched (zero
     * delay).  When a 2nd NIC is present it binds it + calibrates the TSC so the
     * socket demux (outbound connect → lwIP) is ready.  The standalone download
     * self-test is GATED behind OEG_BOOT_SELFTEST (it would add a transfer to boot);
     * egress is now exercised by the real demux (apk/apt). */
    {
        extern int  orch_lwip_egress_init(void);
        if (orch_lwip_egress_init() == 0) {
#ifdef OEG_BOOT_SELFTEST
            extern void orch_lwip_egress_test(void);
            orch_lwip_egress_test();
#endif
        }
    }

    /* sotNet-ε Phase 1 · seed the DNS canary domain table and confirm
     * the synth A record lookup path is wired.  The first call to
     * dns_lookup initialises the table and prints the seeded-count line;
     * the lookup itself prints '[dns] synth A record · ...' to prove
     * the deception path is live at bootstrap. */
    {
        uint32_t test_ip;
        /* DNS-PID-PREWORK · pid=0 (operator / bootstrap path · no sotbox context). */
        dns_lookup(0, "malicious-c2.example.", &test_ip);
    }

    /* C1 · state the deception policy once at boot so the serial output is
     * unambiguous: the installed bait is synthetic-by-design, real secrets are
     * untouched, and the lies are served only to promoted (Tier-2) sotboxes. */
    printf("[deception] policy · /canary-* + installed creds are SYNTHETIC canaries "
           "(tripwires) · real secrets untouched · silenced/shadow functors serve "
           "lies to Tier-2 sotboxes\n");

    /* OBSD-η · userland TPM 2.0 TIS driver + measured boot.
     *
     * tpm_init attempts to map MMIO at TPM_TIS_BASE (0xFED40000) via
     * vka_alloc_frame_at.  If root has not delegated a device untyped
     * covering that address, or if no TPM chip responds (ACCESS=0xFF),
     * tpm_init prints "[tpm] no device · measured boot disabled" and
     * returns -1.  Every subsequent tpm_* call then short-circuits.
     *
     * B-PCR · v0.23 measured-boot: we now hash REAL payloads with the
     * vendored sotos_sha256 (see src/sotos/sha256.c) and extend the
     * digests via tpm_pcr_extend_precomputed.  This replaces the v0.21
     * placeholders (literal string for PCR 8, zero-fill for PCR 9/10).
     *
     * Payload mapping for each PCR:
     *
     *   PCR 8  · orch image bytes
     *            We hash [__executable_start, _cpio_archive) — the
     *            orch's .text + .rodata + .data — followed by the
     *            embedded CPIO archive (_cpio_archive .. _cpio_archive_end).
     *            Together they cover every byte of the orch ELF that
     *            the elfloader baked in at link time.  The runtime-mutable
     *            .data is hashed at THIS point (early bootstrap), so the
     *            measurement captures the bootstrap-time state, not a
     *            later mutated state.  .bss is excluded (always zero at
     *            this point, no integrity signal).
     *
     *   PCR 9  · kernel image identity
     *            Direct hashing of the seL4 kernel image is NOT possible
     *            from inside orch: the kernel was loaded by elfloader and
     *            sits in memory the userland orch cannot map.  As a fallback
     *            we hash a deterministic kernel-identity blob built from:
     *              - the CPUID brand string (48 bytes)
     *              - the host CPUID family/model/stepping (12 bytes)
     *              - the seL4 protocol version reported by libsel4 (sizeof)
     *              - a fixed tag "sotOs-kernel-v0.23"
     *            A future patch can replace this with the real kernel ELF
     *            bytes once root forwards them via the BOOTSTRAP message
     *            (or via a kernel-image frame range delegated to orch).
     *
     *   PCR 10 · initrd / sotfs.img
     *            We hash the first 512 bytes of /dev/vda (sotfs.img sector 0)
     *            that we already read above for the virtio-blk smoke check.
     *            Hashing the entire image (32 MiB) would issue 65 536 single-
     *            sector virtio-blk reads at boot, each emitting a printf;
     *            sector 0 alone is a sufficient initrd-identity fingerprint
     *            for measured-boot purposes.  When the virtio-blk device is
     *            absent (or sector-0 read failed) we degrade to a zero-marker
     *            payload "sotOs-initrd-absent" so PCR 10 still reflects the
     *            absence rather than aliasing with another PCR.
     *
     * Graceful degrade: when tpm_init() returned -1 (no chip) we still
     * compute the SHA-256 digests and PRINT them so the operator sees what
     * would have been extended.  The TPM extend calls themselves become no-ops.
     */
    {
        int tpm_ok = (tpm_init() == 0);

        /* Linker-provided + CPIO bounds for the orch image.  We sweep the
         * entire range [__executable_start, _cpio_archive_end) — the seL4
         * elfloader maps that span as three contiguous PT_LOAD segments
         * (R+X .text, R .rodata, RW .data + ._archive_cpio).  Pages between
         * segment ends and the next page boundary are zero-filled by the
         * loader, so the hash is reproducible across builds with identical
         * sources. */
        extern char __executable_start[];
        extern char _cpio_archive_end[];

        const uint8_t *orch_lo  = (const uint8_t *)&__executable_start[0];
        const uint8_t *cpio_hi  = (const uint8_t *)&_cpio_archive_end[0];

        /* ─── PCR 8 · orch image (text + rodata + data + bundled CPIO) ───── */
        uint8_t digest8[TPM_PCR_SHA256_SIZE];
        {
            sotos_sha256_t ctx;
            sotos_sha256_init(&ctx);
            /* Chunked update over [orch_lo, cpio_hi) in 4 KiB strides so the
             * stack stays bounded (no large memcpy through stack).  The buffer
             * is read-only memory; sotos_sha256_update streams it directly. */
            const size_t chunk = 4096;
            size_t remaining = (size_t)(cpio_hi - orch_lo);
            const uint8_t *p = orch_lo;
            while (remaining > 0) {
                size_t n = remaining > chunk ? chunk : remaining;
                sotos_sha256_update(&ctx, p, n);
                p += n;
                remaining -= n;
            }
            sotos_sha256_final(&ctx, digest8);
            printf("[tpm] PCR 8 payload · %zu bytes (orch image-text + CPIO)\n",
                   (size_t)(cpio_hi - orch_lo));
        }

        /* ─── PCR 9 · kernel identity (synthetic · see comment above) ────── */
        uint8_t digest9[TPM_PCR_SHA256_SIZE];
        {
            uint8_t kid_blob[128];
            size_t  kid_len = 0;

            /* CPUID 0x80000002..0x80000004 → 48-byte brand string. */
            for (uint32_t leaf = 0x80000002u; leaf <= 0x80000004u; ++leaf) {
                uint32_t a, b, c, d;
                asm volatile("cpuid"
                             : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                             : "a"(leaf));
                if (kid_len + 16 <= sizeof(kid_blob)) {
                    __builtin_memcpy(kid_blob + kid_len +  0, &a, 4);
                    __builtin_memcpy(kid_blob + kid_len +  4, &b, 4);
                    __builtin_memcpy(kid_blob + kid_len +  8, &c, 4);
                    __builtin_memcpy(kid_blob + kid_len + 12, &d, 4);
                    kid_len += 16;
                }
            }
            /* CPUID 0x1 EAX = family/model/stepping. */
            {
                uint32_t a, b, c, d;
                asm volatile("cpuid"
                             : "=a"(a), "=b"(b), "=c"(c), "=d"(d)
                             : "a"(1));
                if (kid_len + 16 <= sizeof(kid_blob)) {
                    __builtin_memcpy(kid_blob + kid_len +  0, &a, 4);
                    __builtin_memcpy(kid_blob + kid_len +  4, &b, 4);
                    __builtin_memcpy(kid_blob + kid_len +  8, &c, 4);
                    __builtin_memcpy(kid_blob + kid_len + 12, &d, 4);
                    kid_len += 16;
                }
            }
            /* Fixed tag — bumps the digest whenever the sotOs major rev
             * changes, so PCR 9 alone distinguishes kernel releases. */
            const char tag[] = "sotOs-kernel-v0.23";
            size_t taglen = sizeof(tag) - 1;
            if (kid_len + taglen <= sizeof(kid_blob)) {
                __builtin_memcpy(kid_blob + kid_len, tag, taglen);
                kid_len += taglen;
            }
            sotos_sha256(kid_blob, kid_len, digest9);
            printf("[tpm] PCR 9 payload · %zu bytes (synthetic kernel identity)\n",
                   kid_len);
        }

        /* ─── PCR 10 · initrd / sotfs.img sector 0 ─────────────────────── */
        uint8_t digest10[TPM_PCR_SHA256_SIZE];
        {
            if (bs_sotfs_sector0_valid) {
                sotos_sha256(bs_sotfs_sector0, sizeof(bs_sotfs_sector0),
                             digest10);
                printf("[tpm] PCR 10 payload · 512 bytes (sotfs.img sector 0)\n");
            } else {
                const char absent[] = "sotOs-initrd-absent";
                sotos_sha256(absent, sizeof(absent) - 1, digest10);
                printf("[tpm] PCR 10 payload · sotfs absent · placeholder hashed\n");
            }
        }

        /* ─── Emit a 16-hex-char prefix log line per PCR ────────────────── */
        printf("[tpm] PCR 8 extended %02x%02x%02x%02x%02x%02x%02x%02x...\n",
               digest8[0], digest8[1], digest8[2], digest8[3],
               digest8[4], digest8[5], digest8[6], digest8[7]);
        printf("[tpm] PCR 9 extended %02x%02x%02x%02x%02x%02x%02x%02x...\n",
               digest9[0], digest9[1], digest9[2], digest9[3],
               digest9[4], digest9[5], digest9[6], digest9[7]);
        printf("[tpm] PCR 10 extended %02x%02x%02x%02x%02x%02x%02x%02x...\n",
               digest10[0], digest10[1], digest10[2], digest10[3],
               digest10[4], digest10[5], digest10[6], digest10[7]);

        if (tpm_ok) {
            if (tpm_pcr_extend_precomputed(TPM_PCR_ORCH_BOOTSTRAP, digest8) != 0) {
                printf("[tpm] PCR-%u extend FAILED\n", TPM_PCR_ORCH_BOOTSTRAP);
            }
            if (tpm_pcr_extend_precomputed(TPM_PCR_KERNEL_IMAGE,  digest9) != 0) {
                printf("[tpm] PCR-%u extend FAILED\n", TPM_PCR_KERNEL_IMAGE);
            }
            if (tpm_pcr_extend_precomputed(TPM_PCR_INITRD_SOTFS,  digest10) != 0) {
                printf("[tpm] PCR-%u extend FAILED\n", TPM_PCR_INITRD_SOTFS);
            }

            /* Report the resulting PCR values back to the operator. */
            uint8_t pcr8[TPM_PCR_SHA256_SIZE];
            uint8_t pcr9[TPM_PCR_SHA256_SIZE];
            uint8_t pcr10[TPM_PCR_SHA256_SIZE];
            int rc8  = tpm_pcr_read(TPM_PCR_ORCH_BOOTSTRAP, pcr8);
            int rc9  = tpm_pcr_read(TPM_PCR_KERNEL_IMAGE,   pcr9);
            int rc10 = tpm_pcr_read(TPM_PCR_INITRD_SOTFS,   pcr10);
            if (rc8 == 0) {
                printf("[tpm] PCR-%u=0x%02x%02x..%02x%02x\n",
                       TPM_PCR_ORCH_BOOTSTRAP,
                       pcr8[0], pcr8[1],
                       pcr8[TPM_PCR_SHA256_SIZE - 2],
                       pcr8[TPM_PCR_SHA256_SIZE - 1]);
            }
            if (rc9 == 0) {
                printf("[tpm] PCR-%u=0x%02x%02x..%02x%02x\n",
                       TPM_PCR_KERNEL_IMAGE,
                       pcr9[0], pcr9[1],
                       pcr9[TPM_PCR_SHA256_SIZE - 2],
                       pcr9[TPM_PCR_SHA256_SIZE - 1]);
            }
            if (rc10 == 0) {
                printf("[tpm] PCR-%u=0x%02x%02x..%02x%02x\n",
                       TPM_PCR_INITRD_SOTFS,
                       pcr10[0], pcr10[1],
                       pcr10[TPM_PCR_SHA256_SIZE - 2],
                       pcr10[TPM_PCR_SHA256_SIZE - 1]);
            }
        } else {
            printf("[tpm] graceful degrade · digests computed but not extended\n");
        }
    }

    return 0;
}

vka_t       *orch_vka(void)       { return &g_vka; }
allocman_t  *orch_allocman(void)  { return g_allocman; }
