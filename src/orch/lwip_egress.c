/*
 * sotOs · lwIP egress glue (spike).
 *
 * Bridges the vendored mature TCP/IP stack (liblwip + libethdrivers virtio_pci)
 * to orch's seL4 primitives, so OUTBOUND connections (apk/apt/pip) ride a
 * battle-tested stack instead of the hand-rolled δ busy-poll path.  The δ stack
 * stays for inbound deception (its crafted Linux SYN-ACK / JA3S fingerprint).
 *
 * What this file provides (the "DMA glue"):
 *   - ps_io_port_ops over orch's full-range x86 IOPort cap (legacy virtio regs).
 *   - ps_dma_man over vka + SEL4UTILS_PD_SLOT mapping: dma_alloc batches 4 KiB
 *     frames, verifies they landed physically contiguous (QEMU derives the vring
 *     avail/used offsets from one PFN), maps them contiguously into orch's
 *     vspace, and records virt↔phys so dma_pin returns the device-visible paddr.
 *     Mirrors the proven contiguity pattern in src/sotfs/storage_virtio_net.c.
 *   - sys_now() (TSC→ms, approximate) for lwIP's TCP timers (NO_SYS + LWIP_TIMERS).
 *
 * NOT auto-run: orch_lwip_egress_init() must be called explicitly (a later task
 * wires it + a dedicated 2nd virtio-net so it doesn't fight the δ stack on one
 * NIC).  orch_lwip_egress_test() does a raw-API GET to prove an egress download.
 */

#include <sel4/sel4.h>
#include <sel4/arch/syscalls.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>      /* SEL4UTILS_PD_SLOT */
#include <sel4utils/vspace.h>       /* VSPACE_MAP_PAGING_OBJECTS */
#include <platsupport/io.h>
#include <ethdrivers/raw.h>
#include <ethdrivers/lwip.h>
#include <ethdrivers/virtio_pci.h>
#include <lwip/init.h>
#include <lwip/netif.h>
#include <lwip/tcp.h>
#include <lwip/timeouts.h>
#include <lwip/ip4_addr.h>
#include <netif/etharp.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

extern vka_t    *orch_vka(void);
extern seL4_CPtr orch_get_io_port_cap(void);
extern uint32_t  virtio_net_bar0(void);     /* legacy I/O BAR of the 1st (δ) NIC */
extern int       virtio_net_present(void);
extern uint32_t  sotos_pci_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off);

/* lwIP must NOT fight the δ stack over one NIC.  Find the SECOND virtio-net-pci
 * (vendor 0x1af4, legacy device 0x1000) on bus 0 and return its I/O BAR base; the
 * δ stack owns the first.  0 if there is no second NIC (→ egress self-test skips,
 * so normal single-NIC boots are unaffected). */
static uint16_t oeg_second_virtio_net_iobase(void)
{
    int seen = 0;
    for (int dev = 0; dev < 32; ++dev) {
        for (int func = 0; func < 8; ++func) {
            uint32_t vd = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0);
            if ((vd & 0xFFFF) != 0x1AF4) continue;
            if (((vd >> 16) & 0xFFFF) != 0x1000) continue;   /* legacy virtio-net */
            if (seen++ == 0) continue;                        /* skip the δ NIC */
            uint32_t bar0 = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0x10);
            uint32_t intr = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0x3C);
            printf("[lwip-egress] 2nd virtio-net @0:%d.%d · BAR0=0x%x · IRQ line=%u pin=%u\n",
                   dev, func, bar0, (unsigned)(intr & 0xFF), (unsigned)((intr >> 8) & 0xFF));
            return (uint16_t)(bar0 & 0xFFFCu);
        }
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* ps_io_port_ops · over orch's full-range (0x0000-0xFFFF) IOPort cap. */
/* ------------------------------------------------------------------ */
static int oeg_io_in(void *cookie, uint32_t port, int io_size, uint32_t *result)
{
    (void)cookie;
    seL4_CPtr cap = orch_get_io_port_cap();
    switch (io_size) {
    case 1: { seL4_X86_IOPort_In8_t  r = seL4_X86_IOPort_In8(cap, (uint16_t)port);
              if (r.error) return -1; *result = r.result; return 0; }
    case 2: { seL4_X86_IOPort_In16_t r = seL4_X86_IOPort_In16(cap, (uint16_t)port);
              if (r.error) return -1; *result = r.result; return 0; }
    case 4: { seL4_X86_IOPort_In32_t r = seL4_X86_IOPort_In32(cap, (uint16_t)port);
              if (r.error) return -1; *result = r.result; return 0; }
    default: return -1;
    }
}
static int oeg_io_out(void *cookie, uint32_t port, int io_size, uint32_t val)
{
    (void)cookie;
    seL4_CPtr cap = orch_get_io_port_cap();
    switch (io_size) {
    case 1: seL4_X86_IOPort_Out8 (cap, (uint16_t)port, (uint8_t)val);  return 0;
    case 2: seL4_X86_IOPort_Out16(cap, (uint16_t)port, (uint16_t)val); return 0;
    case 4: seL4_X86_IOPort_Out32(cap, (uint16_t)port, val);           return 0;
    default: return -1;
    }
}

/* ------------------------------------------------------------------ */
/* ps_dma_man · vka frames + PD-slot mapping, contiguity-verified.     */
/* ------------------------------------------------------------------ */
#define OEG_DMA_VBASE       0x30000000UL   /* free orch vaddr window (above the δ virtio 0x29M-0x2DM) */
#define OEG_DMA_MAX_REGIONS 16
#define OEG_DMA_MAX_FRAMES  224            /* ≥ 512 KiB lwIP heap (128 pg) + vrings + margin */

/* lwIP's RAM heap, placed in DMA-pinnable memory (see lwipopts.h
 * LWIP_RAM_HEAP_POINTER + MEMP_MEM_MALLOC).  Set before lwip_init. */
unsigned char *oeg_lwip_heap = NULL;

typedef struct { uintptr_t vaddr; size_t first_frame; size_t npages; int contig; int in_use; } oeg_dma_region_t;
static oeg_dma_region_t g_oeg_regions[OEG_DMA_MAX_REGIONS];
static vka_object_t      g_oeg_frames[OEG_DMA_MAX_FRAMES];
static uintptr_t         g_oeg_frame_pa[OEG_DMA_MAX_FRAMES];   /* per-page paddr (heap need not be contiguous) */
static int               g_oeg_nframes = 0;
static uintptr_t         g_oeg_vbump   = OEG_DMA_VBASE;

/* ONE physically-contiguous 2 MiB page that backs EVERYTHING (lwIP heap + the
 * driver's vrings) via a bump allocator.  Contiguity is mandatory for both: the
 * vring (device derives avail/used from one PFN) AND the RX pbufs in the heap (a
 * straddling pbuf would DMA across a non-contiguous boundary).  A single large
 * page makes all of it contiguous; dma_pin is then a trivial linear map. */
static uintptr_t g_oeg_cbase = 0, g_oeg_cpa = 0, g_oeg_coff = 0, g_oeg_cend = 0;

static void *oeg_dma_alloc(void *cookie, size_t size, int align, int cached, ps_mem_flags_t flags)
{
    (void)cookie; (void)flags;
    /* Preferred path · bump from the single contiguous 2 MiB page (set up by
     * oeg_dma_init_contig).  Page-align every alloc (the vring needs 4 KiB / PFN
     * alignment regardless of the `align` arg) → all DMA is physically contiguous. */
    if (g_oeg_cbase) {
        uintptr_t off = (g_oeg_coff + 0xFFFu) & ~0xFFFUL;        /* 4 KiB align */
        uintptr_t need = (size + 0xFFFu) & ~0xFFFUL;
        if (g_oeg_cbase + off + need > g_oeg_cend) { printf("[lwip-dma] contig pool full (off=0x%lx need=0x%lx)\n",
                                                            (unsigned long)off, (unsigned long)need); return NULL; }
        uintptr_t v = g_oeg_cbase + off;
        g_oeg_coff = off + need;
        memset((void *)v, 0, need);
        return (void *)v;
    }
    vka_t *vka = orch_vka();
    size_t npages = (size + 0xFFFu) / 0x1000u;
    if (npages == 0) npages = 1;
    if (align > 0x1000) {           /* page-aligned base already covers ≤4K align (virtio vring align) */
        printf("[lwip-dma] align %d > 4K unsupported\n", align);
        return NULL;
    }
    if (g_oeg_nframes + (int)npages > OEG_DMA_MAX_FRAMES) { printf("[lwip-dma] out of frame budget\n"); return NULL; }

    int reg = -1;
    for (int i = 0; i < OEG_DMA_MAX_REGIONS; ++i) if (!g_oeg_regions[i].in_use) { reg = i; break; }
    if (reg < 0) { printf("[lwip-dma] out of regions\n"); return NULL; }

    int first = g_oeg_nframes;
    int contig = 1;
    uintptr_t vbase = g_oeg_vbump;
    /* Batch-allocate frames, capture each paddr, map each at consecutive vaddrs.
     * The region is contiguous in VIRTUAL always; physical contiguity is tracked
     * (dma_pin is per-page-correct either way).  Small allocs (the vring) almost
     * always land contiguous from a fresh untyped — required for the device, which
     * derives the avail/used rings from one PFN; we warn if a vring-sized alloc is
     * not contiguous.  The big lwIP heap does NOT need contiguity. */
    for (size_t i = 0; i < npages; ++i) {
        vka_object_t *fr = &g_oeg_frames[first + i];
        if (vka_alloc_frame(vka, seL4_PageBits, fr) != 0) { printf("[lwip-dma] alloc_frame fail\n"); return NULL; }
        seL4_X86_Page_GetAddress_t pa = seL4_X86_Page_GetAddress(fr->cptr);
        if (pa.error) { printf("[lwip-dma] GetAddress fail\n"); return NULL; }
        g_oeg_frame_pa[first + i] = (uintptr_t)pa.paddr;
        if (i > 0 && (uintptr_t)pa.paddr != g_oeg_frame_pa[first] + i * 0x1000u) contig = 0;

        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        int err = sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, fr->cptr,
                                     (void *)(vbase + i * 0x1000u), seL4_AllRights,
                                     cached ? 1 : 0, paging, &npaging);
        if (err) { printf("[lwip-dma] map_page @0x%lx err=%d\n", (unsigned long)(vbase + i * 0x1000u), err); return NULL; }
    }
    if (!contig && npages <= 4)   /* vring-sized + non-contiguous → device may misread */
        printf("[lwip-dma] WARN: %zu-page DMA region not physically contiguous\n", npages);
    memset((void *)vbase, 0, npages * 0x1000u);
    g_oeg_regions[reg] = (oeg_dma_region_t){ .vaddr = vbase, .first_frame = (size_t)first,
                                             .npages = npages, .contig = contig, .in_use = 1 };
    g_oeg_nframes += (int)npages;
    g_oeg_vbump   += npages * 0x1000u;
    return (void *)vbase;
}

static uintptr_t oeg_dma_pin(void *cookie, void *addr, size_t size)
{
    (void)cookie; (void)size;
    uintptr_t v = (uintptr_t)addr;
    if (g_oeg_cbase && v >= g_oeg_cbase && v < g_oeg_cend)   /* contiguous 2 MiB pool · linear */
        return g_oeg_cpa + (v - g_oeg_cbase);
    for (int i = 0; i < OEG_DMA_MAX_REGIONS; ++i) {
        oeg_dma_region_t *r = &g_oeg_regions[i];
        if (r->in_use && v >= r->vaddr && v < r->vaddr + r->npages * 0x1000u) {
            if (r->contig)   /* physically contiguous (e.g. the 2 MiB heap) → linear */
                return g_oeg_frame_pa[r->first_frame] + (v - r->vaddr);
            size_t page = (v - r->vaddr) >> 12;                  /* else per-page paddr lookup */
            return g_oeg_frame_pa[r->first_frame + page] + (v & 0xFFFu);
        }
    }
    return 0;   /* not found → pin fails */
}
static void oeg_dma_unpin(void *cookie, void *addr, size_t size) { (void)cookie; (void)addr; (void)size; }
static void oeg_dma_free(void *cookie, void *addr, size_t size)  { (void)cookie; (void)addr; (void)size; /* spike: leak (egress is long-lived) */ }
static void oeg_dma_cache_op(void *cookie, void *addr, size_t size, dma_cache_op_t op)
{ (void)cookie; (void)addr; (void)size; (void)op; /* x86: cache-coherent DMA, no-op */ }

/* Allocate a PHYSICALLY-CONTIGUOUS DMA region as a single 2 MiB large page.  The
 * lwIP heap MUST be contiguous: with MEMP_MEM_MALLOC the RX ring buffers are
 * PBUF_RAM from this heap and a ~1500 B pbuf can straddle a 4 KiB boundary; the
 * device DMAs `len` bytes linearly from the one dma_pin'd phys, so if the heap is
 * built from non-contiguous 4 KiB frames the part past the boundary lands in the
 * wrong physical page → silent RX corruption → bad TCP checksum → stall (the
 * intermittent ~270-415 KB stall — it tracked the run-to-run physical layout, not
 * heap size).  A 2 MiB page is one contiguous frame, so nothing straddles. */
static int oeg_dma_init_contig(void)
{
    vka_t *vka = orch_vka();
    vka_object_t *fr = &g_oeg_frames[g_oeg_nframes];
    if (vka_alloc_frame(vka, seL4_LargePageBits, fr) != 0) {   /* 2 MiB physically-contiguous frame */
        printf("[lwip-dma] 2 MiB frame alloc failed (no large untyped?) · 4 KiB fallback\n");
        return -1;
    }
    seL4_X86_Page_GetAddress_t pa = seL4_X86_Page_GetAddress(fr->cptr);
    if (pa.error) { printf("[lwip-dma] contig GetAddress fail\n"); return -1; }

    uintptr_t vbase = (g_oeg_vbump + 0x1FFFFFu) & ~0x1FFFFFUL;   /* 2 MiB-align the vaddr */
    vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
    int npaging = VSPACE_MAP_PAGING_OBJECTS;
    int err = sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, fr->cptr, (void *)vbase,
                                 seL4_AllRights, 1 /*cached*/, paging, &npaging);
    if (err) { printf("[lwip-dma] 2 MiB map @0x%lx err=%d\n", (unsigned long)vbase, err); return -1; }

    g_oeg_nframes += 1;
    g_oeg_vbump   = vbase + 0x200000u;
    g_oeg_cbase = vbase; g_oeg_cpa = (uintptr_t)pa.paddr; g_oeg_coff = 0; g_oeg_cend = vbase + 0x200000u;
    printf("[lwip-dma] contiguous 2 MiB DMA pool @0x%lx pa=0x%lx (heap + vrings)\n",
           (unsigned long)vbase, (unsigned long)pa.paddr);
    return 0;
}

/* ------------------------------------------------------------------ */
/* sys_now · lwIP time source (TSC → ms, approximate is fine for TCP). */
/* ------------------------------------------------------------------ */
static uint64_t g_oeg_tsc_per_ms = 2500000ull;   /* ~2.5 GHz default; refined at init if a freq is known */
uint32_t sys_now(void)
{
    uint64_t tsc = __builtin_ia32_rdtsc();
    return (uint32_t)(tsc / g_oeg_tsc_per_ms);
}

/* ------------------------------------------------------------------ */
/* Init + assembly.                                                    */
/* ------------------------------------------------------------------ */
static struct netif  g_oeg_netif;
static lwip_iface_t *g_oeg_iface = NULL;
static ps_io_ops_t   g_oeg_io_ops;
static int           g_oeg_up = 0;

int orch_lwip_egress_init(void)
{
    if (g_oeg_up) return 0;
    uint16_t io_base = oeg_second_virtio_net_iobase();
    if (io_base == 0) { printf("[lwip-egress] no 2nd virtio-net · egress self-test skipped\n"); return -1; }

    memset(&g_oeg_io_ops, 0, sizeof(g_oeg_io_ops));
    g_oeg_io_ops.io_port_ops = (ps_io_port_ops_t){ .cookie = NULL,
        .io_port_in_fn = oeg_io_in, .io_port_out_fn = oeg_io_out };
    g_oeg_io_ops.dma_manager = (ps_dma_man_t){ .cookie = NULL,
        .dma_alloc_fn = oeg_dma_alloc, .dma_free_fn = oeg_dma_free,
        .dma_pin_fn = oeg_dma_pin, .dma_unpin_fn = oeg_dma_unpin,
        .dma_cache_op_fn = oeg_dma_cache_op };
    /* malloc_ops: liblwip/the eth driver use plain malloc — provide muslc's. */
    extern int sel4platsupport_new_malloc_ops(ps_malloc_ops_t *ops);
    if (sel4platsupport_new_malloc_ops(&g_oeg_io_ops.malloc_ops) != 0) {
        printf("[lwip-egress] malloc_ops init failed\n"); return -1;
    }

    /* Place lwIP's RAM heap in DMA-pinnable memory BEFORE lwip_init (mem_init
     * reads LWIP_RAM_HEAP_POINTER == oeg_lwip_heap).  MEM_SIZE=128 KiB + slack for
     * the heap bookkeeping/alignment.  Contiguous (oeg_dma_alloc verifies). */
    (void)oeg_dma_init_contig();   /* set up the contiguous 2 MiB DMA pool (heap + vrings bump from it) */
    oeg_lwip_heap = (unsigned char *)oeg_dma_alloc(NULL, 0x84000, 0x1000, 1, 0);   /* 512 KiB heap + slack */
    if (!oeg_lwip_heap) { printf("[lwip-egress] lwIP heap alloc failed\n"); return -1; }
    if (!oeg_lwip_heap) { printf("[lwip-egress] lwIP heap dma_alloc failed (contiguity?)\n"); return -1; }

    lwip_init();

    ethif_virtio_pci_config_t cfg = {
        .io_base   = io_base,    /* the 2nd NIC's legacy I/O BAR (the δ stack owns the 1st) */
        .mmio_base = NULL,       /* legacy: I/O ports, no MMIO */
    };
    g_oeg_iface = ethif_new_lwip_driver(g_oeg_io_ops, &g_oeg_io_ops.dma_manager,
                                        ethif_virtio_pci_init, &cfg);
    if (!g_oeg_iface) { printf("[lwip-egress] ethif_new_lwip_driver failed\n"); return -1; }

    ip4_addr_t ip, mask, gw;
    IP4_ADDR(&ip,   10, 0, 2, 15);
    IP4_ADDR(&mask, 255, 255, 255, 0);
    IP4_ADDR(&gw,   10, 0, 2, 2);
    if (!netif_add(&g_oeg_netif, &ip, &mask, &gw, g_oeg_iface,
                   g_oeg_iface->ethif_init, ethernet_input)) {
        printf("[lwip-egress] netif_add failed\n"); return -1;
    }
    netif_set_default(&g_oeg_netif);
    netif_set_up(&g_oeg_netif);
    g_oeg_up = 1;
    printf("[lwip-egress] netif up · ip=10.0.2.15 · io_base=0x%x\n", cfg.io_base);

    /* TSC self-calibration · tight Wait-loop on the PIT (true 100 Hz / QEMU real
     * time): consume 100 ticks = 1.000 s wall-clock, rdtsc delta = real TSC freq.
     * No RX traffic yet, so every wake is a PIT tick (no coalescing).  Fixes
     * sys_now() (was a hard-coded 2.5 GHz guess) so lwIP's TCP timers run at the
     * right wall-clock rate. */
    {
        extern seL4_CPtr orch_lwip_irq_ntf(void);
        extern seL4_CPtr orch_lwip_pit_handler(void);
        seL4_CPtr ntf = orch_lwip_irq_ntf(), pit = orch_lwip_pit_handler();
        if (ntf && pit) {
            uint64_t t0 = __builtin_ia32_rdtsc();
            for (int t = 0; t < 100; ++t) {
                seL4_Word b = 0;
                do { seL4_Wait(ntf, &b); seL4_IRQHandler_Ack(pit); } while (!(b & 0x200UL));
            }
            uint64_t per_s = __builtin_ia32_rdtsc() - t0;   /* rdtsc ticks in 1.0 s */
            printf("[lwip-egress] TSC calibrated · %lu Hz (was assumed 2.5e9)\n",
                   (unsigned long)per_s);
            if (per_s > 100000000ull && per_s < 100000000000ull)
                g_oeg_tsc_per_ms = per_s / 1000;            /* fix sys_now() */
        }
    }
    return 0;
}

/* Pump: drain RX into lwIP + run TCP timers.  Call from orch's loop while egress
 * is live.  ethif_lwip_poll() runs the eth driver's raw_poll → feeds frames to
 * netif->input; the IRQ variant (ethif_lwip_handle_irq) hooks the virtio-net IRQ. */
void orch_lwip_egress_poll(void)
{
    if (!g_oeg_up || !g_oeg_iface) return;
    ethif_lwip_poll(g_oeg_iface);
    sys_check_timeouts();
}

/* Is the lwIP egress path up (netif bound)?  lucas's connect() uses this to
 * decide whether an outbound connection rides lwIP or the legacy δ stack. */
int orch_lwip_egress_up(void) { return g_oeg_up; }

/* ================================================================== */
/* Egress session API · the SOCKET DEMUX backend.                     */
/*                                                                    */
/* lucas routes an OUTBOUND connect()/send()/recv()/close() through   */
/* these when lwIP egress is up; INBOUND deception stays on the δ     */
/* stack.  Each session owns an lwIP PCB + a byte ring the recv       */
/* callback fills, drained by orch_lwip_egress_recv.  Single-threaded */
/* (orch), so no locking; the pump is the busy-poll (IRQ throughput   */
/* is the separate follow-up).                                        */
/* ================================================================== */
#define OEG_SESS_MAX   8
#define OEG_SESS_RING  65536u            /* per-session RX ring (power of two) */
typedef struct {
    struct tcp_pcb *pcb;
    int             state;               /* 0 connecting · 1 established · 2 closed/error */
    int             peer_fin;            /* peer sent FIN (drain ring, then EOF) */
    int             in_use;
    uint32_t        head, tail;          /* ring producer/consumer (mod OEG_SESS_RING) */
    uint8_t         ring[OEG_SESS_RING];
} oeg_session_t;
static oeg_session_t g_oeg_sess[OEG_SESS_MAX];

static inline uint32_t oeg_ring_used(const oeg_session_t *s){ return s->head - s->tail; }

/* One pump step.  If the 2nd NIC's IRQ is wired, BLOCK on its Notification so the
 * vCPU idles and QEMU's iothread gets the host CPU → inbound frames DMA in at line
 * rate (the throughput fix).  handle_irq reads the device ISR (deasserts level
 * INTx) + drains RX/TX; re-arm via IRQHandler_Ack.  No IRQ → busy-poll fallback.
 * Relies on immediate ACKs (oeg_sess_recv → tcp_output) so RX keeps flowing and the
 * blocking Wait keeps waking; an idle connection is the residual hang risk that a
 * timer-bound notification would close. */
static void oeg_pump_step(void)
{
    /* TIMER-BOUND blocking pump.  Block on the notification that BOTH the GSI-10 RX
     * IRQ and the PIT tick (~100 Hz, GSI 2) signal: the vCPU idles → QEMU's iothread
     * runs → RX lands at line rate (wakes measured 3-18 ms), AND the PIT guarantees
     * a wake at least every ~10 ms so raw_poll/complete_tx runs regularly — reclaims
     * the TX ring, keeps ACKs flowing, so it never deadlocks on a full TX ring (the
     * ~68 KB stall a pure RX-only blocking-Wait hit).  handle_irq reads the device
     * ISR (deasserts the level RX INTx) + raw_poll; then Ack both IRQs (RX is level,
     * PIT is edge — both need Ack to re-arm).  Falls back to busy-poll if the timer-
     * bound notification wasn't wired (no PIT). */
    extern seL4_CPtr orch_lwip_irq_ntf(void);
    extern seL4_CPtr orch_lwip_irq_handler(void);
    extern seL4_CPtr orch_lwip_pit_handler(void);
    seL4_CPtr ntf = orch_lwip_irq_ntf();
    seL4_CPtr pit = orch_lwip_pit_handler();
    if (ntf != 0 && pit != 0) {
        seL4_Word badge = 0;
        seL4_Wait(ntf, &badge);                   /* wakes on RX IRQ (0x100) OR PIT tick (0x200) */
        ethif_lwip_handle_irq(g_oeg_iface, 10);   /* ISR ack + complete_tx/rx + refill */
        sys_check_timeouts();
        seL4_CPtr h = orch_lwip_irq_handler();
        if (h)   seL4_IRQHandler_Ack(h);          /* re-arm the level RX IRQ */
        seL4_IRQHandler_Ack(pit);                 /* re-arm the edge PIT tick */
    } else {
        orch_lwip_egress_poll();                  /* no timer wired → busy-poll */
    }
}

static err_t oeg_sess_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
    oeg_session_t *s = (oeg_session_t *)arg;
    if (err != ERR_OK) { if (s) s->state = 2; if (p) pbuf_free(p); return ERR_OK; }
    if (p == NULL) { if (s) s->peer_fin = 1; return ERR_OK; }   /* peer half-closed */
    /* BACKPRESSURE · accept the segment ONLY if the whole pbuf fits in the ring.
     * If not, return ERR_MEM WITHOUT freeing or tcp_recved → lwIP keeps the pbuf
     * and redelivers it once recv() has drained the ring.  Dropping overflow +
     * tcp_recved'ing the full segment (the old behaviour) advanced the window past
     * bytes we discarded → stream corruption + a hard stall at one ring-fill (~64
     * KB).  With backpressure the advertised window tracks ring space, so the peer
     * never overruns us. */
    (void)pcb;
    /* FLOW CONTROL · buffer the segment but DO NOT tcp_recved here — the window is
     * reopened by orch_lwip_egress_recv as it actually DRAINS the ring, so the
     * advertised window tracks ring free space and the peer can never overrun the
     * ring (no drop, no double-free of refused pbufs).  The ring (64 KiB) ≥ TCP_WND
     * (35 KiB), so a full window always fits; ERR_MEM is a defensive backstop. */
    if ((OEG_SESS_RING - oeg_ring_used(s)) < p->tot_len)
        return ERR_MEM;            /* shouldn't happen given window ≤ ring · retry later */
    for (struct pbuf *q = p; q; q = q->next) {
        const uint8_t *src = (const uint8_t *)q->payload;
        for (uint16_t i = 0; i < q->len; ++i)
            s->ring[s->head++ & (OEG_SESS_RING - 1)] = src[i];
    }
    pbuf_free(p);
    return ERR_OK;
}

static err_t oeg_sess_connected(void *arg, struct tcp_pcb *pcb, err_t err)
{
    (void)pcb;
    oeg_session_t *s = (oeg_session_t *)arg;
    if (s) s->state = (err == ERR_OK) ? 1 : 2;
    return ERR_OK;
}

static void oeg_sess_err(void *arg, err_t err)
{
    (void)err;
    oeg_session_t *s = (oeg_session_t *)arg;
    if (s) { s->state = 2; s->pcb = NULL; }   /* lwIP already freed the pcb */
}

/* connect START → tcp_new + tcp_connect, return an opaque session handle in the
 * CONNECTING state (s->state==0) WITHOUT blocking.  A non-blocking client (apt's
 * http method SetNonBlock(true)s then connect()s expecting EINPROGRESS) drives the
 * handshake via poll(POLLOUT)/getsockopt — see orch_lwip_egress_poll_out/so_error.
 * addr_be/port_be are network byte order (as lucas already has them). */
void *orch_lwip_egress_connect_start(uint32_t addr_be, uint16_t port_be)
{
    if (!g_oeg_up) return NULL;
    oeg_session_t *s = NULL;
    for (int i = 0; i < OEG_SESS_MAX; ++i) if (!g_oeg_sess[i].in_use) { s = &g_oeg_sess[i]; break; }
    if (!s) { printf("[lwip-egress] no free session slot\n"); return NULL; }
    memset(s, 0, sizeof(*s));
    s->in_use = 1;
    s->pcb = tcp_new();
    if (!s->pcb) { s->in_use = 0; return NULL; }
    tcp_arg(s->pcb, s);
    tcp_recv(s->pcb, oeg_sess_recv);
    tcp_err(s->pcb, oeg_sess_err);
    ip4_addr_t dst; dst.addr = addr_be;            /* lwIP ip4 stores network order */
    if (tcp_connect(s->pcb, &dst, lwip_ntohs(port_be), oeg_sess_connected) != ERR_OK) {
        tcp_abort(s->pcb); s->in_use = 0; return NULL;
    }
    /* Drive the handshake with the IRQ-pump RIGHT HERE (same mechanism the blocking
     * connect uses — and which apk connects fast through) until ESTABLISHED or a
     * short bound.  Leaving the SYN to the first poll_out pump (which only runs after
     * the client's fcntl()+pselect6 gap) let the SYN-ACK go unprocessed → lwIP's
     * 1s/3s/6s SYN-retransmit backoff → connect resolved ~50 s late, tripping apt's
     * method watchdog (it abandons the URI: "Ign … InRelease").  Bounded so a genuinely
     * slow/real connect still returns promptly as EINPROGRESS (poll_out finishes it). */
    for (int i = 0; i < 400 && s->state == 0; ++i) oeg_pump_step();
    return s;                          /* state 1 = already established · 0 = EINPROGRESS */
}

/* connect (blocking) → start + pump until established/failed.  For a blocking
 * socket (apk's HTTP client) connect() must not return until ESTABLISHED. */
void *orch_lwip_egress_connect(uint32_t addr_be, uint16_t port_be)
{
    oeg_session_t *s = orch_lwip_egress_connect_start(addr_be, port_be);
    if (!s) return NULL;
    /* Pump until established/failed (blocks on the RX IRQ → the SYN-ACK wakes it). */
    for (long i = 0; i < 2000000L && s->state == 0; ++i) oeg_pump_step();
    if (s->state != 1) { if (s->pcb) tcp_abort(s->pcb); s->in_use = 0; return NULL; }
    return s;
}

/* poll(POLLOUT) on a connecting/connected lwIP-egress fd: pump the handshake until
 * it resolves, then report WRITABLE once established (or failed → writable so the
 * client's getsockopt(SO_ERROR) reads the error).  This is where a non-blocking
 * client's WaitFd(write)/select-for-connect blocks. */
int orch_lwip_egress_poll_out(void *handle)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use) return 1;
    for (long i = 0; i < 2000000L && s->state == 0; ++i) oeg_pump_step();
    return (s->state != 0) ? 1 : 0;
}

/* SO_ERROR for a lwIP-egress fd · 0 = connected/connecting-ok, ECONNREFUSED(111) =
 * the connect failed.  Pumps a bounded bit so a just-issued non-blocking connect
 * resolves before the client checks. */
int orch_lwip_egress_so_error(void *handle)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use) return 9 /*EBADF*/;
    for (long i = 0; i < 2000000L && s->state == 0; ++i) oeg_pump_step();
    return (s->state == 2) ? 111 /*ECONNREFUSED*/ : 0;
}

/* send → tcp_write + flush; pumps briefly so the peer ACK is processed. */
int64_t orch_lwip_egress_send(void *handle, const uint8_t *buf, uint32_t len)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use || s->state != 1 || !s->pcb) return -1;
    if (len == 0) return 0;
    uint32_t snd = tcp_sndbuf(s->pcb);
    if (len > snd) len = snd;                       /* bounded by the send window */
    if (len == 0) { for (int i = 0; i < 100000 && tcp_sndbuf(s->pcb) == 0; ++i) orch_lwip_egress_poll();
                    len = tcp_sndbuf(s->pcb); if (len == 0) return 0; }
    if (tcp_write(s->pcb, buf, (u16_t)len, TCP_WRITE_FLAG_COPY) != ERR_OK) return -1;
    tcp_output(s->pcb);   /* on the wire now; recv()'s blocking pump handles the reply */
    return (int64_t)len;
}

/* recv → drain the ring.  nonblock: return -11 (EAGAIN) immediately when no data
 * (a non-blocking event-loop client like apt's http method reads expecting EAGAIN
 * before it writes its request — a blocking recv would hang it).  blocking: pump
 * the RX IRQ until data / peer close.  0 = peer EOF, >0 = bytes, -11 = EAGAIN. */
int64_t orch_lwip_egress_recv(void *handle, uint8_t *buf, uint32_t len, int nonblock)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use) return -1;
    if (nonblock) {
        if (oeg_ring_used(s) == 0)
            /* EOF only on a real peer FIN / failed conn; EAGAIN while connecting
             * (state==0) or established-with-no-data-yet (state==1). */
            return (s->peer_fin || s->state == 2) ? 0 : -11 /*EAGAIN*/;
        /* else fall through and drain what's buffered */
    } else {
        /* Block on the RX IRQ until data arrives / peer closes (vCPU idles → QEMU
         * delivers at line rate).  Generous bound so a momentary gap isn't EOF. */
        for (long i = 0; i < 2000000L && oeg_ring_used(s) == 0 && !s->peer_fin && s->state == 1; ++i)
            oeg_pump_step();
    }
    uint32_t avail = oeg_ring_used(s);
    if (avail == 0) return 0;                        /* EOF (peer FIN / closed) */
    uint32_t n = (len < avail) ? len : avail;
    if (n > 0xFFFFu) n = 0xFFFFu;   /* tcp_recved takes a u16_t · drain ≤ 64 KiB per call */
    for (uint32_t i = 0; i < n; ++i) buf[i] = s->ring[s->tail++ & (OEG_SESS_RING - 1)];
    /* Reopen the receive window for exactly what we drained (deferred from the recv
     * callback) → the advertised window = ring free space → flow control, no overrun.
     * Flush the window-update ACK so the peer resumes promptly. */
    if (s->pcb) { tcp_recved(s->pcb, (u16_t)n); tcp_output(s->pcb); }
    return (int64_t)n;
}

/* poll(POLLIN) readiness for an lwIP-egress fd — a CHEAP, NON-pumping check (must
 * not block: it runs in the poll/select readiness scan, including for POLLOUT-only
 * polls).  readable = buffered data, a peer FIN, or a closed/failed conn — NOT while
 * still connecting (state==0).  The actual RX drive (pumping lwIP to receive the
 * response) happens in lucas_egress_poll_pump, which only blocks when the client is
 * waiting to READ. */
int orch_lwip_egress_poll_in(void *handle)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use) return 1;                  /* error → readable (recv yields -1) */
    return (oeg_ring_used(s) > 0 || s->peer_fin || s->state == 2) ? 1 : 0;
}

/* One non-blocking lwIP RX/TX drive step for an egress session (for the poll pump's
 * loop — drives the wire without the IRQ-blocking oeg_pump_step). */
void orch_lwip_egress_pump_once(void *handle)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use) return;
    orch_lwip_egress_poll();   /* raw_poll: complete_tx (flush queued GET) + RX + timers */
}

void orch_lwip_egress_close(void *handle)
{
    oeg_session_t *s = (oeg_session_t *)handle;
    if (!s || !s->in_use) return;
    if (s->pcb) {
        tcp_arg(s->pcb, NULL); tcp_recv(s->pcb, NULL); tcp_err(s->pcb, NULL);
        if (tcp_close(s->pcb) != ERR_OK) tcp_abort(s->pcb);
        for (int i = 0; i < 50000; ++i) orch_lwip_egress_poll();   /* flush the FIN */
    }
    s->in_use = 0;
}

/* ------------------------------------------------------------------ */
/* Self-test · raw-API GET to the host (10.0.2.2:8099, the local harness        */
/* server) over lwIP.  Proves the mature stack completes an egress download     */
/* that the δ stack stalled on.  Logs total bytes received.                     */
/* ------------------------------------------------------------------ */
/* Exercises the SESSION API (connect/send/recv/close) — the exact path lucas's
 * socket demux uses — so a green run proves the demux backend end to end. */
void orch_lwip_egress_test(void)
{
    if (!g_oeg_up) return;
    ip4_addr_t dst; IP4_ADDR(&dst, 10, 0, 2, 2);   /* dst.addr is network order */
    printf("[lwip-egress] TEST · session connect 10.0.2.2:8099 (APKINDEX)\n");
    void *s = orch_lwip_egress_connect(dst.addr, PP_HTONS(8099));
    if (!s) { printf("[lwip-egress] session connect FAILED\n"); return; }
    printf("[lwip-egress] session established · sending GET\n");
    static const char req[] =
        "GET /alpine/v3.20/main/x86_64/APKINDEX.tar.gz HTTP/1.0\r\nHost: 10.0.2.2\r\n\r\n";
    if (orch_lwip_egress_send(s, (const uint8_t *)req, sizeof(req) - 1) < 0) {
        printf("[lwip-egress] session send FAILED\n"); orch_lwip_egress_close(s); return;
    }
    uint32_t total = 0, logged = 0;
    static uint8_t rxb[4096];
    uint64_t t0 = __builtin_ia32_rdtsc();
    for (;;) {
        int64_t n = orch_lwip_egress_recv(s, rxb, sizeof(rxb), 0 /*blocking*/);
        if (n <= 0) break;                    /* 0 = EOF · <0 = error */
        total += (uint32_t)n;
        if (total - logged >= 65536) { logged = total;
            printf("[lwip-egress] session download · %u bytes\n", (unsigned)total); }
    }
    uint64_t ms = (__builtin_ia32_rdtsc() - t0) / g_oeg_tsc_per_ms;
    if (ms == 0) ms = 1;
    printf("[lwip-egress] *** DONE · total=%u bytes · %lu ms · %lu KB/s ***\n",
           (unsigned)total, (unsigned long)ms, (unsigned long)((uint64_t)total / ms));  /* B/ms = KB/s */
    orch_lwip_egress_close(s);
}
