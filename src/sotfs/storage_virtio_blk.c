/*
 * sotOs · sotFS-γ Phase 2b/2c/2d · virtio-blk PCI discovery + virtqueue I/O.
 *
 * Phase 2b: walks PCI bus 0 reading vendor/device IDs via legacy config-space
 * access through I/O ports 0xCF8 (CONFIG_ADDRESS) and 0xCFC (CONFIG_DATA).
 * Identifies the virtio-blk device (vendor 0x1AF4, device 0x1001 legacy /
 * 0x1042 modern).
 *
 * Phase 2c: sets up the virtqueue (split virtqueue, 256 descriptors as reported
 * by the device) and performs the first block read (sector 0) to validate the
 * full driver stack.
 *
 * Phase 2d: adds virtio_blk_write_sector + sotfs_storage_virtio_blk vtable
 * so the WAL can write to the persistent 4 MiB sotfs.img block device.
 *
 * Security note: the IOPort cap used here covers the FULL port range
 * (0x0000-0xFFFF).  TODO Phase 2d: tighten to sub-range 0xCF8-0xCFF
 * (PCI config space) + the virtio device's own I/O ports once BAR0
 * is known.  Documented as a future improvement.
 *
 * -------------------------------------------------------------------------
 * Legacy virtio-blk I/O port layout (relative to iobase = BAR0 & ~3):
 *
 *   0x00  32  Device Features
 *   0x04  32  Guest Features
 *   0x08  32  Queue Address (PFN = phys >> 12)
 *   0x0C  16  Queue Size
 *   0x0E  16  Queue Select
 *   0x10  16  Queue Notify
 *   0x12   8  Device Status
 *   0x13   8  ISR Status
 *   0x14+      Device-specific config (block capacity etc.)
 *
 * Device Status bits:
 *   ACKNOWLEDGE=1, DRIVER=2, DRIVER_OK=4
 *
 * Init sequence:
 *   1. Reset (write 0 to Device Status)
 *   2. ACKNOWLEDGE (write 1)
 *   3. DRIVER (write 3)
 *   4. Skip feature negotiation (write 0 to Guest Features)
 *   5. Set up virtqueue 0 (Queue Select=0, alloc queue, write PFN)
 *   6. DRIVER_OK (write 7)
 *
 * -------------------------------------------------------------------------
 * Queue memory layout (256-entry queue, device-reported size):
 *
 *   Page 0 (4 KiB): Descriptor table, 256 × 16 = 4096 bytes (exact fit)
 *   Page 1 (4 KiB): Available ring,  4 + 256×2 + 2 = 518 bytes
 *   Page 2 (4 KiB): Used ring (at 8 KiB from queue base): 4+256×8+2=2054 B
 *
 * All three pages must be PHYSICALLY CONTIGUOUS.  We allocate all required
 * frames first (NO mapping calls interleaved) to maximize the chance that
 * utspace_split gives us contiguous paddrs, then map them afterwards.
 * -------------------------------------------------------------------------
 */
#include <sel4/sel4.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <sel4utils/mapping.h>      /* sel4utils_map_page */
#include <sel4utils/process.h>      /* SEL4UTILS_PD_SLOT */
#include <vka/vka.h>
#include <vka/object.h>

extern seL4_CPtr orch_get_io_port_cap(void);
extern vka_t    *orch_vka(void);

/* Wall-clock reference for the request-completion timeout (see the poll loops).
 * An iteration-count timeout is host-speed-dependent; rdtsc gives a real-time
 * budget so a cold sector read/write (host page-cache miss) doesn't spuriously
 * time out on a fast KVM host.  0 on non-x86 → callers fall back to an iter cap. */
static inline uint64_t blk_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi; __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

#define PCI_CONFIG_ADDRESS  0xCF8u
#define PCI_CONFIG_DATA     0xCFCu

#define VIRTIO_VENDOR_ID    0x1AF4u
#define VIRTIO_BLK_LEGACY   0x1001u
#define VIRTIO_BLK_MODERN   0x1042u

uint32_t sotos_pci_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off)
{
    uint32_t addr = (uint32_t)(
        (1u << 31)
      | ((uint32_t)bus  << 16)
      | ((uint32_t)dev  << 11)
      | ((uint32_t)func <<  8)
      | ((uint32_t)off  & 0xFCu)
    );
    seL4_CPtr cap = orch_get_io_port_cap();
    if (cap == 0) return 0xFFFFFFFFu;
    seL4_X86_IOPort_Out32(cap, PCI_CONFIG_ADDRESS, addr);
    seL4_X86_IOPort_In32_t r = seL4_X86_IOPort_In32(cap, PCI_CONFIG_DATA);
    if (r.error) return 0xFFFFFFFFu;
    return r.result;
}

/* Backward-compat alias used internally. */
static inline uint32_t pci_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off)
{
    return sotos_pci_config_read32(bus, dev, func, off);
}

static struct {
    int     found;
    uint8_t bus, dev, func;
    uint16_t vendor, device;
    uint32_t bar0;
} g_virtio_blk = { 0, 0, 0, 0, 0, 0, 0 };

int virtio_blk_probe(void)
{
    printf("[virtio-blk] probing PCI bus 0 for virtio-blk (vendor=0x%X)...\n",
           VIRTIO_VENDOR_ID);
    int candidates = 0;
    /* Quick scan · bus 0 only · 32 devices × 8 functions.  Most modern QEMU
     * puts virtio-blk-pci at bus 0 device 3-5 depending on other PCI devices. */
    for (int dev = 0; dev < 32; ++dev) {
        for (int func = 0; func < 8; ++func) {
            uint32_t vd = pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0);
            if ((vd & 0xFFFFu) == 0xFFFFu) continue;   /* no device */
            uint16_t vendor = (uint16_t)(vd & 0xFFFFu);
            uint16_t device = (uint16_t)((vd >> 16) & 0xFFFFu);
            if (vendor == VIRTIO_VENDOR_ID) {
                ++candidates;
                printf("[virtio-blk] candidate 0:%d.%d · vendor=0x%X device=0x%X\n",
                       dev, func, vendor, device);
                if (device == VIRTIO_BLK_LEGACY || device == VIRTIO_BLK_MODERN) {
                    uint32_t bar0 = pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0x10);
                    g_virtio_blk.found  = 1;
                    g_virtio_blk.bus    = 0;
                    g_virtio_blk.dev    = (uint8_t)dev;
                    g_virtio_blk.func   = (uint8_t)func;
                    g_virtio_blk.vendor = vendor;
                    g_virtio_blk.device = device;
                    g_virtio_blk.bar0   = bar0;
                    printf("[virtio-blk] FOUND at 0:%d.%d · BAR0=0x%X · type=%s\n",
                           dev, func, bar0,
                           device == VIRTIO_BLK_LEGACY ? "legacy" : "modern");
                    return 0;
                }
            }
        }
    }
    printf("[virtio-blk] no virtio-blk found · %d virtio candidates total\n", candidates);
    return -1;
}

int virtio_blk_present(void) { return g_virtio_blk.found; }
uint32_t virtio_blk_bar0(void) { return g_virtio_blk.bar0; }

/* =========================================================================
 * Phase 2c · virtqueue setup and first block read
 * =========================================================================
 *
 * Queue size: 256 entries (device-reported, legacy read-only register).
 * Queue physical memory layout (3 contiguous 4 KiB pages):
 *
 *   paddr+0x0000 (page 0): Descriptor table  256×16 = 4096 bytes
 *   paddr+0x1000 (page 1): Available ring     4+256×2+2 = 518 bytes
 *   paddr+0x2000 (page 2): Used ring          4+256×8+2 = 2054 bytes
 *     (the used ring starts at paddr+0x2000 because legacy QUEUE_ALIGN=4096,
 *      and align(4096+518, 4096) = 0x2000)
 *
 * KEY: All frame vka_alloc_frame calls are done FIRST (in one batch),
 * THEN sel4utils_map_page is called.  This prevents PT-object allocations
 * from interleaving with frame allocations, maximising the chance that
 * utspace_split produces contiguous paddrs.
 * =========================================================================*/

/* DMA virtual address range: 0x29000000-0x2A000000.
 * Beyond orch_parent_vspace's bump range (0x20000000-0x28000000). */
#define VIRTIO_DMA_BASE  0x29000000UL
#define VIRTIO_DMA_LIMIT 0x2A000000UL

/* Total frames: 3 queue pages + 1 request page = 4 frames. */
#define DMA_TOTAL_FRAMES  4
#define QUEUE_FRAMES      3   /* pages 0..2 */
#define REQ_FRAME_IDX     3   /* page  3    */

static vka_object_t  g_dma_objs[DMA_TOTAL_FRAMES];
static uintptr_t     g_dma_paddrs[DMA_TOTAL_FRAMES];
static void         *g_dma_vaddrs[DMA_TOTAL_FRAMES];   /* set after mapping */

/* Convenience accessors. */
static void     *g_queue_vbase = NULL;   /* virtual base of queue (page 0 vaddr) */
static uintptr_t g_queue_pbase = 0;     /* physical base of queue (page 0 paddr) */
static void     *g_req_vaddr   = NULL;
static uintptr_t g_req_paddr   = 0;

/* Queue size as reported by the device. */
static uint16_t g_queue_size = 0;

static int g_virtio_inited = 0;

/* -----------------------------------------------------------------------
 * I/O port helpers
 * ----------------------------------------------------------------------- */
static uint16_t g_iobase = 0;   /* BAR0 & ~3 */

static void io_out8(uint16_t off, uint8_t v) {
    seL4_X86_IOPort_Out8(orch_get_io_port_cap(), (uint16_t)(g_iobase + off), v);
}
static void io_out16(uint16_t off, uint16_t v) {
    seL4_X86_IOPort_Out16(orch_get_io_port_cap(), (uint16_t)(g_iobase + off), v);
}
static void io_out32(uint16_t off, uint32_t v) {
    seL4_X86_IOPort_Out32(orch_get_io_port_cap(), (uint16_t)(g_iobase + off), v);
}
static uint8_t io_in8(uint16_t off) {
    seL4_X86_IOPort_In8_t r = seL4_X86_IOPort_In8(orch_get_io_port_cap(),
                                                    (uint16_t)(g_iobase + off));
    return r.error ? 0xFFu : (uint8_t)r.result;
}
static uint16_t io_in16(uint16_t off) {
    seL4_X86_IOPort_In16_t r = seL4_X86_IOPort_In16(orch_get_io_port_cap(),
                                                      (uint16_t)(g_iobase + off));
    return r.error ? 0xFFFFu : (uint16_t)r.result;
}

/* -----------------------------------------------------------------------
 * Virtqueue descriptor format
 * ----------------------------------------------------------------------- */
#define VIRTQ_DESC_F_NEXT  1u
#define VIRTQ_DESC_F_WRITE 2u

typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed)) virtq_desc_t;

/* -----------------------------------------------------------------------
 * virtio-blk request structure
 * ----------------------------------------------------------------------- */
#define VIRTIO_BLK_T_IN  0u   /* read from device */
#define VIRTIO_BLK_T_OUT 1u   /* write to device */

typedef struct {
    uint32_t type;
    uint32_t reserved;
    uint64_t sector;
    uint8_t  data[512];
    uint8_t  status;
} __attribute__((packed)) virtio_blk_req_t;

/* -----------------------------------------------------------------------
 * virtio_blk_init_queue
 * -----------------------------------------------------------------------
 * Two-phase DMA frame setup:
 *   Phase A: allocate ALL frames (no mapping) → contiguous paddrs.
 *   Phase B: map ALL frames into orch's address space.
 * Then: configure device registers, set DRIVER_OK.
 * ----------------------------------------------------------------------- */
int virtio_blk_init_queue(void)
{
    if (!g_virtio_blk.found) {
        printf("[virtio-blk] init_queue: device not found · skipping\n");
        return -1;
    }
    if (orch_get_io_port_cap() == 0) {
        printf("[virtio-blk] init_queue: no IOPort cap · skipping\n");
        return -1;
    }

    g_iobase = (uint16_t)(g_virtio_blk.bar0 & 0xFFFCu);
    printf("[virtio-blk] init_queue · iobase=0x%X\n", (unsigned)g_iobase);

    /* Step 1: Reset device. */
    io_out8(0x12, 0);

    /* Step 2+3: ACKNOWLEDGE | DRIVER. */
    io_out8(0x12, 1 | 2);

    /* Step 4: Skip feature negotiation (legacy minimal · write 0). */
    io_out32(0x04, 0);

    /* Step 5a: Select queue 0 and read its size. */
    io_out16(0x0E, 0);
    g_queue_size = io_in16(0x0C);
    printf("[virtio-blk] queue 0 size = %u\n", (unsigned)g_queue_size);
    if (g_queue_size == 0) {
        printf("[virtio-blk] queue size 0 · device unavailable\n");
        return -1;
    }

    /* Phase A: Allocate all DMA frames in one batch before ANY mapping.
     * This avoids PT-object allocations interleaving with frame allocations,
     * keeping the paddrs contiguous (utspace_split carves from the same UT). */
    vka_t *vka = orch_vka();
    for (int i = 0; i < DMA_TOTAL_FRAMES; ++i) {
        int err = vka_alloc_frame(vka, seL4_PageBits, &g_dma_objs[i]);
        if (err) {
            printf("[virtio-blk] vka_alloc_frame[%d] failed (err=%d)\n", i, err);
            return -1;
        }
        /* Get physical address immediately (before any other allocs). */
        seL4_X86_Page_GetAddress_t pa = seL4_X86_Page_GetAddress(g_dma_objs[i].cptr);
        if (pa.error) {
            printf("[virtio-blk] Page_GetAddress[%d] failed (err=%d)\n", i, pa.error);
            return -1;
        }
        g_dma_paddrs[i] = (uintptr_t)pa.paddr;
    }

    /* Verify queue frames 0..2 are physically contiguous. */
    {
        int ok = 1;
        for (int i = 1; i < QUEUE_FRAMES; ++i) {
            if (g_dma_paddrs[i] != g_dma_paddrs[0] + (uintptr_t)(i * 4096)) {
                ok = 0;
                printf("[virtio-blk] queue frame[%d] paddr=0x%lx not contiguous "
                       "(expected 0x%lx)\n",
                       i, (unsigned long)g_dma_paddrs[i],
                       (unsigned long)(g_dma_paddrs[0] + (uintptr_t)(i * 4096)));
            }
        }
        if (!ok) {
            printf("[virtio-blk] non-contiguous queue frames · virtqueue init failed\n");
            return -1;
        }
    }

    /* Phase B: Map all frames into orch's virtual address space.
     * We use a sequential bump range starting at VIRTIO_DMA_BASE. */
    uintptr_t vaddr = VIRTIO_DMA_BASE;
    for (int i = 0; i < DMA_TOTAL_FRAMES; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        int err = sel4utils_map_page(vka,
                                      SEL4UTILS_PD_SLOT,
                                      g_dma_objs[i].cptr,
                                      (void *)vaddr,
                                      seL4_AllRights,
                                      1 /* cacheable */,
                                      paging, &npaging);
        if (err) {
            printf("[virtio-blk] map_page[%d] @0x%lx failed (err=%d)\n",
                   i, vaddr, err);
            return -1;
        }
        g_dma_vaddrs[i] = (void *)vaddr;
        memset((void *)vaddr, 0, 4096);
        vaddr += 4096;
    }

    /* Set up accessors. */
    g_queue_vbase = g_dma_vaddrs[0];
    g_queue_pbase = g_dma_paddrs[0];
    g_req_vaddr   = g_dma_vaddrs[REQ_FRAME_IDX];
    g_req_paddr   = g_dma_paddrs[REQ_FRAME_IDX];

    printf("[virtio-blk] queue · vbase=%p pbase=0x%lx\n",
           g_queue_vbase, (unsigned long)g_queue_pbase);
    printf("[virtio-blk] req   · vaddr=%p paddr=0x%lx\n",
           g_req_vaddr, (unsigned long)g_req_paddr);

    /* Step 5d: Write queue PFN to device.
     * Legacy virtio uses QUEUE_ALIGN = 4096 for the used ring.
     * For queue_size=256:
     *   Descriptor table: [pbase+0x0000 .. pbase+0x0FFF] = page 0
     *   Available ring:   [pbase+0x1000 .. pbase+0x1205] = page 1
     *   Used ring:        [pbase+0x2000 .. pbase+0x2805] = page 2 */
    uint32_t pfn = (uint32_t)(g_queue_pbase >> 12);
    io_out32(0x08, pfn);

    /* Step 6: DRIVER_OK. */
    io_out8(0x12, 1 | 2 | 4);
    printf("[virtio-blk] init done · DRIVER_OK set\n");

    g_virtio_inited = 1;
    return 0;
}

/* -----------------------------------------------------------------------
 * virtio_blk_read_sector
 * -----------------------------------------------------------------------
 * Submits a 3-descriptor chain to virtqueue 0 to read one 512-byte sector.
 * Polls the status byte with a 100M iteration bound.
 *
 * Descriptor chain:
 *   desc[0]: req header (type + reserved + sector, 16 bytes) · NEXT
 *   desc[1]: data buffer (512 bytes)                         · NEXT | WRITE
 *   desc[2]: status byte (1 byte)                            · WRITE
 *
 * Queue memory layout for 256-entry queue:
 *   Descriptor table at g_queue_vbase+0x0000 (256 × 16 = 4096 bytes)
 *   Available ring   at g_queue_vbase+0x1000 (= pbase + queue_size*16)
 *   Used ring        at g_queue_vbase+0x2000 (= pbase + align(1000+518,4096))
 *
 * Returns 0 on success, -1 on timeout/error.
 * ----------------------------------------------------------------------- */
int virtio_blk_read_sector(uint64_t sector, void *out_buf)
{
    if (!g_virtio_inited) {
        printf("[virtio-blk] read_sector: not initialised\n");
        return -1;
    }

    /* Initialise request struct in DMA memory. */
    virtio_blk_req_t *req = (virtio_blk_req_t *)g_req_vaddr;
    req->type     = VIRTIO_BLK_T_IN;
    req->reserved = 0;
    req->sector   = sector;
    memset(req->data, 0, 512);
    req->status   = 0xFF;   /* anomaly · device writes 0 on success */

    /* Build descriptor table in queue page 0.
     * desc[0]: request header (type=4B + reserved=4B + sector=8B = 16 bytes).
     * desc[1]: data buffer (512 bytes, device writes here).
     * desc[2]: status byte (device writes 0 on success). */
    virtq_desc_t *descs = (virtq_desc_t *)g_queue_vbase;

    descs[0].addr  = (uint64_t)(g_req_paddr + offsetof(virtio_blk_req_t, type));
    descs[0].len   = 16;   /* type(4) + reserved(4) + sector(8) */
    descs[0].flags = VIRTQ_DESC_F_NEXT;
    descs[0].next  = 1;

    descs[1].addr  = (uint64_t)(g_req_paddr + offsetof(virtio_blk_req_t, data));
    descs[1].len   = 512;
    descs[1].flags = VIRTQ_DESC_F_NEXT | VIRTQ_DESC_F_WRITE;
    descs[1].next  = 2;

    descs[2].addr  = (uint64_t)(g_req_paddr + offsetof(virtio_blk_req_t, status));
    descs[2].len   = 1;
    descs[2].flags = VIRTQ_DESC_F_WRITE;
    descs[2].next  = 0;

    /* Available ring: located at queue_vbase + queue_size * 16 bytes.
     * For queue_size=256: offset = 256 * 16 = 4096 bytes = start of page 1.
     *
     * Available ring layout:
     *   uint16  flags      avail[0]
     *   uint16  idx        avail[1]
     *   uint16  ring[256]  avail[2..257]
     *   uint16  used_event avail[258]
     */
    uintptr_t avail_vaddr = (uintptr_t)g_queue_vbase +
                             (uintptr_t)g_queue_size * sizeof(virtq_desc_t);
    volatile uint16_t *avail = (volatile uint16_t *)avail_vaddr;

    uint16_t prev_idx = avail[1];
    avail[2 + (prev_idx % g_queue_size)] = 0;   /* desc chain head = desc 0 */

    /* Compiler + CPU memory barrier before bumping idx. */
    __asm__ volatile("" ::: "memory");

    avail[1] = (uint16_t)(prev_idx + 1);

    /* Another barrier before notifying the device. */
    __asm__ volatile("" ::: "memory");

    /* Notify queue 0. */
    io_out16(0x10, 0);

    /* Poll req->status with a 100M iteration timeout.
     * Volatile pointer prevents the compiler from caching the read.
     * The device writes the status byte last, so once it changes from
     * 0xFF the operation has completed. */
    volatile uint8_t *status_p = (volatile uint8_t *)&req->status;
    /* WALL-CLOCK completion timeout + host-CPU yield.  A pure tight spin never
     * VM-exits, so QEMU's iothread (which DMAs the data + writes status) is
     * starved → a cold/slow sector times out with status stuck at 0xFF (the
     * gtk3-demo libz read / the relocated-rwbinstore write hit this).  Two fixes:
     *  (1) re-notify queue 0 every ~4K spins — a PIO → VM-exit that lets the
     *      iothread run; idempotent (avail.idx unchanged → device finds no work).
     *  (2) time out on REAL TIME (rdtsc, ~2 s), not an iteration count: 100M
     *      tight spins is only ~10-50 ms on a fast KVM host — too short for a
     *      cold read (host page-cache miss → real disk I/O).  Same starvation
     *      class as the watch+SSH netstack fix. */
    uint64_t spin = 0, t0 = blk_rdtsc();
    while (*status_p == 0xFF) {
        if ((++spin & 0xFFFu) == 0) {
            io_out16(0x10, 0);                                   /* re-notify · VM-exit */
            if (t0) { if (blk_rdtsc() - t0 > 5000000000ULL) break; }  /* ~2 s @ 2.4 GHz */
            else    { if (spin > 400000000ULL)            break; }    /* non-x86 backstop */
        }
    }

    if (*status_p == 0xFF) {
        printf("[virtio-blk] read sector %lu TIMEOUT · status still 0xFF\n",
               (unsigned long)sector);
        return -1;
    }

    if (*status_p != 0) {
        printf("[virtio-blk] read sector %lu FAILED · status=%u\n",
               (unsigned long)sector, (unsigned)*status_p);
        return -1;
    }

    /* Success. */
    if (out_buf) memcpy(out_buf, req->data, 512);

    /* PR 8 · throttle the per-sector debug trace · was unconditional
     * in PR 2-3 which made the 10x simreboot stress run blow the
     * smoke budget (each cascade replay = 24k sector reads = 22s of
     * serial bandwidth).  Log only the first 16 reads of each boot
     * so the virtio-blk path remains observable but the cascade is
     * not serial-bound during stress.  A future PR can wire this to
     * a verbose flag · the call site is otherwise unchanged. */
    static uint32_t s_read_log_budget = 16;
    if (s_read_log_budget > 0) {
        s_read_log_budget--;
        printf("[virtio-blk] read sector %lu OK · first 16 bytes:",
               (unsigned long)sector);
        for (int i = 0; i < 16; ++i)
            printf(" %02x", (unsigned)req->data[i]);
        printf("\n");
    }

    return 0;
}

/* -----------------------------------------------------------------------
 * virtio_blk_write_sector
 * -----------------------------------------------------------------------
 * Submits a 3-descriptor chain to virtqueue 0 to write one 512-byte sector.
 * Mirrors read_sector but with VIRTIO_BLK_T_OUT (1) and data descriptor
 * has NO WRITE flag (device reads our buffer instead of writing to it).
 *
 * Descriptor chain:
 *   desc[0]: req header (type + reserved + sector, 16 bytes) · NEXT
 *   desc[1]: data buffer (512 bytes, host reads from us)      · NEXT
 *   desc[2]: status byte (device writes 0 on success)         · WRITE
 *
 * Returns 0 on success, -1 on timeout/error.
 * ----------------------------------------------------------------------- */
int virtio_blk_write_sector(uint64_t sector, const void *buf)
{
    if (!g_virtio_inited) {
        printf("[virtio-blk] write_sector: not initialised\n");
        return -1;
    }

    /* Initialise request struct in DMA memory. */
    virtio_blk_req_t *req = (virtio_blk_req_t *)g_req_vaddr;
    req->type     = VIRTIO_BLK_T_OUT;
    req->reserved = 0;
    req->sector   = sector;
    if (buf) memcpy(req->data, buf, 512);
    req->status   = 0xFF;   /* anomaly · device writes 0 on success */

    /* Build descriptor table in queue page 0.
     * desc[0]: request header (type=4B + reserved=4B + sector=8B = 16 bytes).
     * desc[1]: data buffer (512 bytes, device reads from us - NO WRITE flag).
     * desc[2]: status byte (device writes 0 on success - WRITE flag). */
    virtq_desc_t *descs = (virtq_desc_t *)g_queue_vbase;

    descs[0].addr  = (uint64_t)(g_req_paddr + offsetof(virtio_blk_req_t, type));
    descs[0].len   = 16;
    descs[0].flags = VIRTQ_DESC_F_NEXT;
    descs[0].next  = 1;

    descs[1].addr  = (uint64_t)(g_req_paddr + offsetof(virtio_blk_req_t, data));
    descs[1].len   = 512;
    descs[1].flags = VIRTQ_DESC_F_NEXT;   /* NO WRITE flag · device reads from us */
    descs[1].next  = 2;

    descs[2].addr  = (uint64_t)(g_req_paddr + offsetof(virtio_blk_req_t, status));
    descs[2].len   = 1;
    descs[2].flags = VIRTQ_DESC_F_WRITE;
    descs[2].next  = 0;

    /* Available ring at queue_vbase + queue_size * sizeof(virtq_desc_t). */
    uintptr_t avail_vaddr = (uintptr_t)g_queue_vbase +
                             (uintptr_t)g_queue_size * sizeof(virtq_desc_t);
    volatile uint16_t *avail = (volatile uint16_t *)avail_vaddr;

    uint16_t prev_idx = avail[1];
    avail[2 + (prev_idx % g_queue_size)] = 0;

    __asm__ volatile("" ::: "memory");
    avail[1] = (uint16_t)(prev_idx + 1);
    __asm__ volatile("" ::: "memory");

    /* Notify queue 0. */
    io_out16(0x10, 0);

    /* Poll req->status with a 100M iteration timeout. */
    volatile uint8_t *status_p = (volatile uint8_t *)&req->status;
    /* WALL-CLOCK completion timeout + host-CPU yield.  A pure tight spin never
     * VM-exits, so QEMU's iothread (which DMAs the data + writes status) is
     * starved → a cold/slow sector times out with status stuck at 0xFF (the
     * gtk3-demo libz read / the relocated-rwbinstore write hit this).  Two fixes:
     *  (1) re-notify queue 0 every ~4K spins — a PIO → VM-exit that lets the
     *      iothread run; idempotent (avail.idx unchanged → device finds no work).
     *  (2) time out on REAL TIME (rdtsc, ~2 s), not an iteration count: 100M
     *      tight spins is only ~10-50 ms on a fast KVM host — too short for a
     *      cold read (host page-cache miss → real disk I/O).  Same starvation
     *      class as the watch+SSH netstack fix. */
    uint64_t spin = 0, t0 = blk_rdtsc();
    while (*status_p == 0xFF) {
        if ((++spin & 0xFFFu) == 0) {
            io_out16(0x10, 0);                                   /* re-notify · VM-exit */
            if (t0) { if (blk_rdtsc() - t0 > 5000000000ULL) break; }  /* ~2 s @ 2.4 GHz */
            else    { if (spin > 400000000ULL)            break; }    /* non-x86 backstop */
        }
    }

    if (*status_p == 0xFF) {
        printf("[virtio-blk] write sector %lu TIMEOUT · status still 0xFF\n",
               (unsigned long)sector);
        return -1;
    }

    if (*status_p != 0) {
        printf("[virtio-blk] write sector %lu FAILED · status=%u\n",
               (unsigned long)sector, (unsigned)*status_p);
        return -1;
    }

    return 0;
}

/* =========================================================================
 * Phase 2d · sotfs_storage_virtio_blk vtable
 *
 * Wraps virtio_blk_read_sector / virtio_blk_write_sector into the
 * sotfs_storage_ops_t interface used by the WAL.  Handles arbitrary
 * (offset, len) via sector-aligned R/M/W for partial sectors at the
 * head/tail of a transfer, and full-sector pass-through for aligned
 * middle ranges.
 * =========================================================================*/
#include <sotfs/wal.h>      /* sotfs_storage_t, sotfs_storage_ops_t */
#include <sotfs/layout.h>   /* SOTFS_IMG_TOTAL_BYTES · single source of truth */
#include <sotfs/storage_virtio_blk.h>  /* A2 · vblk_write_block prototype */

#define VBLK_SECTOR_SIZE 512u
/* SP2 · capacity tracks the image size (layout.h · single source of truth)
 * so the WAL at the image tail stays addressable as regions grow (now
 * 128 MiB · stdlib + binstore + sysroot + rwbinstore + WAL). */
#define VBLK_CAPACITY    (SOTFS_IMG_TOTAL_BYTES)

static uint8_t g_sector_buf[VBLK_SECTOR_SIZE];   /* scratch for RMW */

int vblk_write_block(void *backend, uint64_t offset, const void *buf, size_t len)
{
    (void)backend;
    if (offset + len > VBLK_CAPACITY) return -28;  /* ENOSPC */

    uint64_t       sector    = offset / VBLK_SECTOR_SIZE;
    uint64_t       off_in_s  = offset % VBLK_SECTOR_SIZE;
    size_t         remaining = len;
    const uint8_t *p         = (const uint8_t *)buf;

    /* Leading partial sector: RMW. */
    if (off_in_s != 0) {
        if (virtio_blk_read_sector(sector, g_sector_buf) != 0) return -5;
        size_t can = VBLK_SECTOR_SIZE - (size_t)off_in_s;
        if (can > remaining) can = remaining;
        memcpy(g_sector_buf + off_in_s, p, can);
        if (virtio_blk_write_sector(sector, g_sector_buf) != 0) return -5;
        p         += can;
        remaining -= can;
        sector++;
    }

    /* Full sectors: direct write. */
    while (remaining >= VBLK_SECTOR_SIZE) {
        if (virtio_blk_write_sector(sector, p) != 0) return -5;
        p         += VBLK_SECTOR_SIZE;
        remaining -= VBLK_SECTOR_SIZE;
        sector++;
    }

    /* Trailing partial sector: RMW. */
    if (remaining > 0) {
        if (virtio_blk_read_sector(sector, g_sector_buf) != 0) return -5;
        memcpy(g_sector_buf, p, remaining);
        if (virtio_blk_write_sector(sector, g_sector_buf) != 0) return -5;
    }

    return (int)len;
}

static int vblk_read_block(void *backend, uint64_t offset, void *buf, size_t len)
{
    (void)backend;
    if (offset + len > VBLK_CAPACITY) return -22;  /* EINVAL */

    uint64_t  sector    = offset / VBLK_SECTOR_SIZE;
    uint64_t  off_in_s  = offset % VBLK_SECTOR_SIZE;
    size_t    remaining = len;
    uint8_t  *p         = (uint8_t *)buf;

    /* Leading partial sector. */
    if (off_in_s != 0) {
        if (virtio_blk_read_sector(sector, g_sector_buf) != 0) return -5;
        size_t can = VBLK_SECTOR_SIZE - (size_t)off_in_s;
        if (can > remaining) can = remaining;
        memcpy(p, g_sector_buf + off_in_s, can);
        p         += can;
        remaining -= can;
        sector++;
    }

    /* Full sectors. */
    while (remaining >= VBLK_SECTOR_SIZE) {
        if (virtio_blk_read_sector(sector, p) != 0) return -5;
        p         += VBLK_SECTOR_SIZE;
        remaining -= VBLK_SECTOR_SIZE;
        sector++;
    }

    /* Trailing partial sector. */
    if (remaining > 0) {
        if (virtio_blk_read_sector(sector, g_sector_buf) != 0) return -5;
        memcpy(p, g_sector_buf, remaining);
    }

    return (int)len;
}

static int vblk_flush(void *backend)
{
    (void)backend;
    /* VIRTIO_BLK_T_FLUSH (4) skipped for Phase 2d minimal. */
    return 0;
}

static uint64_t vblk_capacity_bytes(void *backend)
{
    (void)backend;
    return VBLK_CAPACITY;
}

static const sotfs_storage_ops_t vblk_ops = {
    .write_block    = vblk_write_block,
    .read_block     = vblk_read_block,
    .flush          = vblk_flush,
    .capacity_bytes = vblk_capacity_bytes,
};

sotfs_storage_t sotfs_storage_virtio_blk(void)
{
    return (sotfs_storage_t) {
        .ops           = &vblk_ops,
        .backend_state = NULL,
    };
}

int sotfs_storage_virtio_blk_ready(void)
{
    return virtio_blk_present() && (g_queue_vbase != NULL);
}
