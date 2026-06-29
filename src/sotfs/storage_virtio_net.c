/*
 * sotOs · sotNet-β-1 · virtio-net PCI discovery.
 * sotOs · sotNet-β-2 · virtio-net device init + RX/TX virtqueue setup.
 *
 * β-1: Walks PCI bus 0 looking for vendor=0x1AF4 device=0x1000 (legacy)
 * or device=0x1041 (modern).  Records BAR0 + IRQ line for later
 * phases (virtqueue setup, raw frame TX/RX, IP stack).
 *
 * β-2: virtio_net_init_queues() sets up the device (Reset → ACK → DRIVER
 * → feature negotiation skip → DRIVER_OK), reads the MAC address from
 * config space (6 bytes at BAR0 + 0x14), allocates frames for RX queue
 * (queue 0) and TX queue (queue 1), and populates the RX queue with empty
 * buffers ready to receive frames.
 *
 * -------------------------------------------------------------------------
 * Legacy virtio-net I/O port layout (relative to iobase = BAR0 & ~3):
 *
 *   0x00  32  Device Features
 *   0x04  32  Guest Features
 *   0x08  32  Queue Address (PFN = phys >> 12)
 *   0x0C  16  Queue Size
 *   0x0E  16  Queue Select
 *   0x10  16  Queue Notify
 *   0x12   8  Device Status
 *   0x13   8  ISR Status
 *   0x14   6  MAC address (6 bytes, feature-gated but default in QEMU)
 *
 * Queues: 0 = RX, 1 = TX, 2 = control (skip).
 *
 * DMA virtual address range: 0x2A000000-0x2B000000.
 * Beyond virtio-blk's range (0x29000000-0x2A000000).
 *
 * Two-phase frame allocation pattern (same as virtio-blk Phase 2c):
 *   Phase A: allocate ALL frames (no mapping) → contiguous paddrs.
 *   Phase B: map ALL frames into orch's address space.
 * -------------------------------------------------------------------------
 */
#include <sel4/sel4.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sel4utils/mapping.h>      /* sel4utils_map_page */
#include <sel4utils/process.h>      /* SEL4UTILS_PD_SLOT */
#include <vka/vka.h>
#include <vka/object.h>
extern int g_orch_quiet;   /* v2.9 · operator `watch` quiet mode (suppress per-packet spam) */

extern uint32_t sotos_pci_config_read32(uint8_t bus, uint8_t dev,
                                         uint8_t func, uint8_t off);
extern seL4_CPtr orch_get_io_port_cap(void);
extern vka_t    *orch_vka(void);

#define VIRTIO_VENDOR_ID    0x1AF4
#define VIRTIO_NET_LEGACY   0x1000
#define VIRTIO_NET_MODERN   0x1041

static struct {
    int found;
    uint8_t bus, dev, func;
    uint16_t vendor, device;
    uint32_t bar0;
    uint8_t  irq_line;   /* PCI config 0x3C[7:0] · the GSI/IOAPIC pin SeaBIOS assigned */
    uint8_t  irq_pin;    /* PCI config 0x3C[15:8] · INTx pin (1=INTA..4=INTD; 0=none) */
} g_virtio_net = { 0 };

int virtio_net_probe(void) {
    printf("[virtio-net] probing PCI bus 0 for vendor=0x%X device=0x%X/0x%X...\n",
           VIRTIO_VENDOR_ID, VIRTIO_NET_LEGACY, VIRTIO_NET_MODERN);
    for (int dev = 0; dev < 32; ++dev) {
        for (int func = 0; func < 8; ++func) {
            uint32_t vd = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0);
            if ((vd & 0xFFFF) == 0xFFFF) continue;
            uint16_t vendor = vd & 0xFFFF;
            uint16_t device = (vd >> 16) & 0xFFFF;
            if (vendor != VIRTIO_VENDOR_ID) continue;
            if (device != VIRTIO_NET_LEGACY && device != VIRTIO_NET_MODERN) continue;
            uint32_t bar0 = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0x10);
            /* IRQ-driven RX arc · PCI config 0x3C: [7:0]=interrupt line (the GSI/
             * IOAPIC pin SeaBIOS programmed), [15:8]=interrupt pin (INTx). */
            uint32_t intr = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0x3C);
            g_virtio_net.found  = 1;
            g_virtio_net.bus    = 0;
            g_virtio_net.dev    = (uint8_t)dev;
            g_virtio_net.func   = (uint8_t)func;
            g_virtio_net.vendor = vendor;
            g_virtio_net.device = device;
            g_virtio_net.bar0   = bar0;
            g_virtio_net.irq_line = (uint8_t)(intr & 0xFF);
            g_virtio_net.irq_pin  = (uint8_t)((intr >> 8) & 0xFF);
            printf("[virtio-net] FOUND at 0:%d.%d · BAR0=0x%X · type=%s · IRQ line=%u pin=INT%c\n",
                   dev, func, bar0,
                   device == VIRTIO_NET_LEGACY ? "legacy" : "modern",
                   g_virtio_net.irq_line,
                   g_virtio_net.irq_pin ? ('A' + g_virtio_net.irq_pin - 1) : '-');
            return 0;
        }
    }
    printf("[virtio-net] no virtio-net found\n");
    return -1;
}

int virtio_net_present(void) { return g_virtio_net.found; }
uint32_t virtio_net_bar0(void) { return g_virtio_net.bar0; }
uint8_t virtio_net_irq_line(void) { return g_virtio_net.irq_line; }
uint8_t virtio_net_irq_pin(void)  { return g_virtio_net.irq_pin; }

/* =========================================================================
 * sotNet-β-2 · virtio-net init + RX/TX virtqueue setup
 * =========================================================================*/

/* DMA virtual address range for virtio-net: 0x2A000000-0x2B000000.
 * Virtio-blk occupies 0x29000000-0x2A000000 (4 frames × 4 KiB = 16 KiB). */
#define VNET_DMA_BASE  0x2A000000UL

/* Queue parameters.  The legacy virtio queue size is FIXED by the device
 * (read from reg 0x0C · QEMU reports 256); the driver must lay out the vring
 * for that size.  For Q=256 the legacy vring needs 3 contiguous pages per
 * queue: descriptors (page 0), available ring (page 1 · +4096), used ring
 * (page 2 · +8192).  Mirrors src/sotfs/storage_virtio_blk.c. */
#define VNET_QUEUE_PAGES   3
#define VNET_RX_BUF_BYTES  1536   /* max ethernet frame + virtio_net_hdr */
/* N0 · 32 RX buffers (was 4): the buffer-scan RX path delivers each initial
 * buffer once and its re-arm/recycle is unreliable, so size the initial pool to
 * hold a full short exchange without recycling — DHCP(2) + a TCP handshake +
 * GET-ACK + an HTTP response + FIN all fit in 32 with margin. */
#define VNET_NUM_RX_BUFS   32

/* Total DMA frames:
 *   [0..2]    RX queue (desc/avail/used · 3 contiguous pages)
 *   [3..5]    TX queue (desc/avail/used · 3 contiguous pages)
 *   [6]       TX scratch buffer (1 page)
 *   [7..38]   RX receive buffers (VNET_NUM_RX_BUFS = 32 pages)
 */
#define VNET_FRAME_RX_QUEUE   0
#define VNET_FRAME_TX_QUEUE   3
#define VNET_FRAME_TX_BUF     6
#define VNET_FRAME_RX_BUF0    7
#define VNET_TOTAL_FRAMES     (2 * VNET_QUEUE_PAGES + 1 + VNET_NUM_RX_BUFS)   /* = 11 */

static vka_object_t  g_vnet_objs[VNET_TOTAL_FRAMES];
static uintptr_t     g_vnet_paddrs[VNET_TOTAL_FRAMES];
static void         *g_vnet_vaddrs[VNET_TOTAL_FRAMES];

/* Convenient accessor pointers set after mapping. */
static void     *g_vn_rx_queue_vaddr = NULL;
static uintptr_t g_vn_rx_queue_paddr = 0;
static void     *g_vn_tx_queue_vaddr = NULL;
static uintptr_t g_vn_tx_queue_paddr = 0;

/* Device-reported (legacy: fixed) queue sizes · set in init_queues from reg 0x0C.
 * The avail/used ring offsets are computed from these, NOT a hardcoded constant. */
static uint16_t  g_vn_rx_qsz = 0;
static uint16_t  g_vn_tx_qsz = 0;

/* I/O helpers bound to virtio-net iobase. */
static uint16_t g_vn_iobase = 0;
static uint8_t  g_vn_mac[6] = {0};

static void vn_out8(uint16_t off, uint8_t v) {
    seL4_X86_IOPort_Out8(orch_get_io_port_cap(), (uint16_t)(g_vn_iobase + off), v);
}
static void vn_out16(uint16_t off, uint16_t v) {
    seL4_X86_IOPort_Out16(orch_get_io_port_cap(), (uint16_t)(g_vn_iobase + off), v);
}
static void vn_out32(uint16_t off, uint32_t v) {
    seL4_X86_IOPort_Out32(orch_get_io_port_cap(), (uint16_t)(g_vn_iobase + off), v);
}
static uint8_t vn_in8(uint16_t off) {
    seL4_X86_IOPort_In8_t r = seL4_X86_IOPort_In8(orch_get_io_port_cap(),
                                                    (uint16_t)(g_vn_iobase + off));
    return r.error ? 0xFFu : (uint8_t)r.result;
}
static uint16_t vn_in16(uint16_t off) {
    seL4_X86_IOPort_In16_t r = seL4_X86_IOPort_In16(orch_get_io_port_cap(),
                                                      (uint16_t)(g_vn_iobase + off));
    return r.error ? 0xFFFFu : (uint16_t)r.result;
}

/* IRQ-driven RX · read the legacy ISR status register (BAR0+0x13).  The READ
 * itself deasserts the device's level-triggered INTx line (virtio legacy spec),
 * so the orch IRQ handler MUST call this before seL4_IRQHandler_Ack — otherwise
 * the line stays high and the IRQ re-fires immediately (storm).  Returns the ISR
 * bits: 0x1 = used-ring progressed (RX/TX), 0x2 = config changed.  Returns 0 if
 * the device isn't initialised (g_vn_iobase==0) so a stray early call is inert. */
uint8_t virtio_net_ack_isr(void) {
    if (g_vn_iobase == 0) return 0;
    return vn_in8(0x13);
}


/* Virtqueue descriptor flags. */
#define VIRTQ_DESC_F_WRITE 2u

/* Virtqueue descriptor (same struct as virtio-blk). */
typedef struct {
    uint64_t addr;
    uint32_t len;
    uint16_t flags;
    uint16_t next;
} __attribute__((packed)) vnet_desc_t;

/* -----------------------------------------------------------------------
 * virtio_net_init_queues
 * -----------------------------------------------------------------------
 * Two-phase DMA frame setup (mirrors virtio-blk Phase 2c pattern):
 *   Phase A: allocate ALL frames (no mapping) → paddrs captured.
 *   Phase B: map ALL frames into orch's virtual address space.
 * Then configure device registers + DRIVER_OK.
 * ----------------------------------------------------------------------- */
int virtio_net_init_queues(void)
{
    if (!g_virtio_net.found) {
        printf("[virtio-net] init_queues: device not found · skipping\n");
        return -1;
    }
    if (orch_get_io_port_cap() == 0) {
        printf("[virtio-net] init_queues: no IOPort cap · skipping\n");
        return -1;
    }

    g_vn_iobase = (uint16_t)(g_virtio_net.bar0 & 0xFFFCu);
    printf("[virtio-net] init_queues · iobase=0x%X\n", (unsigned)g_vn_iobase);

    /* Reset + ACK + DRIVER. */
    vn_out8(0x12, 0);
    vn_out8(0x12, 1 | 2);

    /* Skip feature negotiation · minimal, no GSO, no checksum offload. */
    vn_out32(0x04, 0);

    /* Read MAC address from config space (offset 0x14, 6 bytes).
     * VIRTIO_NET_F_MAC is set by default in QEMU so this is always valid. */
    for (int i = 0; i < 6; ++i) g_vn_mac[i] = vn_in8((uint16_t)(0x14 + i));
    printf("[virtio-net] MAC = %02x:%02x:%02x:%02x:%02x:%02x\n",
           g_vn_mac[0], g_vn_mac[1], g_vn_mac[2],
           g_vn_mac[3], g_vn_mac[4], g_vn_mac[5]);

    vka_t *vka = orch_vka();

    /* Phase A: Allocate ALL frames in one batch before ANY mapping.
     * Prevents PT-object allocations from interleaving with frame
     * allocations and breaking contiguity / paddr expectations. */
    for (int i = 0; i < VNET_TOTAL_FRAMES; ++i) {
        int err = vka_alloc_frame(vka, seL4_PageBits, &g_vnet_objs[i]);
        if (err) {
            printf("[virtio-net] vka_alloc_frame[%d] failed (err=%d)\n", i, err);
            return -1;
        }
        seL4_X86_Page_GetAddress_t pa = seL4_X86_Page_GetAddress(g_vnet_objs[i].cptr);
        if (pa.error) {
            printf("[virtio-net] Page_GetAddress[%d] failed (err=%d)\n", i, pa.error);
            return -1;
        }
        g_vnet_paddrs[i] = (uintptr_t)pa.paddr;
    }

    /* The two queue regions (RX frames 0..2, TX frames 3..5) must each be
     * physically contiguous: QEMU derives the avail (+4096) and used (+8192)
     * rings from the single queue PFN.  Verify the first 2*VNET_QUEUE_PAGES
     * frames form one contiguous run + bail otherwise (same guard as
     * storage_virtio_blk.c). */
    for (int i = 1; i < 2 * VNET_QUEUE_PAGES; ++i) {
        if (g_vnet_paddrs[i] != g_vnet_paddrs[0] + (uintptr_t)(i * 4096)) {
            printf("[virtio-net] queue frame[%d] paddr=0x%lx not contiguous (expected 0x%lx) · init failed\n",
                   i, (unsigned long)g_vnet_paddrs[i],
                   (unsigned long)(g_vnet_paddrs[0] + (uintptr_t)(i * 4096)));
            return -1;
        }
    }

    /* Phase B: Map ALL frames into orch's address space. */
    uintptr_t vaddr = VNET_DMA_BASE;
    for (int i = 0; i < VNET_TOTAL_FRAMES; ++i) {
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        int err = sel4utils_map_page(vka,
                                      SEL4UTILS_PD_SLOT,
                                      g_vnet_objs[i].cptr,
                                      (void *)vaddr,
                                      seL4_AllRights,
                                      1 /* cacheable */,
                                      paging, &npaging);
        if (err) {
            printf("[virtio-net] map_page[%d] @0x%lx failed (err=%d)\n",
                   i, (unsigned long)vaddr, err);
            return -1;
        }
        g_vnet_vaddrs[i] = (void *)vaddr;
        memset((void *)vaddr, 0, 4096);
        vaddr += 4096;
    }

    /* Set up convenience pointers. */
    g_vn_rx_queue_vaddr = g_vnet_vaddrs[VNET_FRAME_RX_QUEUE];
    g_vn_rx_queue_paddr = g_vnet_paddrs[VNET_FRAME_RX_QUEUE];
    g_vn_tx_queue_vaddr = g_vnet_vaddrs[VNET_FRAME_TX_QUEUE];
    g_vn_tx_queue_paddr = g_vnet_paddrs[VNET_FRAME_TX_QUEUE];

    /* -----------------------------------------------------------------------
     * RX queue (queue 0) setup.
     * Select queue, read reported size, populate descriptors with empty
     * receive buffers and publish them in the available ring.
     * ----------------------------------------------------------------------- */
    vn_out16(0x0E, 0);  /* Queue Select 0 = RX */
    uint16_t qs_rx = vn_in16(0x0C);
    g_vn_rx_qsz = qs_rx;   /* legacy: the device fixes the size · lay out for it */
    printf("[virtio-net] RX queue size = %u (using %d entries)\n",
           (unsigned)qs_rx, VNET_NUM_RX_BUFS);
    if (qs_rx < VNET_NUM_RX_BUFS) {
        printf("[virtio-net] RX queue too small (%u < %d)\n",
               (unsigned)qs_rx, VNET_NUM_RX_BUFS);
        return -1;
    }

    /* Fill descriptor table: each descriptor points at one RX buffer page. */
    vnet_desc_t *rx_descs = (vnet_desc_t *)g_vn_rx_queue_vaddr;
    for (int i = 0; i < VNET_NUM_RX_BUFS; ++i) {
        rx_descs[i].addr  = (uint64_t)g_vnet_paddrs[VNET_FRAME_RX_BUF0 + i];
        rx_descs[i].len   = VNET_RX_BUF_BYTES;
        rx_descs[i].flags = VIRTQ_DESC_F_WRITE;  /* device writes into buffer */
        rx_descs[i].next  = 0;
    }

    /* Available ring layout (at queue_vbase + g_vn_rx_qsz * sizeof(vnet_desc_t)):
     *   uint16 flags       [0]
     *   uint16 idx         [1]
     *   uint16 ring[Q]     [2 .. 2+Q-1]
     */
    uint16_t *rx_avail = (uint16_t *)((uint8_t *)g_vn_rx_queue_vaddr +
                                       (size_t)g_vn_rx_qsz * sizeof(vnet_desc_t));
    for (int i = 0; i < VNET_NUM_RX_BUFS; ++i) {
        rx_avail[2 + i] = (uint16_t)i;
    }
    __asm__ volatile("" ::: "memory");
    rx_avail[1] = (uint16_t)VNET_NUM_RX_BUFS;

    /* Write RX queue PFN to device. */
    vn_out32(0x08, (uint32_t)(g_vn_rx_queue_paddr >> 12));
    printf("[virtio-net] RX queue · paddr=0x%lx · %d bufs published\n",
           (unsigned long)g_vn_rx_queue_paddr, VNET_NUM_RX_BUFS);

    /* -----------------------------------------------------------------------
     * TX queue (queue 1) setup.
     * Select queue, read size, write PFN.  No descriptors published yet
     * (TX happens in β-3).
     * ----------------------------------------------------------------------- */
    vn_out16(0x0E, 1);  /* Queue Select 1 = TX */
    uint16_t qs_tx = vn_in16(0x0C);
    g_vn_tx_qsz = qs_tx;
    printf("[virtio-net] TX queue size = %u\n", (unsigned)qs_tx);
    if (qs_tx == 0) {
        printf("[virtio-net] TX queue size 0 · device unavailable\n");
        return -1;
    }
    vn_out32(0x08, (uint32_t)(g_vn_tx_queue_paddr >> 12));

    /* DRIVER_OK: device is live. */
    vn_out8(0x12, 1 | 2 | 4);
    printf("[virtio-net] init done · DRIVER_OK set\n");
    return 0;
}

/* =========================================================================
 * sotNet-β-3 · raw frame TX / RX + MAC accessor
 * =========================================================================*/

/* Byte-swap helpers (avoid pulling in <arpa/inet.h> which isn't available). */
static inline uint16_t vn_htons(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }
static inline uint16_t vn_ntohs(uint16_t v) { return (uint16_t)((v << 8) | (v >> 8)); }

/* virtio_net_hdr · legacy, NO VIRTIO_NET_F_MRG_RXBUF (we negotiate 0 features),
 * so it is 10 bytes WITHOUT the num_buffers field.  QEMU strips exactly these
 * 10 bytes on TX and prepends exactly 10 on RX; a 12-byte hdr here desyncs the
 * frame by 2 bytes (mangled MAC/ethertype · DHCP/ARP unparseable). */
typedef struct {
    uint8_t  flags;
    uint8_t  gso_type;
    uint16_t hdr_len;
    uint16_t gso_size;
    uint16_t csum_start;
    uint16_t csum_offset;
} __attribute__((packed)) vnet_net_hdr_t;

/* Convenience TX buffer vaddr/paddr (frame VNET_FRAME_TX_BUF, allocated in β-2). */
static void     *g_vn_tx_buf_vaddr = NULL;
static uintptr_t g_vn_tx_buf_paddr = 0;

/* Convenience RX buffer vaddr array (set after β-2 mapping). */
static void     *g_vn_rx_bufs_vaddr[VNET_NUM_RX_BUFS];

/* -----------------------------------------------------------------------
 * β-2 sets g_vnet_vaddrs/g_vnet_paddrs but the TX/RX buffer pointers used
 * here are initialised lazily on first call in case the caller invokes these
 * before init_queues finishes.  In normal operation init_queues runs first
 * so the pointers below are already valid; this guard just prevents crashes.
 * ----------------------------------------------------------------------- */
static void vn_ensure_buf_ptrs(void)
{
    if (g_vn_tx_buf_vaddr == NULL && g_vnet_vaddrs[VNET_FRAME_TX_BUF] != NULL) {
        g_vn_tx_buf_vaddr = g_vnet_vaddrs[VNET_FRAME_TX_BUF];
        g_vn_tx_buf_paddr = g_vnet_paddrs[VNET_FRAME_TX_BUF];
    }
    for (int i = 0; i < VNET_NUM_RX_BUFS; ++i) {
        if (g_vn_rx_bufs_vaddr[i] == NULL) {
            g_vn_rx_bufs_vaddr[i] = g_vnet_vaddrs[VNET_FRAME_RX_BUF0 + i];
        }
    }
}

/* ----------------------------------------------------------------------- */
void virtio_net_get_mac(uint8_t out[6])
{
    for (int i = 0; i < 6; ++i) out[i] = g_vn_mac[i];
}

/* ----------------------------------------------------------------------- */
/* virtio_net_tx: place one frame in TX queue 1 and kick the device.
 *
 * Uses a single scratch buffer (VNET_FRAME_TX_BUF) for the virtio_net_hdr
 * prepended to the Ethernet frame.  The descriptor index is always 0; we
 * reuse the same slot (single-entry avail ring pattern that is sufficient
 * for synchronous one-at-a-time transmit).
 *
 * We do NOT poll the used ring after notifying the device.  QEMU processes
 * the TX descriptor synchronously with the MMIO/IOPort notify, so by the
 * time Out16 returns the frame has been placed in the TAP/user-net socket.
 * A proper implementation (β-3-Phase-B) would poll the used ring and
 * recycle descriptors, but for the minimal case with one slot this is safe.
 */
int virtio_net_tx(const uint8_t *frame, size_t len)
{
    if (len == 0 || len > 1500) return -1;

    vn_ensure_buf_ptrs();
    if (g_vn_tx_buf_vaddr == NULL || g_vn_tx_queue_vaddr == NULL) {
        printf("[virtio-net] tx: queues not initialised\n");
        return -1;
    }

    /* Build virtio_net_hdr (zeroed) + Ethernet frame in the scratch buffer. */
    vnet_net_hdr_t *nhdr = (vnet_net_hdr_t *)g_vn_tx_buf_vaddr;
    memset(nhdr, 0, sizeof(*nhdr));
    memcpy((uint8_t *)g_vn_tx_buf_vaddr + sizeof(*nhdr), frame, len);

    /* Set up descriptor 0 of TX queue with the entire header+frame. */
    vn_out16(0x0E, 1);   /* Queue Select 1 = TX */
    vnet_desc_t *descs = (vnet_desc_t *)g_vn_tx_queue_vaddr;
    descs[0].addr  = (uint64_t)g_vn_tx_buf_paddr;
    descs[0].len   = (uint32_t)(sizeof(*nhdr) + len);
    descs[0].flags = 0;   /* device-read (not VIRTQ_DESC_F_WRITE) */
    descs[0].next  = 0;

    /* Available ring for TX queue: at offset g_vn_tx_qsz*sizeof(desc).
     * Layout: uint16 flags [0], uint16 idx [1], uint16 ring[...].
     * We always publish descriptor 0 by writing ring[avail_idx % size] = 0
     * then bumping idx. */
    uint16_t *tx_avail = (uint16_t *)((uint8_t *)g_vn_tx_queue_vaddr +
                                       (size_t)g_vn_tx_qsz * sizeof(vnet_desc_t));
    static uint16_t g_tx_avail_idx = 0;
    tx_avail[2 + (g_tx_avail_idx % g_vn_tx_qsz)] = 0;
    __asm__ volatile("" ::: "memory");   /* store-store barrier */
    tx_avail[1] = (uint16_t)(g_tx_avail_idx + 1);
    __asm__ volatile("" ::: "memory");
    g_tx_avail_idx++;

    /* Kick device: write queue index (1 = TX) to notify register (offset 0x10). */
    vn_out16(0x10, 1);

    if (!g_orch_quiet)
        printf("[virtio-net] tx %zu bytes (hdr+frame=%zu)\n",
               len, sizeof(*nhdr) + len);
    return 0;
}

/* ----------------------------------------------------------------------- */
/* virtio_net_rx_poll: check if a frame has landed in one of the RX buffers.
 *
 * HACK NOTE (β-3 minimal):
 *   The used ring for RX queue 0 lives at an offset beyond the single 4 KiB
 *   queue page allocated in β-2.  The legacy virtio used-ring offset is
 *   ALIGN(sizeof(desc)*Q + 2 + 2*Q, 4096), which for Q=8 is 4096 bytes from
 *   the start of the queue page — exactly one full page.  We only allocated
 *   ONE page for the RX queue (VNET_FRAME_RX_QUEUE), so the used ring is
 *   inaccessible without a second contiguous page.
 *
 *   Workaround: scan each RX buffer for a non-zero ethertype at the expected
 *   offset (virtio_net_hdr=12 bytes + eth_dst[6] + eth_src[6] = offset 24).
 *   When QEMU fills the buffer it writes the Ethernet frame starting at
 *   byte 12 (after the virtio_net_hdr), so ethertype lands at byte 24.
 *   A zero ethertype is not a valid Ethernet frame so this is a reliable
 *   anomaly: if the 16-bit field at [24..25] is non-zero a frame arrived.
 *
 *   This approach has the following known limitations:
 *     (a) We don't know the actual frame length (QEMU writes it in the
 *         used-ring entry's len field, which we can't read).  We copy up to
 *         buf_max or VNET_RX_BUF_BYTES, whichever is smaller.  Callers that
 *         know the expected protocol (ARP=42 bytes, ICMP=varies) can pass a
 *         smaller buf_max.
 *     (b) There's a tiny TOCTOU: after we zero the buffer to re-arm it and
 *         before we bump the avail ring index, QEMU might fill the slot again
 *         and we'd miss the second frame (no practical issue at β-3 pace).
 *
 *   TODO (β-3-Phase-B): Allocate 2 contiguous pages for the RX queue so that
 *   the used ring at offset 4096 is accessible, then poll the used ring
 *   properly and recycle descriptors by index.
 *
 * Returns 0 and fills *out_len if a frame was found, -1 if nothing arrived.
 */
/* N1-DRAIN · debug accessors for the standalone in-orch RX-delivery probe.
 * kick = notify the RX queue (re-arm QEMU); ring_state = read avail.idx/used.idx
 * (the driver-published count vs QEMU's completed count) to isolate whether QEMU
 * delivers >4 frames under sustained in-orch polling+kicking (no sotbox path). */
void virtio_net_rx_kick(void) { vn_out16(0x10, 0); }
void virtio_net_rx_ring_state(uint16_t *avail_idx, uint16_t *used_idx) {
    volatile uint16_t *a = (volatile uint16_t *)((uint8_t *)g_vn_rx_queue_vaddr + 4096 + 2);
    volatile uint16_t *u = (volatile uint16_t *)((uint8_t *)g_vn_rx_queue_vaddr + 8192 + 2);
    __asm__ volatile("" ::: "memory");
    if (avail_idx) *avail_idx = *a;
    if (used_idx)  *used_idx  = *u;
}

int virtio_net_rx_poll(uint8_t *out_buf, size_t buf_max, size_t *out_len)
{
    vn_ensure_buf_ptrs();

    /* Ethertype is 2 bytes at offset 10 (virtio_net_hdr · no mrg_rxbuf) + 12 (dst+src MACs) = 22. */
    static const int VNET_HDR_SIZE = 10;
    static const int ETH_TYPE_OFF  = 12;   /* within the Ethernet header */
    static int g_next_rx_idx = 0;

    for (int attempt = 0; attempt < VNET_NUM_RX_BUFS; ++attempt) {
        int i = (g_next_rx_idx + attempt) % VNET_NUM_RX_BUFS;
        volatile uint8_t *buf = (volatile uint8_t *)g_vn_rx_bufs_vaddr[i];
        if (buf == NULL) continue;

        /* Check ethertype at byte VNET_HDR_SIZE + ETH_TYPE_OFF = 24. */
        uint16_t ethertype = (uint16_t)(((uint16_t)buf[VNET_HDR_SIZE + ETH_TYPE_OFF] << 8) |
                                         (uint16_t)buf[VNET_HDR_SIZE + ETH_TYPE_OFF + 1]);
        if (ethertype == 0) continue;

        /* Frame found in slot i.  Copy frame (skip virtio_net_hdr). */
        size_t copy_len = buf_max < (size_t)(VNET_RX_BUF_BYTES - VNET_HDR_SIZE)
                          ? buf_max
                          : (size_t)(VNET_RX_BUF_BYTES - VNET_HDR_SIZE);
        /* Try to infer a more accurate frame length from the IP total-length
         * field when ethertype == 0x0800 (IPv4) or use ARP fixed size. */
        if (ethertype == 0x0806) {
            /* ARP over Ethernet: 14 (eth) + 28 (arp) = 42 bytes. */
            if (42 < copy_len) copy_len = 42;
        } else if (ethertype == 0x0800) {
            /* IPv4: read total_len from IP header at eth+14+2. */
            uint16_t ip_tot = (uint16_t)(((uint16_t)buf[VNET_HDR_SIZE + 14 + 2] << 8) |
                                          (uint16_t)buf[VNET_HDR_SIZE + 14 + 3]);
            size_t ip_frame = 14 + (size_t)ip_tot;
            if (ip_frame < copy_len) copy_len = ip_frame;
        }

        memcpy(out_buf, (const uint8_t *)buf + VNET_HDR_SIZE, copy_len);
        *out_len = copy_len;

        /* Zero the buffer so the next poll doesn't see stale data. */
        memset((uint8_t *)buf, 0, VNET_RX_BUF_BYTES);

        /* Re-publish the descriptor in the avail ring so QEMU can refill it.
         * We update the avail ring index to tell the device one more buffer
         * is available (slot i, descriptor index i). */
        uint16_t *rx_avail = (uint16_t *)((uint8_t *)g_vn_rx_queue_vaddr +
                                           (size_t)g_vn_rx_qsz * sizeof(vnet_desc_t));
        /* Place descriptor index i into the next avail ring slot and bump idx.
         * We track a separate avail publish counter to avoid clobbering the
         * initial ring set up in β-2. */
        static uint16_t g_rx_avail_publish = VNET_NUM_RX_BUFS;  /* β-2 published 4 */
        rx_avail[2 + (g_rx_avail_publish % g_vn_rx_qsz)] = (uint16_t)i;
        __asm__ volatile("" ::: "memory");
        rx_avail[1] = (uint16_t)(g_rx_avail_publish + 1);
        g_rx_avail_publish++;

        /* Kick RX queue to let QEMU know the buffer is available again. */
        vn_out16(0x10, 0);

        if (!g_orch_quiet)
            printf("[virtio-net] rx %zu bytes from buf[%d] · ethertype=0x%04x\n",
                   copy_len, i, (unsigned)ethertype);

        g_next_rx_idx = (i + 1) % VNET_NUM_RX_BUFS;
        return 0;
    }
    return -1;   /* no frame received */
}
