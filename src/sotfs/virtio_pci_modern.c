#include <sotfs/virtio_modern.h>
#include <string.h>
#ifndef VIRTIO_MODERN_HOST_TEST
#include <sel4/sel4.h>
#include <vka/vka.h>
#include <vka/object.h>
#include <sel4utils/mapping.h>
#include <sel4utils/process.h>
#include <stdio.h>
extern uint32_t sotos_pci_config_read32(uint8_t bus, uint8_t dev, uint8_t func, uint8_t off);
extern seL4_CPtr orch_get_io_port_cap(void);
extern vka_t    *orch_vka(void);
#endif

/* Resolve a (possibly 64-bit) memory BAR's base paddr from config space. */
static uintptr_t bar_base(vpci_read32_fn rd, void *ctx, uint8_t bar_index) {
    uint8_t off = (uint8_t)(0x10 + bar_index * 4);
    uint32_t lo = rd(ctx, off);
    uintptr_t base = (uintptr_t)(lo & ~0xFUL);          /* clear flag bits */
    if ((lo & 0x6) == 0x4) {                             /* 64-bit BAR */
        uint32_t hi = rd(ctx, (uint8_t)(off + 4));
        base |= ((uintptr_t)hi) << 32;
    }
    return base;
}

int virtio_pci_parse_caps(vpci_read32_fn rd, void *ctx, vpci_caps_t *out) {
    memset(out, 0, sizeof *out);
    uint8_t cap = (uint8_t)(rd(ctx, 0x34) & 0xFF);       /* capabilities pointer */
    int guard = 0;
    while (cap && cap != 0xFF && guard++ < 48) {
        uint32_t w0 = rd(ctx, cap);                      /* id | next | len | cfg_type */
        uint8_t id = w0 & 0xFF, next = (w0 >> 8) & 0xFF, cfg_type = (w0 >> 24) & 0xFF;
        if (id == PCI_CAP_ID_VNDR) {
            uint8_t bar = rd(ctx, (uint8_t)(cap + 4)) & 0xFF;
            uint32_t offset = rd(ctx, (uint8_t)(cap + 8));
            uint32_t length = rd(ctx, (uint8_t)(cap + 12));
            uintptr_t pa = bar_base(rd, ctx, bar) + offset;
            switch (cfg_type) {
            case VIRTIO_PCI_CAP_COMMON_CFG: out->common_pa = pa; out->common_len = length; break;
            case VIRTIO_PCI_CAP_NOTIFY_CFG: out->notify_pa = pa; out->notify_len = length;
                                            out->notify_mult = rd(ctx, (uint8_t)(cap + 16)); break;
            case VIRTIO_PCI_CAP_ISR_CFG:    out->isr_pa = pa; out->isr_len = length; break;
            case VIRTIO_PCI_CAP_DEVICE_CFG: out->device_pa = pa; out->device_len = length; break;
            default: break;
            }
        }
        cap = next;
    }
    return out->common_pa ? 0 : -1;
}

#ifndef VIRTIO_MODERN_HOST_TEST
/* =========================================================================
 * Part A: device probe + BAR mapping + feature negotiation
 * ========================================================================= */

/* DMA/MMIO vaddr window for virtio-modern BAR mappings (above the legacy
 * net/blk windows at 0x29/0x2A000000).  Bump-allocated per mapped page. */
static uintptr_t g_vmm_next = 0x2C000000UL;

static uint32_t cfg_rd(void *ctx, uint8_t off) {
    virtio_dev_t *d = ctx;
    return sotos_pci_config_read32(d->bus, d->dev, d->func, off);
}

/* Map [pa, pa+len) (page-granular) uncached into orch; return vaddr of the
 * first byte (accounting for sub-page offset), or NULL. */
static volatile uint8_t *map_mmio(uintptr_t pa, uint32_t len) {
    vka_t *vka = orch_vka();
    uintptr_t pa_base = pa & ~0xFFFUL;
    uint32_t  span = (uint32_t)((pa - pa_base) + len);
    uint32_t  pages = (span + 0xFFF) / 0x1000;
    uintptr_t va_base = g_vmm_next;
    for (uint32_t i = 0; i < pages; ++i) {
        vka_object_t frame;
        int err = vka_alloc_frame_at(vka, seL4_PageBits,
                                     pa_base + (uintptr_t)i * 0x1000, &frame);
        if (err) {
            printf("[virtio-modern] map: alloc_frame_at(0x%lx) err=%d\n",
                   (unsigned long)(pa_base + (uintptr_t)i * 0x1000), err);
            return NULL;
        }
        vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
        int npaging = VSPACE_MAP_PAGING_OBJECTS;
        err = sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, frame.cptr,
                                 (void *)(va_base + (uintptr_t)i * 0x1000),
                                 seL4_AllRights,
                                 0 /* uncached for MMIO */,
                                 paging, &npaging);
        if (err) {
            printf("[virtio-modern] map: map_page err=%d\n", err);
            return NULL;
        }
        g_vmm_next += 0x1000;
    }
    return (volatile uint8_t *)(va_base + (pa - pa_base));
}

int virtio_modern_probe(uint16_t device_id, int nth, virtio_dev_t *out) {
    memset(out, 0, sizeof *out);
    int seen = 0;
    for (int dev = 0; dev < 32; ++dev) {
        for (int func = 0; func < 8; ++func) {
            uint32_t vd = sotos_pci_config_read32(0, (uint8_t)dev, (uint8_t)func, 0);
            uint16_t vendor = vd & 0xFFFF, devid = (vd >> 16) & 0xFFFF;
            if (vendor != VIRTIO_VENDOR_ID || devid != device_id) continue;
            if (seen++ < nth) continue;
            out->bus = 0; out->dev = (uint8_t)dev; out->func = (uint8_t)func;
            vpci_caps_t caps;
            if (virtio_pci_parse_caps(cfg_rd, out, &caps) != 0) {
                printf("[virtio-modern] dev 0x%X: no COMMON cap\n", device_id);
                return -1;
            }
            out->common = (virtio_common_cfg_t *)map_mmio(caps.common_pa, caps.common_len);
            out->notify_base = map_mmio(caps.notify_pa, caps.notify_len);
            out->notify_off_multiplier = caps.notify_mult;
            out->notify_cap_offset = (uint32_t)(caps.notify_pa & 0xFFF);
            if (caps.device_pa)
                out->device_cfg = map_mmio(caps.device_pa, caps.device_len);
            if (!out->common || !out->notify_base) return -1;
            out->found = 1;
            printf("[virtio-modern] dev 0x%X @0:%d.%d mapped (common=%p notify=%p)\n",
                   device_id, dev, func, (void *)out->common, (void *)out->notify_base);
            return 0;
        }
    }
    return -1;
}

int virtio_modern_negotiate(virtio_dev_t *dev, uint64_t extra_features) {
    virtio_common_cfg_t *c = dev->common;
    c->device_status = 0;                                    /* reset */
    /* Wait for reset to complete — BOUNDED so a misbehaving device can never
     * hang orch (the OS's single point of failure) forever. On timeout, fail
     * the device and return -1 → gpu_init returns -1 → orch stays headless. */
    for (uint32_t t = 0; c->device_status != 0; ++t) {
        if (t >= 2000000) {
            printf("[virtio-modern] reset wait TIMEOUT (status=0x%x)\n", c->device_status);
            c->device_status = VIRTIO_STATUS_FAILED;
            return -1;
        }
        for (volatile int s = 0; s < 100; ++s) { }
    }
    c->device_status = VIRTIO_STATUS_ACKNOWLEDGE;
    c->device_status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER;
    c->driver_feature_select = 0;
    c->driver_feature = (uint32_t)(extra_features & 0xFFFFFFFFu);
    c->driver_feature_select = 1;
    c->driver_feature = VIRTIO_F_VERSION_1_WORD1
                      | (uint32_t)(extra_features >> 32);
    c->device_status = VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER
                     | VIRTIO_STATUS_FEATURES_OK;
    if (!(c->device_status & VIRTIO_STATUS_FEATURES_OK)) {
        printf("[virtio-modern] FEATURES_OK rejected\n");
        c->device_status = VIRTIO_STATUS_FAILED;
        return -1;
    }
    return 0;
}

void virtio_modern_driver_ok(virtio_dev_t *dev) {
    dev->common->device_status |= VIRTIO_STATUS_DRIVER_OK;
}

/* =========================================================================
 * Part B: virtqueue setup + request/poll
 * ========================================================================= */

/* Alloc one zeroed 4K frame (cached, for DMA), map it into orch, return
 * vaddr + paddr via pa_out.  Returns NULL on failure. */
static void *alloc_page(uintptr_t *pa_out) {
    vka_t *vka = orch_vka();
    vka_object_t f;
    if (vka_alloc_frame(vka, seL4_PageBits, &f)) return NULL;
    void *va = (void *)g_vmm_next;
    vka_object_t paging[VSPACE_MAP_PAGING_OBJECTS];
    int npaging = VSPACE_MAP_PAGING_OBJECTS;
    if (sel4utils_map_page(vka, SEL4UTILS_PD_SLOT, f.cptr, va,
                           seL4_AllRights, 1 /* cached */,
                           paging, &npaging))
        return NULL;
    g_vmm_next += 0x1000;
    *pa_out = (uintptr_t)seL4_X86_Page_GetAddress(f.cptr).paddr;
    memset(va, 0, 0x1000);
    return va;
}

int virtio_modern_setup_queue(virtio_dev_t *dev, int qidx, virtq_t *out) {
    virtio_common_cfg_t *c = dev->common;
    memset(out, 0, sizeof *out);
    c->queue_select = (uint16_t)qidx;
    uint16_t qsz = c->queue_size;
    if (qsz == 0) { printf("[virtio-modern] queue %d size 0\n", qidx); return -1; }
    if (qsz > 256) qsz = 256;              /* cap so each ring fits one page */
    c->queue_size = qsz;
    out->qsz = qsz;
    out->desc  = alloc_page(&out->desc_pa);
    out->avail = alloc_page(&out->avail_pa);
    out->used  = alloc_page(&out->used_pa);
    if (!out->desc || !out->avail || !out->used) return -1;
    c->queue_desc   = out->desc_pa;
    c->queue_driver = out->avail_pa;
    c->queue_device = out->used_pa;
    out->notify = (volatile uint16_t *)(dev->notify_base
                  + (uint32_t)c->queue_notify_off * dev->notify_off_multiplier);
    c->queue_enable = 1;
    out->last_used = 0; out->free_head = 0;
    printf("[virtio-modern] queue %d ready qsz=%u notify_off=%u\n",
           qidx, qsz, (unsigned)c->queue_notify_off);
    return 0;
}

int virtio_modern_request(virtio_dev_t *dev, virtq_t *vq,
                          struct vio_buf *bufs, int n, uint32_t timeout_iters) {
    (void)dev;
    /* The chain uses descriptors [0..n-1]; refuse if it exceeds the device's
     * advertised queue size (else the device would silently truncate the chain
     * and read/write the wrong backing). */
    if (n <= 0 || n > vq->qsz) {
        printf("[virtio-modern] request n=%d exceeds qsz=%u\n", n, (unsigned)vq->qsz);
        return -1;
    }
    for (int i = 0; i < n; ++i) {
        vq->desc[i].addr  = bufs[i].paddr;
        vq->desc[i].len   = bufs[i].len;
        vq->desc[i].flags = (uint16_t)((bufs[i].device_writable ? VIRTQ_DESC_F_WRITE : 0)
                          | (i + 1 < n ? VIRTQ_DESC_F_NEXT : 0));
        vq->desc[i].next  = (uint16_t)(i + 1);
    }
    uint16_t aidx = vq->avail->idx;
    vq->avail->ring[aidx % vq->qsz] = 0;        /* head descriptor index */
    __atomic_store_n(&vq->avail->idx, (uint16_t)(aidx + 1), __ATOMIC_RELEASE);
    *vq->notify = 0;                              /* doorbell */
    for (uint32_t t = 0; t < timeout_iters; ++t) {
        if (__atomic_load_n(&vq->used->idx, __ATOMIC_ACQUIRE) != vq->last_used) {
            vq->last_used++;
            return 0;
        }
        for (volatile int s = 0; s < 1000; ++s) { }   /* brief backoff */
    }
    printf("[virtio-modern] request TIMEOUT\n");
    return -1;
}
#endif /* VIRTIO_MODERN_HOST_TEST */
