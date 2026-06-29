#ifndef SOTFS_VIRTIO_MODERN_H
#define SOTFS_VIRTIO_MODERN_H
#include <stdint.h>
#include <stddef.h>

/* ---- PCI / virtio-pci-cap constants ---- */
#define VIRTIO_VENDOR_ID        0x1AF4
#define PCI_CAP_ID_VNDR         0x09        /* virtio caps are vendor-specific */
#define VIRTIO_PCI_CAP_COMMON_CFG  1
#define VIRTIO_PCI_CAP_NOTIFY_CFG  2
#define VIRTIO_PCI_CAP_ISR_CFG     3
#define VIRTIO_PCI_CAP_DEVICE_CFG  4

/* device_status bits */
#define VIRTIO_STATUS_ACKNOWLEDGE  1
#define VIRTIO_STATUS_DRIVER       2
#define VIRTIO_STATUS_DRIVER_OK    4
#define VIRTIO_STATUS_FEATURES_OK  8
#define VIRTIO_STATUS_FAILED       128
/* feature word 1, bit 0 = VIRTIO_F_VERSION_1 (overall bit 32) */
#define VIRTIO_F_VERSION_1_WORD1   (1u << 0)

/* virtqueue descriptor flags */
#define VIRTQ_DESC_F_NEXT   1
#define VIRTQ_DESC_F_WRITE  2

/* virtio_pci_common_cfg — MMIO layout (offsets within the COMMON BAR region). */
typedef volatile struct {
    uint32_t device_feature_select;
    uint32_t device_feature;
    uint32_t driver_feature_select;
    uint32_t driver_feature;
    uint16_t msix_config;
    uint16_t num_queues;
    uint8_t  device_status;
    uint8_t  config_generation;
    uint16_t queue_select;
    uint16_t queue_size;
    uint16_t queue_msix_vector;
    uint16_t queue_enable;
    uint16_t queue_notify_off;
    uint64_t queue_desc;
    uint64_t queue_driver;
    uint64_t queue_device;
} __attribute__((packed)) virtio_common_cfg_t;

/* split-virtqueue ring structs */
typedef struct { uint64_t addr; uint32_t len; uint16_t flags; uint16_t next; }
    __attribute__((packed)) vq_desc_t;
typedef struct { uint16_t flags; uint16_t idx; uint16_t ring[]; }
    __attribute__((packed)) vq_avail_t;
typedef struct { uint32_t id; uint32_t len; }
    __attribute__((packed)) vq_used_elem_t;
typedef struct { uint16_t flags; uint16_t idx; vq_used_elem_t ring[]; }
    __attribute__((packed)) vq_used_t;

/* A set-up virtqueue (per-page rings; addresses captured). */
typedef struct {
    uint16_t      qsz;
    vq_desc_t    *desc;     uintptr_t desc_pa;
    vq_avail_t   *avail;    uintptr_t avail_pa;
    vq_used_t    *used;     uintptr_t used_pa;
    volatile uint16_t *notify;   /* the MMIO notify doorbell for this queue */
    uint16_t      last_used;      /* driver's used-ring consumer cursor */
    uint16_t      free_head;      /* next free descriptor index (simple bump/free) */
} virtq_t;

/* A probed modern virtio device. */
typedef struct {
    int       found;
    uint8_t   bus, dev, func;
    virtio_common_cfg_t *common;          /* mapped COMMON cfg */
    volatile uint8_t    *notify_base;     /* mapped NOTIFY BAR region base */
    uint32_t  notify_off_multiplier;
    uint32_t  notify_cap_offset;          /* cap.offset of the NOTIFY region */
    volatile uint8_t    *device_cfg;      /* mapped DEVICE cfg (may be NULL) */
} virtio_dev_t;

/* One IN/OUT buffer for a descriptor chain. */
struct vio_buf { uintptr_t paddr; uint32_t len; int device_writable; };

/* ---- API ---- */
/* Probe the nth (0-based) device with the given modern device-id (e.g. 0x1050
 * for gpu). Returns 0 + fills *out on success, -1 if not found. Maps its BARs. */
int  virtio_modern_probe(uint16_t device_id, int nth, virtio_dev_t *out);

/* Reset + ACK/DRIVER + negotiate VIRTIO_F_VERSION_1 + FEATURES_OK. -1 on failure. */
int  virtio_modern_negotiate(virtio_dev_t *dev, uint64_t extra_features);

/* Allocate + program one split virtqueue (queue index qidx). -1 on failure. */
int  virtio_modern_setup_queue(virtio_dev_t *dev, int qidx, virtq_t *out);

/* Finish init: device_status |= DRIVER_OK. */
void virtio_modern_driver_ok(virtio_dev_t *dev);

/* Submit a descriptor chain (bufs[0..n-1]); kick the device; poll the used ring.
 * Returns 0 on completion, -1 on timeout. Single in-flight chain (PR1 is
 * request/response, no pipelining). */
int  virtio_modern_request(virtio_dev_t *dev, virtq_t *vq,
                           struct vio_buf *bufs, int n, uint32_t timeout_iters);

/* ---- pure helpers (host-unit-tested) ---- */
/* Walk the PCI capability list via read32(ctx,off) and resolve each virtio cap
 * region's absolute MMIO paddr. Fills the four region paddr/len/extra outs
 * (0 if a region is absent). Returns 0 if a COMMON region was found, else -1.
 * `read32` reads PCI config dword at byte offset `off` for the device. */
typedef uint32_t (*vpci_read32_fn)(void *ctx, uint8_t off);
typedef struct {
    uintptr_t common_pa;  uint32_t common_len;
    uintptr_t notify_pa;  uint32_t notify_len;  uint32_t notify_mult;
    uintptr_t isr_pa;     uint32_t isr_len;
    uintptr_t device_pa;  uint32_t device_len;
} vpci_caps_t;
int virtio_pci_parse_caps(vpci_read32_fn read32, void *ctx, vpci_caps_t *out);

#endif
