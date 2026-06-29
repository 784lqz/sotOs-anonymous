/* Host unit test for virtio_pci_parse_caps (pure cap-chain logic).
 *   cc -I include src/test/virtio_modern_unit/virtio_modern_unit.c \
 *      src/sotfs/virtio_pci_modern.c -o /tmp/vmu && /tmp/vmu
 * NOTE: virtio_pci_modern.c must compile on host — guard seL4-only code with
 * #ifndef VIRTIO_MODERN_HOST_TEST around the BAR-map/queue/request functions so
 * only the pure parser links here. */
#include <sotfs/virtio_modern.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do{ if(!(c)){printf("FAIL: %s (line %d)\n",#c,__LINE__);fails++;} }while(0)

/* Mock 256-byte PCI config space. */
static uint8_t cfg[256];
static uint32_t mock_read32(void *ctx, uint8_t off) {
    (void)ctx; uint32_t v; memcpy(&v, cfg + off, 4); return v;
}
static void put32(uint8_t off, uint32_t v){ memcpy(cfg+off,&v,4); }

int main(void) {
    memset(cfg, 0, sizeof cfg);
    /* Status reg (0x06) bit 4 = capabilities list present. */
    put32(0x04, 0x00100000);            /* status high word bit4 */
    put32(0x34, 0x40);                  /* cap pointer = 0x40 */
    /* BAR4 (offset 0x20) = 64-bit MMIO BAR at paddr 0xC0000000. */
    put32(0x20, 0xC0000000 | 0x4 /*64-bit*/ | 0x0 /*mem*/);
    put32(0x24, 0x0);                   /* BAR5 = high dword = 0 */

    /* cap @0x40: COMMON cfg, bar=4, offset=0x0000, length=0x1000. */
    cfg[0x40]=PCI_CAP_ID_VNDR; cfg[0x41]=0x50 /*next*/; cfg[0x42]=16; cfg[0x43]=VIRTIO_PCI_CAP_COMMON_CFG;
    cfg[0x44]=4 /*bar*/; put32(0x48, 0x0000); put32(0x4C, 0x1000);
    /* cap @0x50: NOTIFY cfg, bar=4, offset=0x3000, length=0x1000, mult=4. */
    cfg[0x50]=PCI_CAP_ID_VNDR; cfg[0x51]=0x00 /*end*/; cfg[0x52]=20; cfg[0x53]=VIRTIO_PCI_CAP_NOTIFY_CFG;
    cfg[0x54]=4; put32(0x58, 0x3000); put32(0x5C, 0x1000); put32(0x60, 4 /*mult*/);

    vpci_caps_t caps; memset(&caps,0,sizeof caps);
    int rc = virtio_pci_parse_caps(mock_read32, NULL, &caps);
    CHECK(rc == 0);
    CHECK(caps.common_pa == 0xC0000000 + 0x0000);
    CHECK(caps.common_len == 0x1000);
    CHECK(caps.notify_pa == 0xC0000000 + 0x3000);
    CHECK(caps.notify_mult == 4);

    if (fails == 0) printf("virtio_modern_unit: ALL PASS\n");
    return fails ? 1 : 0;
}
