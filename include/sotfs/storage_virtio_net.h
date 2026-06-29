#ifndef SOTFS_STORAGE_VIRTIO_NET_H
#define SOTFS_STORAGE_VIRTIO_NET_H
#include <stdint.h>
#include <stddef.h>
int virtio_net_probe(void);
int virtio_net_present(void);
uint32_t virtio_net_bar0(void);
int virtio_net_init_queues(void);
/* sotNet-β-3 additions */
void virtio_net_get_mac(uint8_t out[6]);
int  virtio_net_tx(const uint8_t *frame, size_t len);
int  virtio_net_rx_poll(uint8_t *out_buf, size_t buf_max, size_t *out_len);
#endif
