/*
 * sotOs · sotNet · N2 · TCP-RST stub.
 *
 * Visibility-only TCP responder · proto=6.  We do not implement a TCP state
 * machine; the only behavior is: when an incoming TCP segment with the SYN
 * flag set arrives for our IP, log the connection attempt and reply with a
 * RST+ACK so the peer's connect() returns ECONNREFUSED quickly instead of
 * hanging.  All other TCP packets (ACK-only, RST, data, FIN) are silently
 * ignored.
 *
 * Wire format (RFC 793):
 *   Ethernet (14B) + IPv4 (20B, no options) + TCP (20B, no options).
 *
 * Caller (sotnet_poll IPv4 branch) is responsible for checking ip->proto == 6
 * before invoking tcp_handle_syn().
 */
#ifndef SOTNET_TCP_H
#define SOTNET_TCP_H

#include <stdint.h>
#include <stddef.h>

/*
 * struct tcp_hdr · minimal TCP header (no options).
 *
 * All multi-byte fields are big-endian on the wire.
 */
struct tcp_hdr {
    uint16_t src_port;     /* BE */
    uint16_t dst_port;     /* BE */
    uint32_t seq;          /* BE */
    uint32_t ack;          /* BE */
    uint8_t  data_off;     /* high nibble = data offset in 32-bit words */
    uint8_t  flags;        /* FIN=0x01 SYN=0x02 RST=0x04 PSH=0x08 ACK=0x10 */
    uint16_t window;       /* BE */
    uint16_t csum;         /* BE · ones-complement of pseudo-hdr + tcp seg */
    uint16_t urgent;       /* BE */
} __attribute__((packed));

#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20
#define TCP_FLAG_ECE 0x40
#define TCP_FLAG_CWR 0x80

/*
 * tcp_handle_syn: parse an incoming Ethernet+IPv4+TCP frame; if it is a SYN
 * targeting our IP, log the attempt and reply with a RST+ACK frame on the
 * wire via virtio_net_tx.  Silently no-ops otherwise.
 *
 * frame: full Ethernet frame as received (eth+ip+tcp[+payload]).
 * len  : frame length in bytes.
 */
void tcp_handle_syn(const uint8_t *frame, size_t len);

#endif /* SOTNET_TCP_H */
