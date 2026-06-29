/*
 * sotOs · sotNet · N3 · IPv6 + ICMPv6 echo + Neighbor Solicitation.
 *
 * Minimal IPv6 handling layered above the Ethernet frame poll in
 * src/sotnet/sotnet.c.  Provides:
 *   - Fixed link-local address fe80::5054:ff:fe12:3456 (EUI-64 from our MAC
 *     52:54:00:12:34:56, universal/local bit flipped per RFC 4291).
 *   - ICMPv6 Echo Request (type 128) → Echo Reply (type 129).
 *   - ICMPv6 Neighbor Solicitation (type 135) for our addr → Neighbor
 *     Advertisement (type 136).
 *   - All other IPv6 packets: log and ignore.
 *
 * ICMPv6 checksum: ones-complement sum of the IPv6 pseudo-header
 * (src + dst + payload_len_be32 + zero(3) + next_header) + ICMPv6 message.
 *
 * NOTE: QEMU user-mode networking has IPv6 disabled by default, so the
 * handler will typically remain dormant during `just run`.  This is
 * expected and documented in the change description.
 */
#ifndef SOTNET_IPV6_H
#define SOTNET_IPV6_H

#include <stdint.h>
#include <stddef.h>

/* IPv6 ethertype (big-endian on the wire). */
#define IPV6_ETHERTYPE  0x86dd

/* IPv6 fixed header is 40 bytes (RFC 8200 §3). */
struct ipv6_hdr {
    uint8_t  ver_tc_flow[4];   /* version(4) | traffic_class(8) | flow_label(20) */
    uint16_t payload_len;      /* BE · bytes after this header */
    uint8_t  next_header;      /* 58 = ICMPv6 */
    uint8_t  hop_limit;
    uint8_t  src[16];
    uint8_t  dst[16];
} __attribute__((packed));

/* ICMPv6 common message header (4 bytes type/code/csum + variable body). */
struct icmp6_hdr {
    uint8_t  type;
    uint8_t  code;
    uint16_t csum;             /* BE · ones-complement over pseudo-hdr + msg */
} __attribute__((packed));

/*
 * handle_ipv6: parse an IPv6 frame received on the wire and dispatch.
 *   frame: pointer to the start of the Ethernet frame (14-byte L2 header
 *          followed by the IPv6 header at offset 14).
 *   len  : total Ethernet frame length (eth + ipv6 + payload).
 *
 * Behaviour:
 *   - If next_header == 58 (ICMPv6) and type is 128 (Echo Request)
 *     addressed to our link-local, send a 129 Echo Reply.
 *   - If next_header == 58 and type is 135 (Neighbor Solicitation) for
 *     our link-local target address, send a 136 Neighbor Advertisement.
 *   - All other IPv6 packets: log and ignore.
 *
 * Emits one of:
 *   [ipv6] echo from <src>
 *   [ipv6] NS from <src>
 *   [ipv6] unknown from <src>
 */
void handle_ipv6(const uint8_t *frame, size_t len);

#endif /* SOTNET_IPV6_H */
