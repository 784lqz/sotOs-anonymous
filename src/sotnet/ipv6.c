/*
 * sotOs · sotNet · N3 · IPv6 + ICMPv6 echo + Neighbor Solicitation.
 *
 * See include/sotnet/ipv6.h for the contract.
 *
 * Layering: handle_ipv6() is invoked from sotnet_poll() in
 * src/sotnet/sotnet.c when the L2 ethertype == 0x86dd.  It parses the
 * 40-byte IPv6 header, then for next_header == 58 (ICMPv6) dispatches
 * Echo Request (128) and Neighbor Solicitation (135).
 *
 * No malloc.  Bounded static TX buffers.  All multi-byte on-wire fields
 * are big-endian; conversion is local to this file (matches sotnet.c
 * style — no <arpa/inet.h> available in the seL4/muslc environment).
 */

#include <sotnet/ipv6.h>
#include <sotnet/sotnet.h>           /* struct eth_hdr */
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

/* Forward decl for the virtio-net TX path (defined in storage_virtio_net.c
 * and already used by sotnet.c). */
extern int  virtio_net_tx(const uint8_t *frame, size_t len);
extern void virtio_net_get_mac(uint8_t out[6]);

/* -------------------------------------------------------------------------
 * Byte-order helpers (file-local; mirror sotnet.c's htons_/ntohs_).
 * -------------------------------------------------------------------------*/
static inline uint16_t ipv6_htons(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}
static inline uint16_t ipv6_ntohs(uint16_t v)
{
    return (uint16_t)((v << 8) | (v >> 8));
}

/* -------------------------------------------------------------------------
 * Our fixed link-local address: fe80::5054:ff:fe12:3456.
 *
 * Derived (per RFC 4291 §2.5.1) from our QEMU-fixed MAC 52:54:00:12:34:56
 * by inserting ff:fe in the middle and flipping the universal/local bit
 * (0x02): 50:54:00:ff:fe:12:34:56.  Address is statically encoded so the
 * handler works even if virtio_net_get_mac is not invoked here.
 * -------------------------------------------------------------------------*/
static const uint8_t OUR_LL[16] = {
    0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56,
};

/* All-nodes multicast (used to recognise NS sent to solicited-node mcast
 * group prefix ff02::1:ff00:0/104).  We just accept any dst here and rely
 * on the target-address match inside the NS. */

/* -------------------------------------------------------------------------
 * Print a compact textual IPv6 address.  Not RFC 5952 canonical — good
 * enough for `[ipv6] %s from <src>` debug lines.  Avoids snprintf-style
 * surprises by writing directly to a 40-byte caller buffer.
 * -------------------------------------------------------------------------*/
static void ipv6_addr_str(const uint8_t addr[16], char out[40])
{
    static const char hex[] = "0123456789abcdef";
    size_t o = 0;
    for (int i = 0; i < 8; ++i) {
        uint16_t group = (uint16_t)((addr[i * 2] << 8) | addr[i * 2 + 1]);
        /* Print 4 hex nibbles · skip leading zeros within the group except
         * keep at least one digit. */
        int started = 0;
        for (int shift = 12; shift >= 0; shift -= 4) {
            uint8_t n = (uint8_t)((group >> shift) & 0xfu);
            if (n || started || shift == 0) {
                out[o++] = hex[n];
                started = 1;
            }
        }
        if (i != 7) out[o++] = ':';
    }
    out[o] = '\0';
}

/* -------------------------------------------------------------------------
 * ICMPv6 checksum: ones-complement over the IPv6 pseudo-header followed
 * by the ICMPv6 message.  RFC 4443 §2.3, RFC 8200 §8.1.
 *
 * Pseudo-header layout (40 bytes):
 *   src[16] + dst[16] + upper-layer-length(4, BE) + zero(3) + next_hdr(1)
 * -------------------------------------------------------------------------*/
static uint16_t icmp6_checksum(const uint8_t src[16], const uint8_t dst[16],
                               uint32_t payload_len, uint8_t next_header,
                               const uint8_t *msg, size_t msg_len)
{
    uint32_t sum = 0;

    /* Pseudo-header: src + dst (16-bit accumulation). */
    for (int i = 0; i < 16; i += 2) {
        sum += (uint32_t)((src[i] << 8) | src[i + 1]);
    }
    for (int i = 0; i < 16; i += 2) {
        sum += (uint32_t)((dst[i] << 8) | dst[i + 1]);
    }

    /* Upper-layer payload length, 32-bit BE, fed as two 16-bit halves. */
    sum += (payload_len >> 16) & 0xFFFFu;
    sum += payload_len & 0xFFFFu;

    /* Zero(3) + next_header(1) == 0x0000 + (0x00 << 8 | next_header). */
    sum += (uint32_t)next_header;

    /* ICMPv6 message body (the csum field inside must be zero on input). */
    size_t i = 0;
    while (i + 1 < msg_len) {
        sum += (uint32_t)((msg[i] << 8) | msg[i + 1]);
        i += 2;
    }
    if (i < msg_len) {
        sum += (uint32_t)(msg[i] << 8);
    }

    while (sum >> 16) sum = (sum & 0xFFFFu) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFFu);
}

/* -------------------------------------------------------------------------
 * Build + send an ICMPv6 Echo Reply (type 129) in response to an Echo
 * Request (type 128) addressed to us.  The reply mirrors payload and
 * identifier/sequence; only src/dst and type are swapped.
 * -------------------------------------------------------------------------*/
static void send_echo_reply(const uint8_t *frame, size_t len,
                            const struct ipv6_hdr *ip6, size_t icmp_len)
{
    if (len > 1500) return;   /* virtio_net_tx rejects > 1500 */

    static uint8_t reply[1500];
    memcpy(reply, frame, len);

    struct eth_hdr  *r_eth  = (struct eth_hdr *)reply;
    struct ipv6_hdr *r_ip6  = (struct ipv6_hdr *)(reply + 14);
    struct icmp6_hdr *r_ic  = (struct icmp6_hdr *)(reply + 14 + 40);

    /* Swap Ethernet addresses; reply src = our MAC. */
    uint8_t our_mac[6];
    virtio_net_get_mac(our_mac);
    memcpy(r_eth->dst, ((const struct eth_hdr *)frame)->src, 6);
    memcpy(r_eth->src, our_mac, 6);

    /* Swap IPv6 addresses.  For multicast destinations the reply src would
     * normally need to be our unicast — we accept this minor non-compliance
     * since QEMU user-mode networking doesn't typically deliver multicast
     * echo requests to the guest. */
    memcpy(r_ip6->src, ip6->dst, 16);
    memcpy(r_ip6->dst, ip6->src, 16);
    r_ip6->hop_limit = 64;

    /* Flip Echo Request → Echo Reply; recompute checksum over the buffer
     * we just built (csum field is zeroed). */
    r_ic->type = 129;
    r_ic->csum = 0;

    uint16_t csum = icmp6_checksum(r_ip6->src, r_ip6->dst,
                                   (uint32_t)icmp_len, 58,
                                   reply + 14 + 40, icmp_len);
    r_ic->csum = ipv6_htons(csum);

    (void)virtio_net_tx(reply, len);
}

/* -------------------------------------------------------------------------
 * Build + send an ICMPv6 Neighbor Advertisement (type 136) in response
 * to a Neighbor Solicitation (type 135) for our link-local address.
 *
 * NA wire format (RFC 4861 §4.4):
 *   type=136 code=0 csum
 *   flags(4 bytes): R(0)|S(1)|O(1)|reserved
 *   target address(16) = our_ll
 *   option: target link-layer address (type=2, len=1, MAC[6])  → 8 bytes
 * Total ICMPv6 message = 4 + 20 + 8 = 32 bytes.
 * -------------------------------------------------------------------------*/
static void send_neighbor_advert(const uint8_t *frame,
                                 const struct ipv6_hdr *ip6)
{
    static uint8_t reply[14 + 40 + 32];
    memset(reply, 0, sizeof(reply));

    struct eth_hdr  *r_eth = (struct eth_hdr *)reply;
    struct ipv6_hdr *r_ip6 = (struct ipv6_hdr *)(reply + 14);
    uint8_t *icmp = reply + 14 + 40;

    uint8_t our_mac[6];
    virtio_net_get_mac(our_mac);

    /* Ethernet: reply to NS source. */
    memcpy(r_eth->dst, ((const struct eth_hdr *)frame)->src, 6);
    memcpy(r_eth->src, our_mac, 6);
    r_eth->ethertype = ipv6_htons(IPV6_ETHERTYPE);

    /* IPv6 header. */
    r_ip6->ver_tc_flow[0] = 0x60;  /* version = 6 */
    r_ip6->ver_tc_flow[1] = 0;
    r_ip6->ver_tc_flow[2] = 0;
    r_ip6->ver_tc_flow[3] = 0;
    r_ip6->payload_len = ipv6_htons(32);
    r_ip6->next_header = 58;       /* ICMPv6 */
    r_ip6->hop_limit   = 255;      /* RFC 4861 mandates 255 for NDP */
    memcpy(r_ip6->src, OUR_LL, 16);
    memcpy(r_ip6->dst, ip6->src, 16);

    /* ICMPv6 NA. */
    icmp[0] = 136;        /* type */
    icmp[1] = 0;          /* code */
    icmp[2] = 0;          /* csum hi (filled below) */
    icmp[3] = 0;          /* csum lo */
    /* Flags: R=0 S=1 O=1 (Solicited + Override). */
    icmp[4] = 0x60;
    icmp[5] = 0;
    icmp[6] = 0;
    icmp[7] = 0;
    /* Target address = our link-local. */
    memcpy(icmp + 8, OUR_LL, 16);
    /* Option: Target Link-Layer Address (type=2, length=1 * 8B). */
    icmp[24] = 2;
    icmp[25] = 1;
    memcpy(icmp + 26, our_mac, 6);

    uint16_t csum = icmp6_checksum(r_ip6->src, r_ip6->dst,
                                   32, 58, icmp, 32);
    icmp[2] = (uint8_t)((csum >> 8) & 0xFF);
    icmp[3] = (uint8_t)(csum & 0xFF);

    (void)virtio_net_tx(reply, sizeof(reply));
}

/* -------------------------------------------------------------------------
 * Public entry point: dispatch a received IPv6 frame.
 * -------------------------------------------------------------------------*/
void handle_ipv6(const uint8_t *frame, size_t len)
{
    /* Need at least eth(14) + ipv6_hdr(40). */
    if (len < 14 + 40) return;

    const struct ipv6_hdr *ip6 = (const struct ipv6_hdr *)(frame + 14);

    /* Version field is the upper nibble of the first byte. */
    if ((ip6->ver_tc_flow[0] >> 4) != 6) return;

    uint16_t payload_len = ipv6_ntohs(ip6->payload_len);
    if ((size_t)payload_len + 14 + 40 > len) return;

    char src_str[40];
    ipv6_addr_str(ip6->src, src_str);

    if (ip6->next_header == 58 && payload_len >= 4) {
        const uint8_t *icmp = frame + 14 + 40;
        uint8_t type = icmp[0];

        if (type == 128) {                 /* Echo Request */
            printf("[ipv6] echo from %s\n", src_str);
            send_echo_reply(frame, len, ip6, payload_len);
            return;
        }
        if (type == 135) {                 /* Neighbor Solicitation */
            /* NS body: reserved(4) + target(16) = 20 bytes minimum. */
            if (payload_len < 4 + 20) return;
            const uint8_t *target = icmp + 8;
            if (memcmp(target, OUR_LL, 16) != 0) {
                printf("[ipv6] NS from %s · target not ours · ignoring\n",
                       src_str);
                return;
            }
            printf("[ipv6] NS from %s\n", src_str);
            send_neighbor_advert(frame, ip6);
            return;
        }
    }

    printf("[ipv6] unknown from %s\n", src_str);
}
