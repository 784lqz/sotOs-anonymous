/*
 * sotOs · sotNet-β-3 · minimal Ethernet/ARP/ICMP stack header.
 *
 * Provides a thin network stack above virtio-net raw frame TX/RX.
 * Handles:
 *   - ARP request → ARP reply (so the host can discover our MAC).
 *   - ICMP echo request → ICMP echo reply (ping response).
 *
 * All multi-byte fields in on-wire structures are big-endian (network byte
 * order).  Use htons_/ntohs_ from sotnet.c internals — do not include
 * <arpa/inet.h> (not available in seL4/muslc userspace without posix layer).
 */
#ifndef SOTNET_SOTNET_H
#define SOTNET_SOTNET_H

#include <stdint.h>
#include <stddef.h>

/* -------------------------------------------------------------------------
 * On-wire frame structures (all packed · no padding).
 * -------------------------------------------------------------------------*/

struct eth_hdr {
    uint8_t  dst[6];
    uint8_t  src[6];
    uint16_t ethertype;   /* big-endian: 0x0806 ARP, 0x0800 IPv4 */
} __attribute__((packed));

struct arp_pkt {
    uint16_t htype;   /* 1 = Ethernet · BE */
    uint16_t ptype;   /* 0x0800 = IPv4 · BE */
    uint8_t  hlen;    /* 6 */
    uint8_t  plen;    /* 4 */
    uint16_t oper;    /* 1 = request, 2 = reply · BE */
    uint8_t  sha[6];
    uint8_t  spa[4];
    uint8_t  tha[6];
    uint8_t  tpa[4];
} __attribute__((packed));

struct ipv4_hdr {
    uint8_t  ihl_ver;      /* (4<<4)|5 */
    uint8_t  tos;
    uint16_t total_len;    /* BE */
    uint16_t ident;
    uint16_t flags_frag;
    uint8_t  ttl;
    uint8_t  proto;        /* 1 = ICMP */
    uint16_t hdr_csum;     /* BE · ones-complement */
    uint32_t src;          /* BE */
    uint32_t dst;          /* BE */
} __attribute__((packed));

struct icmp_hdr {
    uint8_t  type;    /* 8 = echo request, 0 = echo reply */
    uint8_t  code;
    uint16_t csum;    /* BE */
    uint16_t ident;
    uint16_t seq;
} __attribute__((packed));

/* -------------------------------------------------------------------------
 * Public API
 * -------------------------------------------------------------------------*/

/*
 * sotnet_init: record our IP address (network byte order) and read the
 * hardware MAC from the virtio-net device.  Must be called after
 * virtio_net_init_queues().
 *
 * our_ip_be: IP in network byte order.  10.0.2.15 = 0x0F02000A.
 */
void sotnet_init(uint32_t our_ip_be);

/*
 * sotnet_get_our_ip: return the IP address passed to sotnet_init, in
 * network byte order.  Returns 0 if sotnet_init has not been called yet.
 */
uint32_t sotnet_get_our_ip(void);

/*
 * sotnet_resolve_gateway: actively resolve the L2 (MAC) address of next-hop
 * gateway gw_ip_be via ARP.  Broadcasts an ARP request (re-sent periodically),
 * polls the RX ring for a reply, and learns the sender into the ARP cache.
 * Bounded + fail-soft: returns 0 with out_mac filled on success, -1 on timeout.
 * Requires sotnet_init() to have run (uses our IP/MAC).
 */
int sotnet_resolve_gateway(uint32_t gw_ip_be, uint8_t out_mac[6]);

/*
 * sotnet_poll: drain one frame from the RX ring and process it.
 *   - ARP request targeting our IP → send ARP reply.
 *   - ICMP echo request targeting our IP → send ICMP echo reply.
 *   - Anything else → silently ignored.
 *
 * Returns 0 if a frame was processed, -1 if no frame was waiting.
 */
int sotnet_poll(void);

/*
 * sotnet_send_udp: build a complete eth+ip+udp packet and transmit it via
 * virtio_net_tx.
 *
 *   dst_ip_be  : destination IPv4 address, network byte order.
 *   dst_port_be: destination UDP port, network byte order.
 *   src_port_be: source UDP port, network byte order.
 *   data       : payload (copied verbatim into UDP data area).
 *   data_len   : payload length; capped to 1400 bytes internally.
 *   pid        : originating sotbox synthetic_pid (0 = kernel/bootstrap).  Plumbed
 *                through to the anomaly NET_PRECOMMIT hook so per-pid rules
 *                (cumulative byte budget, Tier-2 auto-promote) can attribute.
 *
 * Returns 0 on success, negative on error (forwarded from virtio_net_tx).
 * Emits: [sotnet-β] UDP send · <ip>:<port> len=<n>
 */
int sotnet_send_udp(uint32_t dst_ip_be, uint16_t dst_port_be,
                    uint16_t src_port_be, const void *data, size_t data_len,
                    uint32_t pid);

/* -------------------------------------------------------------------------
 * Flow tracker · sotNet-ζ
 * -------------------------------------------------------------------------*/

#define SOTNET_MAX_FLOWS 8

typedef struct sotnet_flow_entry {
    int      in_use;
    uint32_t pid;
    uint32_t src_ip;      /* BE */
    uint32_t dst_ip;      /* BE */
    uint16_t src_port;    /* BE */
    uint16_t dst_port;    /* BE */
    uint32_t bytes_out;
    uint32_t bytes_in;
    uint64_t last_seen_tsc;
} sotnet_flow_entry_t;

/*
 * sotnet_record_send: update flow table for an outgoing UDP send.
 * Called from sotnet_send_udp.  pid=0 for kernel-initiated sends.
 */
void sotnet_record_send(uint32_t pid, uint32_t dst_ip, uint16_t dst_port,
                        uint16_t src_port, uint32_t len);

/*
 * sotnet_get_flows: copy active flow entries into out[0..max-1].
 * Returns number of entries written.
 */
int sotnet_get_flows(sotnet_flow_entry_t *out, int max);

/* -------------------------------------------------------------------------
 * sotNet-γ Phase 1 · Silenced Connection drop counters.
 * -------------------------------------------------------------------------*/

/*
 * sotnet_record_silenced_drop: called from lucas_sys_sendto when st->functor->
 * writes_silenced is true.  Increments the global drop + byte counters.
 * pid is recorded for future per-flow tracking (Phase 2).
 */
void sotnet_record_silenced_drop(uint32_t pid, uint32_t len);

/*
 * sotnet_get_silenced_drops: return total number of silenced-dropped sendto calls
 * since boot.
 */
uint32_t sotnet_get_silenced_drops(void);

/*
 * sotnet_get_silenced_bytes: return total bytes silently dropped by Silenced
 * Connection since boot.
 */
uint32_t sotnet_get_silenced_bytes(void);

/* -------------------------------------------------------------------------
 * sotNet-δ · STS (Secure Transactional Sockets) Phase 1 counters.
 * -------------------------------------------------------------------------*/

/*
 * sotnet_get_sto_commits: return number of UDP sends that completed with
 * a successful STO COMMIT since boot.
 */
uint32_t sotnet_get_sto_commits(void);

/*
 * sotnet_get_sto_aborts: return number of UDP sends that failed and were
 * recorded as STO ABORT since boot.
 */
uint32_t sotnet_get_sto_aborts(void);

/* -------------------------------------------------------------------------
 * sotNet-γ Phase 3-D-2 · pending_recv queue.
 *
 * When net-synth returns a synthetic response via ORCH_OP_SYNTH_RESPONSE,
 * the payload lands in orch but the originating sotbox is not currently
 * blocked in a recvfrom() syscall.  Buffer the body in a small fixed-size
 * static queue keyed by (sotbox_pid, src_ip, src_port) so that LUCAS can
 * deliver it on a later recvfrom (LUCAS dispatch wiring → δ-D-3).
 *
 * Scope for δ-D-2: queue side ONLY · enqueue from orch, dequeue API exposed,
 * dump for sotShell introspection.  No LUCAS integration yet.
 * -------------------------------------------------------------------------*/

#define SOTNET_RECV_QUEUE_SIZE 16
#define SOTNET_RECV_BODY_MAX   256

/*
 * sotnet_recv_enqueue: stash a synthetic response payload for the sotbox
 * with `pid` to consume on its next recvfrom().  Returns 0 on success, -1
 * if the queue is full.  Emits:
 *   [sotnet-γ] queued recv · pid=X src=A.B.C.D:P body_len=N
 * len is truncated to SOTNET_RECV_BODY_MAX.
 */
int sotnet_recv_enqueue(uint32_t pid, const uint8_t src_ip[4],
                        uint16_t src_port, const uint8_t *body, size_t len);

/*
 * sotnet_recv_dequeue: pop the oldest pending recv for `pid` whose source
 * matches `want_ip_be` (network-order IP · 0 = any source, for unconnected
 * sockets).  A connected UDP socket passes its connected peer so it never
 * receives a datagram from the wrong server (the cross-wire bug between two
 * connected DNS sockets).  Copies up to `buf_max` bytes of body into
 * `out_buf`, fills `out_src_ip`/`out_src_port`, frees the slot, returns the
 * original body length (may exceed buf_max).  Returns -1 if no slot matches.
 */
int sotnet_recv_dequeue(uint32_t pid, uint32_t want_ip_be,
                        uint8_t *out_buf, size_t buf_max,
                        uint8_t out_src_ip[4], uint16_t *out_src_port);

/* sotnet_recv_pending: non-destructive · 1 if a pending recv datagram is queued
 * for `pid` (lets poll()/select() report the socket readable before recvfrom). */
int sotnet_recv_pending(uint32_t pid);

/* sotnet_recv_peek_len: non-destructive · byte length of the first pending recv
 * datagram for `pid` whose source matches `want_ip_be` (0 = any).  0 if none.
 * Backs ioctl(FIONREAD) so glibc can size its on-demand DNS answer buffer. */
int sotnet_recv_peek_len(uint32_t pid, uint32_t want_ip_be);

/*
 * sotnet_recv_dump: print all in-use slots (introspection · sotShell
 * `synth-queue` command).  Emits one line per slot:
 *   [sotnet-γ] queue · slot=i pid=X src=A.B.C.D:P body_len=N
 */
void sotnet_recv_dump(void);

#endif /* SOTNET_SOTNET_H */
