/*
 * sotOs · sotNet γ-3-γ-1 · cross-vspace byte channel between orch and the
 * internal network responder.  Two SPSC rings:
 *   c2p (orch -> responder): RW in orch, RO in responder.  Producer = orch.
 *   p2c (responder -> orch): RW in responder, RO in orch.  Producer = responder.
 * The producer owns the write cursor in the ring header (published with a
 * release store); each consumer keeps its own read cursor in private memory
 * and drains [read, write).  The cursor is the source of truth, so a lost
 * wake-up (the doorbell IPC is fire-and-forget) never loses bytes: the next
 * wake drains everything up to the current cursor.
 */
#ifndef SOTNET_BYTEPIPE_H
#define SOTNET_BYTEPIPE_H

#include <stdint.h>
#include <string.h>

/* Fixed, 2 MiB-aligned vaddrs, identical in both vspaces (address spaces are
 * independent; the RW/RO distinction is a property of the mapped cap, not the
 * address).  Chosen above procd's 0x800000000/0x900000000 region and far above
 * every ELF image / morecore / mmap area — collision-free by construction. */
#define BYTEPIPE_C2P_VADDR   0xA00000000UL   /* orch writes here, responder reads */
#define BYTEPIPE_P2C_VADDR   0xB00000000UL   /* responder writes here, orch reads */

/* N2-T · inbound framed transport · a SECOND SPSC ring pair (root-mapped,
 * same direction discipline as the outbound pair above).  in_c2p carries the
 * inbound REQUEST (orch -> synth); in_p2c carries the REPLY (synth -> orch). */
#define BYTEPIPE_IN_C2P_VADDR  0xC00000000UL   /* orch writes (inbound request), synth reads */
#define BYTEPIPE_IN_P2C_VADDR  0xD00000000UL   /* synth writes (reply), orch reads */

/* SSH interactive canary shell (Phase B) · a THIRD SPSC ring pair carrying the
 * DECRYPTED shell stream between net-synth (SSH crypto) and orch (busybox).
 * SHELL_IN  (net-synth -> orch/busybox stdin):  RW->net-synth, RO->orch.
 * SHELL_OUT (orch/busybox stdout -> net-synth):  RW->orch, RO->net-synth. */
#define BYTEPIPE_SHELL_IN_VADDR  0xE00000000UL   /* net-synth writes decrypted keystrokes, orch/busybox reads */
#define BYTEPIPE_SHELL_OUT_VADDR 0xF00000000UL   /* orch/busybox writes shell output, net-synth reads */

/* Control markers carried as the `local_port` of a 0-or-tiny frame.  Real
 * listen ports are 22/80/443 (< 0xFF00), so the 0xFF00-0xFFFF high range is
 * impossible as a wire port and is used as in-band control signals on the
 * existing inbound rings.  (See include/sotnet/bytepipe_frame.h for the
 * reserved-range note.) */
#define BYTEPIPE_PORT_SHELL_START 0xFF01u  /* net-synth->orch (in_p2c): spawn the SSH busybox */
#define BYTEPIPE_PORT_SHELL_EOF   0xFF02u  /* orch->net-synth (in_c2p): busybox exited → CHANNEL_CLOSE */
#define BYTEPIPE_PORT_SHELL_KILL  0xFF03u  /* net-synth->orch (in_p2c): attacker gone → reap busybox */
#define BYTEPIPE_PORT_SHELL_WINCH 0xFF04u  /* net-synth->orch (in_p2c): pty resize · payload = 4 bytes BE: u16 cols, u16 rows */

#define BYTEPIPE_REGION_PAGES 16u                                  /* 64 KiB each (TUI redraw headroom; was 4) */
#define BYTEPIPE_REGION_BYTES (BYTEPIPE_REGION_PAGES * 4096u)      /* 65536        */
#define BYTEPIPE_HDR_BYTES    64u
#define BYTEPIPE_DATA_BYTES   (BYTEPIPE_REGION_BYTES - BYTEPIPE_HDR_BYTES) /* 65472 */
#define BYTEPIPE_MAGIC        0x50495045u     /* "PIPE" · set by the producer once */

typedef struct {
    volatile uint32_t magic;        /* BYTEPIPE_MAGIC after the producer inits     */
    volatile uint32_t w;            /* producer write cursor (monotonic byte count)*/
    /* p2c only · routing for the current reply, so the consumer (orch) can
     * deliver an opportunistically-drained reply without relying on a doorbell.
     * Written by the producer (responder) before it publishes `w`. */
    volatile uint32_t meta_pid;     /* sotbox the reply is for                     */
    volatile uint32_t meta_src_ip;  /* peer IP   (network byte order)              */
    volatile uint32_t meta_src_port;/* peer port (network byte order)              */
    volatile uint32_t r_pub;        /* F4 · consumer-published read cursor (SHELL_OUT backpressure; 0 elsewhere) */
    uint32_t          _rsvd[10];    /* pad header to BYTEPIPE_HDR_BYTES (was 11)    */
    uint8_t           data[BYTEPIPE_DATA_BYTES];
} bytepipe_ring_t;

_Static_assert(sizeof(bytepipe_ring_t) == BYTEPIPE_HDR_BYTES + BYTEPIPE_DATA_BYTES,
               "bytepipe_ring_t header must stay BYTEPIPE_HDR_BYTES (64) bytes");

/* Producer: stamp the routing for the reply about to be pushed (p2c). */
static inline void bytepipe_set_meta(bytepipe_ring_t *r, uint32_t pid,
                                     uint32_t src_ip_be, uint32_t src_port_be)
{
    r->meta_pid      = pid;
    r->meta_src_ip   = src_ip_be;
    r->meta_src_port = src_port_be;
}

/* Producer init: call once, on the producer side, after the region is mapped. */
static inline void bytepipe_producer_init(bytepipe_ring_t *r)
{
    r->w = 0u;
    __atomic_store_n(&r->magic, BYTEPIPE_MAGIC, __ATOMIC_RELEASE);
}

/* Producer push: append n bytes.  Sole producer owns `w`. */
static inline uint32_t bytepipe_push(bytepipe_ring_t *r,
                                     const uint8_t *src, uint32_t n)
{
    if (n > BYTEPIPE_DATA_BYTES) n = BYTEPIPE_DATA_BYTES;
    uint32_t w = r->w;
    for (uint32_t i = 0; i < n; ++i)
        r->data[(w + i) % BYTEPIPE_DATA_BYTES] = src[i];
    __atomic_store_n(&r->w, w + n, __ATOMIC_RELEASE);  /* publish after the bytes */
    return n;
}

/* Consumer pull: drain up to `max` newly-available bytes from *rd (private
 * read cursor) into dst.  Returns the count drained; advances *rd. */
static inline uint32_t bytepipe_pull(bytepipe_ring_t *r, uint32_t *rd,
                                     uint8_t *dst, uint32_t max)
{
    uint32_t w     = __atomic_load_n(&r->w, __ATOMIC_ACQUIRE);
    uint32_t avail = w - *rd;                 /* unsigned wrap-safe */
    if (avail > BYTEPIPE_DATA_BYTES) {        /* producer lapped us · keep newest */
        *rd   = w - BYTEPIPE_DATA_BYTES;
        avail = BYTEPIPE_DATA_BYTES;
    }
    uint32_t n = (avail < max) ? avail : max;
    for (uint32_t i = 0; i < n; ++i)
        dst[i] = r->data[(*rd + i) % BYTEPIPE_DATA_BYTES];
    *rd += n;
    return n;
}

#endif /* SOTNET_BYTEPIPE_H */
