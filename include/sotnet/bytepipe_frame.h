/* sotOs · N2-T · length-prefixed, conn-tagged frames over a bytepipe_ring_t.
 * A frame = [hdr (8B)][len payload bytes], pushed as ONE contiguous run so the
 * ring's release-published `w` only exposes complete frames. The consumer
 * deframes safely: it never advances its read cursor past a partial frame. */
#ifndef SOTNET_BYTEPIPE_FRAME_H
#define SOTNET_BYTEPIPE_FRAME_H
#include <sotnet/bytepipe.h>
#include <stdint.h>
#include <string.h>

/* RESERVED local_port range: 0xFF00-0xFFFF are NOT real listen ports (real
 * response_profiles listen on 22/80/443). They are reserved as in-band control markers
 * carried on the existing inbound rings (e.g. BYTEPIPE_PORT_SHELL_START/EOF/KILL
 * in include/sotnet/bytepipe.h). A frame whose local_port is in this range is a
 * control signal, never wire data — the consumer must NOT tcp_send it. */
typedef struct {
    uint16_t conn_id;     /* accepted-conn id this frame belongs to (0 = invalid) */
    uint16_t local_port;  /* listen port the adversary hit (host order; for N2-R) */
    uint32_t len;         /* payload bytes following this header */
} bytepipe_frame_hdr_t;   /* 8 bytes */

#define BYTEPIPE_FRAME_HDR_SZ ((uint32_t)sizeof(bytepipe_frame_hdr_t))

/* Push one frame (header+payload) as a single ring push so `w` publishes the
 * whole frame atomically. Returns bytes pushed (0 if it would not fit). */
static inline uint32_t bytepipe_push_frame(bytepipe_ring_t *r, uint16_t conn_id,
                                           uint16_t local_port,
                                           const uint8_t *payload, uint32_t len)
{
    if (BYTEPIPE_FRAME_HDR_SZ + len > BYTEPIPE_DATA_BYTES) return 0; /* too big */
    static uint8_t stage[BYTEPIPE_DATA_BYTES];
    bytepipe_frame_hdr_t h = { conn_id, local_port, len };
    memcpy(stage, &h, BYTEPIPE_FRAME_HDR_SZ);
    if (len && payload) memcpy(stage + BYTEPIPE_FRAME_HDR_SZ, payload, len);
    return bytepipe_push(r, stage, BYTEPIPE_FRAME_HDR_SZ + len);
}

/* Pull one complete frame into out_hdr/out_buf. Returns 1 if a frame was
 * dequeued, 0 if none complete yet (cursor left untouched on a partial frame).
 * Single-consumer: *rd is the caller's private read cursor. */
static inline int bytepipe_pull_frame(bytepipe_ring_t *r, uint32_t *rd,
                                      bytepipe_frame_hdr_t *out_hdr,
                                      uint8_t *out_buf, uint32_t out_max)
{
    uint32_t w = __atomic_load_n(&r->w, __ATOMIC_ACQUIRE);
    uint32_t avail = w - *rd;                          /* unsigned wrap-safe */
    if (avail > BYTEPIPE_DATA_BYTES) {                 /* producer lapped us */
        *rd = w - BYTEPIPE_DATA_BYTES; avail = BYTEPIPE_DATA_BYTES;
    }
    if (avail < BYTEPIPE_FRAME_HDR_SZ) return 0;        /* no full header yet */
    bytepipe_frame_hdr_t h;
    for (uint32_t i = 0; i < BYTEPIPE_FRAME_HDR_SZ; ++i)
        ((uint8_t *)&h)[i] = r->data[(*rd + i) % BYTEPIPE_DATA_BYTES];
    if (h.len > BYTEPIPE_DATA_BYTES) return 0;          /* corrupt · skip (don't advance) */
    if (avail < BYTEPIPE_FRAME_HDR_SZ + h.len) return 0;/* payload incomplete · wait */
    if (h.len > out_max) return 0;                      /* caller buf too small · do NOT truncate+advance */
    for (uint32_t i = 0; i < h.len; ++i)
        out_buf[i] = r->data[(*rd + BYTEPIPE_FRAME_HDR_SZ + i) % BYTEPIPE_DATA_BYTES];
    *rd += BYTEPIPE_FRAME_HDR_SZ + h.len;               /* commit only when complete */
    if (out_hdr) *out_hdr = h;
    return 1;
}
#endif
