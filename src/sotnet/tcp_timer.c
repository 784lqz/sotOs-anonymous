/*
 * sotOs · sotNet · T5 · TCP retransmission timer.
 *
 * STRONG override of tcp_timer_tick() (declared WEAK in src/sotnet/tcp.c).
 * Driven from the orch poll loop in src/orch/bootstrap.c · fires once per
 * polling iteration.
 *
 * Behavior:
 *   1. Always bump the monotonic tick counter via tcp_tick_advance() · this
 *      preserves the scaffold's weak default (other code reads last_tx_ms
 *      relative to tcp_now_ms() and depends on it advancing).
 *   2. Walk the connection table via tcp_conn_iter():
 *        · SYN_SENT / SYN_RCVD / ESTABLISHED with unACKed data
 *          (snd_una < snd_nxt) and (now - last_tx_ms) > 1000 ticks:
 *            → retransmit the cached segment.
 *        · TIME_WAIT with (now - time_wait_tick) > 60000 ticks:
 *            → free the connection slot.
 *
 * NOTE on units · "ticks" are NOT real milliseconds.  They are increments of
 * the poll-loop counter and fire much faster than wall-clock seconds in QEMU.
 * The 1000/60000 thresholds are tuning knobs · δ-1 accepts aggressive retx
 * and fast TIME_WAIT cleanup as a deliberate trade-off.
 *
 * Bounded, no malloc, C11.  Single-threaded use from orch's fault loop.
 */

#include <sotnet/tcp.h>
#include <sotnet/tcp_conn.h>
#include <stdio.h>
#include <stdint.h>
#include <stddef.h>

/* Wall-clock pacing.  The retx/TIME_WAIT timers count poll-loop *iterations*,
 * not real time — so their rate is hostage to how fast the caller spins.  The
 * operator `watch` console polls orch in a TIGHT loop, so a connection's retx
 * budget could burn down in milliseconds and RST a live SSH/TLS session before
 * the real remote peer (over SLIRP) could ACK — exactly why `watch` broke the
 * SSH demo.  Gate the *effective* tick to a fixed slice of real wall-clock (via
 * rdtsc) so the tick rate — and thus the retransmit interval — is independent of
 * the call rate.  Self-contained (sotcron's calibrated clock is a separate
 * image): we don't need ms-exactness, only a spin-rate-independent cap.  At a
 * 2.4 GHz KVM-host-typical TSC TCP_TSC_PER_TICK ≈ 1 ms; across the real 1–5 GHz
 * range that maps the retx interval to 0.4–2 s — fine for the honeypot. */
static inline uint64_t tcp_rdtsc(void) {
#if defined(__x86_64__) || defined(__i386__)
    uint32_t lo, hi;
    __asm__ volatile("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;   /* non-x86 · pacing disabled, falls back to per-call advance */
#endif
}
#define TCP_TSC_PER_TICK     2400000ull   /* ~1 ms @ 2.4 GHz */

/* Tuning knobs · 1 tick ≈ 1 ms once wall-clock pacing is active (below). */
#define TCP_RETX_TICKS       1000u    /* ~1 s between unACKed retransmits */
#define TCP_TIME_WAIT_TICKS  4000u    /* ~4 s TIME_WAIT before slot reclaim */
/* Cap consecutive unACKed retransmits.  Without it an abandoned/half-open peer
 * (a port scan, a bare TCP probe, an ssh that drops mid-banner) leaves a segment
 * retransmitting FOREVER — flooding the log and wedging the single-threaded
 * honeypot so new connections can't be served.  After the cap we give up: RST the
 * peer + free the slot. */
#define TCP_RETX_MAX         8u
/* Idle reap · an ESTABLISHED conn with NOTHING to retransmit (snd_una==snd_nxt) that
 * has gone silent this long is a stuck/abandoned handshake: a deception HTTP/TLS conn
 * completes in well under a second, a half-open scan never speaks, a starved responder
 * never replies. Without reaping they leak a slot forever → the conn table fills →
 * "SYN drop · conn table full" → the honeypot stops accepting (TLS :443 went dark).
 * ~30 s @ 1 ms/tick — long enough not to drop a human mid-password-entry (a realism
 * tell), short enough to drain scans/abandoned handshakes. Only fires once last_tx_ms is
 * stale, which now requires NO data/SYN/FIN for the window (bare ACKs no longer refresh
 * it — see tcp.c), so a banner-stuck SSH conn finally ages out. The live interactive
 * shell is exempt (tcp_conn_protected). */
#define TCP_IDLE_TICKS       30000u
/* CLOSE_WAIT completion · the peer FIN'd us and the deception reply already went out, but
 * the honey "app" never calls close — so a couple seconds after the peer's FIN, complete
 * the passive close ourselves (FIN → LAST_ACK).  Without it conns leak in CLOSE_WAIT, where
 * the bulk of rapid sequential recon sessions (T3) piled up → "SYN drop · conn table full". */
#define TCP_CLOSE_WAIT_TICKS 2000u

/* Weak default 0 in tcp.c; orch overrides it to protect the live SSH shell conn (which
 * is legitimately long-lived and idle between keystrokes, so it must NOT be idle-reaped). */
extern int tcp_conn_protected(uint16_t conn_id);

void tcp_timer_tick(void)
{
    /* Step 0 · wall-clock throttle.  Skip the whole tick (counter + scan) if
     * less than ~1 ms of REAL time has elapsed since the last effective tick,
     * capping the tick rate at ~1000/s regardless of how fast we're polled.  A
     * fast operator-`watch` loop can't burn the retransmit budget faster than
     * the remote peer can ACK.  No-op if rdtsc is unavailable (now_tsc==0). */
    {
        uint64_t now_tsc = tcp_rdtsc();
        if (now_tsc) {
            static uint64_t last_tick_tsc;
            if (last_tick_tsc == 0) last_tick_tsc = now_tsc;
            if (now_tsc - last_tick_tsc < TCP_TSC_PER_TICK) return; /* too soon */
            last_tick_tsc = now_tsc;
        }
    }

    /* Step 1 · always advance the monotonic counter first.  Scaffold's weak
     * default did this; we MUST preserve it so last_tx_ms comparisons stay
     * meaningful for the rest of the TCP code. */
    tcp_tick_advance();

    /* Step 2 · scan the connection table. */
    uint32_t now = tcp_now_ms();
    int iter_state = -1;
    struct tcp_conn *conn;

    /* tcp_conn_iter(-1) seeds the walk · returns NULL when done. */
    while ((conn = tcp_conn_iter(&iter_state)) != NULL) {
        switch (conn->state) {

        case TCP_STATE_SYN_SENT:
        case TCP_STATE_SYN_RCVD:
        case TCP_STATE_ESTABLISHED:
            /* Retransmit if we have unACKed data and the retx timer expired. */
            if (conn->snd_una < conn->snd_nxt &&
                (now - conn->last_tx_ms) > TCP_RETX_TICKS) {
                if (conn->retx_count >= TCP_RETX_MAX) {
                    /* Peer is gone · stop the storm: RST + free the slot. */
                    printf("[tcp-timer] conn=%d retx cap (%u) · RST + free\n",
                           iter_state, (unsigned)conn->retx_count);
                    tcp_send_segment(conn, TCP_FLAG_RST, NULL, 0);
                    tcp_conn_free(conn);
                    break;
                }
                conn->retx_count++;
                printf("[tcp-timer] retx conn=%d seq=%u len=%u (try %u/%u)\n",
                       iter_state,
                       (unsigned)conn->snd_una,
                       (unsigned)conn->tx_len,
                       (unsigned)conn->retx_count, (unsigned)TCP_RETX_MAX);
                /* tcp_send_segment refreshes conn->last_tx_ms internally, so
                 * we won't busy-loop retransmitting on the next tick. */
                tcp_send_segment(conn, conn->tx_flags,
                                 conn->tx_buf, conn->tx_len);
            }
            /* IDLE REAP · ESTABLISHED with no unACKed data, silent for too long, and
             * not the protected live shell → a stuck/abandoned conn leaking a slot. */
            else if (conn->state == TCP_STATE_ESTABLISHED &&
                     conn->snd_una == conn->snd_nxt &&
                     (now - conn->last_tx_ms) > TCP_IDLE_TICKS &&
                     !tcp_conn_protected(conn->conn_id)) {
                printf("[tcp-timer] conn=%d idle %u ticks (no progress) · stuck/abandoned · RST + free\n",
                       iter_state, (unsigned)(now - conn->last_tx_ms));
                tcp_send_segment(conn, TCP_FLAG_RST, NULL, 0);
                tcp_conn_free(conn);
                break;
            }
            break;

        case TCP_STATE_CLOSE_WAIT:
            /* The peer closed; the deception session is over (its reply went out before the
             * peer's FIN), but the app never calls close — so complete the passive close
             * here: send our FIN (→ LAST_ACK).  Otherwise the conn leaks in CLOSE_WAIT,
             * where rapid sequential recon sessions (T3) accumulated.  Live shell exempt. */
            if ((now - conn->last_tx_ms) > TCP_CLOSE_WAIT_TICKS &&
                !tcp_conn_protected(conn->conn_id)) {
                extern void sotnet_tcp_close(struct tcp_conn *);
                sotnet_tcp_close(conn);          /* CLOSE_WAIT → LAST_ACK (FIN sent) */
            }
            break;

        case TCP_STATE_FIN_WAIT_1:
        case TCP_STATE_FIN_WAIT_2:
        case TCP_STATE_CLOSING:
        case TCP_STATE_LAST_ACK:
            /* Close handshake stalled (peer gone / not ACKing our FIN).  Reclaim the slot
             * after a grace period rather than leak it; a normal close finishes far sooner
             * via tcp_close.c (LAST_ACK → CLOSED → free) or TIME_WAIT. */
            if ((now - conn->last_tx_ms) > TCP_IDLE_TICKS) {
                printf("[tcp-timer] conn=%d close stalled (state=%d) · free\n",
                       iter_state, (int)conn->state);
                tcp_conn_free(conn);
            }
            break;

        case TCP_STATE_TIME_WAIT:
            if ((now - conn->time_wait_tick) > TCP_TIME_WAIT_TICKS) {
                printf("[tcp-timer] TIME_WAIT done · freed\n");
                tcp_conn_free(conn);
            }
            break;

        default:
            /* CLOSED, LISTEN, FIN_WAIT_*, CLOSE_WAIT, CLOSING, LAST_ACK ·
             * no timer-driven action in this phase. */
            break;
        }
    }
}
