/*
 * sotGuard · event bus ring buffer implementation.
 *
 * Static storage, no locking (orch is single-threaded).  Producer writes
 * at g_head, advancing mod SOTGUARD_RING_CAPACITY.  Consumers peek the
 * most-recent N entries via sotguard_recent(); read order is newest-first
 * so correlation rules can short-circuit on the freshest hits.
 *
 * Overflow semantics: lossy.  Once g_total >= SOTGUARD_RING_CAPACITY the
 * head index laps and overwrites the oldest entry.  Rules MUST tolerate
 * gaps.
 *
 * α · PR 4 · every successful emit is mirrored to the sotfs WAL via
 * sotfs_wal_log_anomaly_ev (gated by g_wal_attached so the boot-time
 * pre-bootstrap events from lazy_init paths stay out of the WAL).
 */
#include <sotguard/event.h>
#include <sotfs/wal.h>
#include <sotfs/wal_ipc.h>

static sotguard_event_t g_ring[SOTGUARD_RING_CAPACITY];
static size_t           g_head;   /* next slot to write */
static uint64_t         g_total;  /* monotonic emit counter */

void
sotguard_event_init(void)
{
    for (size_t i = 0; i < SOTGUARD_RING_CAPACITY; i++) {
        g_ring[i] = (sotguard_event_t){0};
    }
    g_head = 0;
    g_total = 0;
}

int
sotguard_emit(const sotguard_event_t *ev)
{
    if (ev == NULL) {
        return -1;
    }
    if (ev->type == SG_EV_NONE || ev->type > SOTGUARD_EMIT_MAX_KIND) {
        return -1;   /* sottrace kinds 13..15 are ring-only · rejected here */
    }

    g_ring[g_head] = *ev;
    g_head = (g_head + 1) % SOTGUARD_RING_CAPACITY;
    g_total++;

    /* α · PR 4 · mirror to sotfs WAL.  In orch (host of sotos-sotfs)
     * this is a direct call; in other subsystems that link sotguard
     * but not sotos-sotfs (none today, but future-proofing) the symbol
     * stays unresolved and the call would fail at link time.  Today
     * sotguard only ships inside orch / sotOs-lucas via the orch
     * executable so direct linkage is safe.  Pack the most useful
     * subset of the union into the anomaly_ev payload · the WAL
     * record carries the kind already in its outer header. */
    if (g_wal_attached) {
        sotfs_wal_payload_anomaly_ev_t rec = {
            .timestamp = ev->timestamp,
            .pid       = ev->pid,
            .kind      = ev->type,
            .arg0      = 0,
            .arg1      = 0,
        };
        /* Carry the most descriptive field of each detail union into
         * arg0/arg1 · best-effort, not a stable ABI.  PR 6 (replay-
         * applies) decodes by kind so this mapping can evolve. */
        switch (ev->type) {
        case SG_EV_FS_READ:
        case SG_EV_FS_WRITE:
        case SG_EV_FS_OPEN:
            rec.arg0 = (uint32_t)ev->detail.fs.fd;
            rec.arg1 = (uint32_t)ev->detail.fs.bytes;
            break;
        case SG_EV_NET_CONNECT:
        case SG_EV_NET_SEND:
        case SG_EV_NET_RECV:
            rec.arg0 = ev->detail.net.ip_be;
            rec.arg1 = (uint32_t)(((uint32_t)ev->detail.net.port_be << 16)
                                  | (uint32_t)ev->detail.net.len);
            break;
        case SG_EV_DNS_LOOKUP:
            rec.arg0 = ev->detail.dns.ip_be;
            rec.arg1 = 0;
            break;
        case SG_EV_FAULT_SYSCALL:
            rec.arg0 = ev->detail.fault.syscall_nr;
            rec.arg1 = (uint32_t)ev->detail.fault.rip;
            break;
        case SG_EV_GRAPH_CURVATURE_RANSOM:
        case SG_EV_GRAPH_CURVATURE_LATERAL:
            rec.arg0 = ev->detail.graph_curvature.rule_kind;
            rec.arg1 = ev->detail.graph_curvature.severity;
            break;
        default:
            /* SG_EV_PLEDGE_VIOL, SG_EV_CANARY_READ · no structured detail
             * beyond pid/type/timestamp · args stay 0. (The sottrace kinds
             * 13..15 never reach here — they are rejected at the validity
             * gate above, being ring-only / never routed through WAL.) */
            break;
        }
        (void)sotfs_wal_log_anomaly_ev(&rec);
    }
    return 0;
}

size_t
sotguard_recent(sotguard_event_t *out, size_t want)
{
    if (out == NULL || want == 0) {
        return 0;
    }

    /* Number of valid entries currently in the ring.  Before the first
     * lap, only g_total slots are populated; after, the full capacity. */
    size_t valid = (g_total < SOTGUARD_RING_CAPACITY)
                       ? (size_t)g_total
                       : SOTGUARD_RING_CAPACITY;
    if (want > valid) {
        want = valid;
    }

    /* Walk backwards from the slot just before g_head, newest-first. */
    size_t idx = g_head;
    for (size_t i = 0; i < want; i++) {
        idx = (idx == 0) ? (SOTGUARD_RING_CAPACITY - 1) : (idx - 1);
        out[i] = g_ring[idx];
    }
    return want;
}

uint64_t
sotguard_total_emitted(void)
{
    return g_total;
}
