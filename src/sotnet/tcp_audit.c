/*
 * sotOs · sotNet · T8 · TCP connection-open audit hook (STRONG override).
 *
 * Provides the STRONG override of the weak `tcp_audit_open(conn)` declared in
 * include/sotnet/tcp_conn.h.  Whenever a TCP connection reaches a successful
 * open (ACTIVE OPEN → ESTABLISHED in T2, or PASSIVE OPEN third-ACK in T1),
 * the per-state handler calls `tcp_audit_open(conn)` and we relay an
 * audit-only ANOMALY_EV_TCP_OPEN event to anomaly-ext via the orch anomaly
 * EP.
 *
 * Same weak/strong pattern as src/orch/backends_sotnet.c's DNS_HIT override,
 * but lives here under src/sotnet/ so the TCP per-state handlers can call
 * straight into us via the strong override without pulling orch-side headers
 * into the wider sotnet sources.  The anomaly EP accessor itself is exposed
 * via an extern declaration · the symbol is defined in src/orch/sotbox_table.c
 * and pre-set to 0 until A3-Phase-B-v2 spawns anomaly-ext.
 *
 * Message layout (canonical · also documented in include/orch/proto.h):
 *   MR(0) = pid (δ-2 · origin_pid stashed on the conn at tcp_active_open;
 *                0 for passive opens or unattributed flows)
 *   MR(1) = ANOMALY_EV_TCP_OPEN
 *   MR(2) = remote_ip_be (network byte order)
 *   MR(3) = (remote_port_be << 16) | local_port_be  (both BE, packed)
 *
 * Fire-and-forget · anomaly-ext replies length=0 once it has logged.
 */

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include <sotnet/tcp_conn.h>
#include <orch/proto.h>
#include <sotguard/event.h>

/* Anomaly EP accessor lives in src/orch/sotbox_table.c · same pattern as
 * src/sotnet/sotnet.c's pre-commit hook (line 43). */
extern seL4_CPtr orch_get_anomaly_ep(void);

/* SG-NET Phase 2 · per-emit monotonic timestamp for sotGuard event bus.
 * sotguard_event_t.timestamp is documented as a monotonic counter, NOT
 * wall-clock (include/sotguard/event.h line 17).  Static so each
 * trigger-site producer has its own counter; collisions across sites are
 * acceptable since correlation rules key off (pid, type, detail). */
static uint64_t g_sg_tcp_open_ts = 0;

void tcp_audit_open(struct tcp_conn *conn)
{
    if (conn == NULL) {
        return;
    }

    /* Decode ports for logging · stored BE in the conn struct. */
    uint16_t rport_be = conn->remote_port_be;
    uint16_t lport_be = conn->local_port_be;
    uint16_t rport_h  = (uint16_t)(((rport_be & 0xFF) << 8) | ((rport_be >> 8) & 0xFF));
    uint16_t lport_h  = (uint16_t)(((lport_be & 0xFF) << 8) | ((lport_be >> 8) & 0xFF));
    const uint8_t *rip = (const uint8_t *)&conn->remote_ip_be;

    printf("[tcp-audit] open · remote=%u.%u.%u.%u:%u local=:%u\n",
           rip[0], rip[1], rip[2], rip[3], rport_h, lport_h);

    seL4_CPtr anomaly_ep = orch_get_anomaly_ep();
    if (anomaly_ep != 0) {
        /* Pack ports as (remote_be << 16) | local_be · upper 16 = remote,
         * lower 16 = local.  Both stay in network byte order;
         * anomaly-ext is the only consumer and it decodes them with the
         * same shift mask. */
        uint32_t ports_packed =
            ((uint32_t)rport_be << 16) | (uint32_t)lport_be;

        seL4_SetMR(0, (seL4_Word)conn->origin_pid);  /* δ-2: per-sotbox attribution */
        seL4_SetMR(1, ANOMALY_EV_TCP_OPEN);
        seL4_SetMR(2, (seL4_Word)conn->remote_ip_be);
        seL4_SetMR(3, (seL4_Word)ports_packed);

        /* Synchronous · matches the graph_curvature / DNS anomaly events.
         * REPLY-DRIVEN promote: anomaly-ext returns the target tier in MR(0)
         * (0 = audit-only).  It NO LONGER does seL4_Call(orch_ep, PROMOTE_TIER)
         * — that re-entrant Call deadlocks when the connect originates inside
         * orch (e.g. a nested egress fault loop).  We apply the promotion here,
         * in the orch address space, with a plain function call. */
        seL4_MessageInfo_t reply = seL4_Call(anomaly_ep,
                  seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 4));
        int promote_tier = (seL4_MessageInfo_get_length(reply) > 0)
                         ? (int)seL4_GetMR(0) : 0;
        if (promote_tier > 0 && conn->origin_pid >= 1) {
            extern void orch_anomaly_apply_promote(uint32_t pid, int tier);
            orch_anomaly_apply_promote((uint32_t)conn->origin_pid, promote_tier);
        }
    }
    /* If anomaly_ep == 0 (pre-spawn / anomaly disabled) we skip the IPC
     * but still emit into sotGuard below · the in-orch correlation ring is
     * independent of anomaly-ext. */

    /* SG-NET Phase 2 · ADDITIVE sotGuard event-bus emit.  Sibling of the
     * anomaly-ext IPC above · the IPC stays as the authoritative audit
     * path; this emit feeds the in-orch correlation ring for future
     * policy-engine rules.  Best-effort lossy by design. */
    {
        sotguard_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = (uint32_t)conn->origin_pid;
        ev.type = SG_EV_NET_CONNECT;
        ev.timestamp = ++g_sg_tcp_open_ts;
        ev.detail.net.ip_be   = conn->remote_ip_be;
        ev.detail.net.port_be = conn->remote_port_be;
        ev.detail.net.len     = 0;   /* connect carries no payload */
        (void)sotguard_emit(&ev);
    }
}
