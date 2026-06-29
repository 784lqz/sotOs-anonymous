/*
 * sotOs · sotNet-ε Phase 2 · orch-side backends for sotnet weak hooks.
 *
 * This file provides STRONG overrides for the weak symbols declared in
 * src/sotnet/*.c · same pattern as src/lucas/backends_sotfs.c overrides
 * src/sotfs/graph_curvature.c's sotfs_graph_curvature_anomaly_notify.
 *
 * Lives in src/orch/ so it can directly use seL4 IPC headers without
 * polluting the sotnet sources (which compile against a minimal header
 * set so they can be reused outside the orch binary).
 */

#include <sel4/sel4.h>
#include <sotnet/dns.h>
#include <orch/proto.h>
#include <string.h>
#include <stdint.h>

/* Anomaly EP accessor lives in src/orch/sotbox_table.c. */
extern seL4_CPtr orch_get_anomaly_ep(void);

/* ── sotNet-ε Phase 2 · DNS canary-hit → anomaly-ext correlation ────── */

/* Strong override of the weak stub in src/sotnet/dns.c.
 * Called by dns_lookup() on every canary-domain HIT.
 * Sends ANOMALY_EV_DNS_HIT to anomaly-ext for audit-logging.
 *
 * MR layout (see proto.h for canonical definition):
 *   MR(0)      = pid (DNS-PID-PREWORK · forwarded from dns_lookup caller;
 *                     0 = operator / bootstrap, >0 = future sotbox interceptor)
 *   MR(1)      = ANOMALY_EV_DNS_HIT
 *   MR(2)      = ip_be (synth A record, network byte order)
 *   MR(3..9)   = domain bytes 0..55, packed 8 bytes per word (null-padded)
 *
 * Total = 10 words.  Same weak/strong pattern as sotfs_graph_curvature_anomaly_notify. */
void sotnet_dns_anomaly_notify(uint32_t pid, const char *domain, uint32_t ip_be)
{
    seL4_CPtr ep = orch_get_anomaly_ep();
    if (ep == 0) return;
    /* Pack first 56 bytes of domain into MR(3..9) (7 words · 56 bytes). */
    char buf[56];
    memset(buf, 0, sizeof(buf));
    if (domain) {
        size_t n = strnlen(domain, sizeof(buf) - 1);
        memcpy(buf, domain, n);
    }
    seL4_SetMR(0, (seL4_Word)pid);
    seL4_SetMR(1, ANOMALY_EV_DNS_HIT);
    seL4_SetMR(2, (seL4_Word)ip_be);
    for (int i = 0; i < 7; ++i) {
        seL4_Word w = 0;
        memcpy(&w, buf + i * 8, 8);
        seL4_SetMR(3 + i, w);
    }
    /* DNS_HIT is audit-only ("auditing only" · best-effort) and is emitted from
     * the data-path UDP:53 interceptor (lucas_sys_sendto).  Use NBSend, NOT Call:
     * a blocking Call deadlocks when the sotbox's DNS query is driven by a
     * captive orch (e.g. the egress-dns demo fault-loop) — the anomaly-ext
     * server's downstream PROMOTE_TIER Call to orch can't be serviced, so it
     * never replies and the data path stalls before the probe's recvfrom.
     * Fire-and-forget keeps the synth DNS reply (already enqueued) flowing. */
    seL4_NBSend(ep, seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 10));
}
