/*
 * sotOs · lucas-side anomaly emitter · Spec B reply-driven.
 *
 * Called from key syscall handlers (currently: write).  Forwards
 * sync-origin events (WRITE/UNLINK/CRED/EXEC) to the external anomaly
 * process, which folds them into a unified weighted suspicion score and
 * REPLIES with the authoritative target tier in MR(0).  lucas applies
 * that tier locally via lucas_set_tier (never downgrade).
 *
 * Spec B retired the old in-orch write_count>20 rule and the
 * ANOMALY_EXT_FORWARD_LIMIT deadlock cap: the anomaly no longer calls
 * back into orch for these kinds (it only replies), so there is no
 * anomaly→orch callback to deadlock against and no need to cap forwards.
 */
#include <lucas/anomaly.h>
#include <lucas/functor.h>
#include "state.h"
#include <stdio.h>
#include <string.h>
#include <sel4/sel4.h>
#include <orch/proto.h>
#include <sotguard/event.h>

extern seL4_CPtr orch_get_anomaly_ep(void);

/* SG-FS Phase 2 · monotonic per-emit counter for sotGuard event timestamps.
 * event.h documents the timestamp field as "monotonic counter · not wall-clock"
 * so a file-scope counter incremented on each emit satisfies the contract. */
static uint64_t sg_anomaly_monotonic = 0;

/* Spec B · shared sync-event forwarder.  Forwards (kind, magnitude) to
 * the external anomaly and returns the authoritative target tier from
 * the reply (MR(0)), or -1 if no anomaly EP / not a real sotbox.  No
 * FORWARD_LIMIT cap: promotion is reply-driven, so there is no
 * anomaly→orch callback to deadlock against. */
int anomaly_forward_sync(lucas_state_t *st, int kind, uint64_t magnitude) {
    seL4_CPtr sent_ep = orch_get_anomaly_ep();
    if (sent_ep == 0 || st->synthetic_pid < 1) return -1;
    seL4_SetMR(0, (seL4_Word)st->synthetic_pid);
    seL4_SetMR(1, (seL4_Word)kind);
    seL4_SetMR(2, (seL4_Word)magnitude);
    seL4_SetMR(3, (seL4_Word)st->write_count);
    seL4_SetMR(4, (seL4_Word)st->procd_slot);
    seL4_Call(sent_ep, seL4_MessageInfo_new(ORCH_OP_ANOMALY_EVENT, 0, 0, 5));
    return (int)seL4_GetMR(0); /* authoritative target tier · 0 = no change */
}

/* Human-readable trust-tier label for the operator-visible transition line. */
static const char *anomaly_tier_name(int t) {
    switch (t) {
        case 0:  return "untrusted";
        case 1:  return "suspect";
        case 2:  return "hostile";
        default: return "?";
    }
}

/* Apply a reply tier locally · never downgrade. */
void anomaly_apply_reply_tier(lucas_state_t *st, int target) {
    if (target > st->tier) {
        /* A reply-driven promotion is a anomaly rule firing · keep the
         * operator-visible trigger counter meaningful (it was previously
         * bumped by the now-removed in-orch write_count rule). */
        st->anomaly_triggers++;
        printf("[anomaly] pid=%d reply-driven promote Tier %d → %d\n",
               st->synthetic_pid, st->tier, target);
        /* C1 · make the trust transition explicit + human (companion line ·
         * emitted before lucas_set_tier so st->tier is still the old tier). */
        printf("[trust] pid=%d Tier %d→%d (%s→%s) · anomaly rule fired\n",
               st->synthetic_pid, st->tier, target,
               anomaly_tier_name(st->tier), anomaly_tier_name(target));
        lucas_set_tier(st, target);
    }
}

void anomaly_on_write(lucas_state_t *st, uint64_t fd, uint64_t bytes) {
    /* Spec A · console/FS boundary.  Writes to stdout(1)/stderr(2) are
     * console output, not filesystem mutations.  They must NOT count
     * toward write_count nor forward a ANOMALY_EV_WRITE — otherwise a
     * print-only program (e.g. a Python script) crosses the Tier-1
     * threshold and floods the log.  Real-file writes (fd >= 3) are
     * unchanged.  The serial write itself already happened in
     * lucas_sys_write before this hook, so console output is unaffected. */
    if (fd == 1 || fd == 2) return;        /* Spec A console/FS boundary */
    st->write_count++;

    /* SG-FS · additive sotGuard event emit (unchanged · best-effort).
     * Path lookup is not available at this call site (handlers_fs.c only
     * forwards fd/bytes); detail.fs.path stays zero, which the policy
     * engine tolerates. */
    {
        sotguard_event_t ev;
        memset(&ev, 0, sizeof(ev));
        ev.pid = (uint32_t)st->synthetic_pid;
        ev.type = SG_EV_FS_WRITE;
        ev.timestamp = ++sg_anomaly_monotonic;
        ev.detail.fs.fd = fd;
        ev.detail.fs.bytes = bytes;
        (void)sotguard_emit(&ev);
    }

    /* Spec B · forward EV_WRITE; the external anomaly returns the
     * authoritative tier from its weighted score.  Reply-driven · no
     * local threshold rule, no FORWARD_LIMIT cap.
     * N1 · SKIP the blocking forward for TRUSTED sotboxes: lucas_set_tier
     * suppresses promotion for them anyway (the reply is a no-op), AND the
     * blocking seL4_Call DEADLOCKS when the anomaly is stuck in its own
     * TCP_OPEN auto-escalation Call to orch (which orch_fault_loop doesn't
     * service) — this is what hung the trusted Tier-0e egress probe after its
     * GET write, so its read() never ran. */
    if (st->trusted) return;
    int target = anomaly_forward_sync(st, ANOMALY_EV_WRITE, bytes);
    if (target > 0) anomaly_apply_reply_tier(st, target);
}
