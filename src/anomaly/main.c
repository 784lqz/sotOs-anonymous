/*
 * sotOs · sotOs-anomaly · external anomaly process.
 *
 * Receives ORCH_OP_ANOMALY_EVENT IPCs from orch, evaluates rules.
 * Spec B · sync-origin kinds (WRITE/UNLINK/CRED/EXEC) fold into a unified
 * weighted suspicion score (T1=20 → Tier 1, T2=40 → Tier 2) and reply the
 * authoritative target tier in MR(0) for lucas to apply locally — no
 * orch_ep callback (avoids the orch-blocked deadlock).  Async kinds
 * (NET_PRECOMMIT/CURVATURE/DNS_HIT/TCP_OPEN/MSYSCALL) still drive promotion
 * via ORCH_OP_PROMOTE_TIER over the delegated callback EP.
 *
 * argv[0] = "sotOs-anomaly"
 * argv[1] = event EP cap slot (anomaly seL4_Recvs on this)
 * argv[2] = callback EP cap slot (anomaly seL4_Calls this for PROMOTE_TIER)
 * argv[3] = (PR 10) procd badged EP cap slot · anomaly seL4_Calls this
 *           for OP_SET_TIER / OP_REBIND_FUNCTOR.  Badge is
 *           BADGE_ANOMALY_OP_SET_TIER (0xA009) so procd accepts the
 *           mutation.  0 if procd is not configured or the mint failed
 *           · anomaly falls back to the legacy orch callback path so
 *           the simulated_attacker demo's writes_silenced / is_isolated flips still
 *           drive the operator-visible narrative.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sel4/sel4.h>
#include <orch/proto.h>
#include <procd/proto.h>
/* α · PR 4 · anomaly writer · mirror events to the sotfs WAL over the
 * orch listen EP via SOTFS_OP_WAL_LOG.  anomaly is a separate process
 * that does NOT link sotos-sotfs, so the WAL log path is pure IPC. */
#include <sotfs/wal.h>
#include <sotfs/wal_ipc.h>

/* anomaly-side WAL writer state · gated by g_wal_attached, populated
 * at startup from argv[4].  The IPC stub seL4_Calls orch's listen EP
 * with SOTFS_OP_WAL_LOG and packs the 24 B anomaly_ev payload into
 * 3 MRs (MR(2..4)).  Mirrors the procd writer in src/procd/main.c. */
int g_wal_attached = 0;
static seL4_CPtr g_sotfs_wal_ep = 0;

static void anomaly_wal_log_ev(const sotfs_wal_payload_anomaly_ev_t *p) {
    if (!g_wal_attached || g_sotfs_wal_ep == 0 || p == NULL) return;
    _Static_assert(sizeof(sotfs_wal_payload_anomaly_ev_t) == 24,
                   "anomaly_ev must remain 24 B for 3-MR packing");
    const uint64_t *src = (const uint64_t *)p;
    seL4_SetMR(0, (seL4_Word)SOTFS_OP_WAL_LOG);
    seL4_SetMR(1, (seL4_Word)SOTFS_WAL_KIND_ANOMALY_EV);
    for (int i = 0; i < 3; i++) {
        seL4_SetMR(2 + i, (seL4_Word)src[i]);
    }
    (void)seL4_Call(g_sotfs_wal_ep,
                    seL4_MessageInfo_new(SOTFS_OP_WAL_LOG, 0, 0, 5));
}

/* Spec B · unified weighted suspicion score thresholds.  score[pid]
 * accumulates weight(kind) (+ unlink burst bonus); crossing T1 → Tier 1,
 * T2 → Tier 2.  T1=20 keeps ~20 plain writes (weight 1) crossing Tier 1,
 * matching the pre-Spec-B write_count>20 boundary.  Any single >=40
 * contribution crosses T2 in one occurrence (instant escalation for
 * unambiguous threats). */
#define ANOMALY_T1_THRESHOLD 20u
#define ANOMALY_T2_THRESHOLD 40u

/* Per-kind base weights.  Contributions are EVENT COUNTS (1 per event),
 * never byte counts.  unlink burst escalation is computed in
 * anomaly_handle_sync from the per-pid run counter, not here. */
static uint32_t anomaly_weight(int kind) {
    switch (kind) {
        case ANOMALY_EV_WRITE:        return 1;
        case ANOMALY_EV_UNLINK:       return 2;   /* base · escalates by burst */
        case ANOMALY_EV_EXEC:         return 8;
        case ANOMALY_EV_CRED_ACCESS:  return 15;
        case ANOMALY_EV_NET_PRECOMMIT:
        case ANOMALY_EV_CURVATURE:
        case ANOMALY_EV_DNS_HIT:
        case ANOMALY_EV_TCP_OPEN:
        case ANOMALY_EV_MSYSCALL:     return ANOMALY_T2_THRESHOLD; /* instant T2 */
        default:                       return 0;
    }
}

/* Spec B · unified weighted suspicion score · authoritative per-pid state.
 * Hoisted to file scope (was locals in main) so anomaly_handle_sync /
 * anomaly_score_fold can be clean file-scope functions reachable from the
 * dispatch loop.  All indexed by synthetic_pid (1-based, max 15).  procd_ep is
 * likewise hoisted (populated once at startup from argv[3]) so the sync
 * handler can dual-write OP_SET_TIER without threading the cap through. */
static uint32_t anomaly_score[16];
static uint8_t  anomaly_applied_tier[16];
/* Fresh-tenant watermark · NOT a promotion driver (the write threshold is
 * gone).  Holds lucas's last per-state monotonic write count; a drop below
 * it means a new sotbox took this pid slot, triggering a score reset. */
static uint32_t anomaly_write_counts[16];
static uint32_t anomaly_procd_slots[16];
static bool     anomaly_promoted[16];
static uint32_t anomaly_unlink_run[16];          /* consecutive-unlink burst counter */
static uint32_t anomaly_events_since_unlink[16]; /* events since last unlink · burst window */
static seL4_CPtr anomaly_procd_ep = 0;

/* Fold one event into pid's score and return the authoritative target
 * tier (0/1/2).  burst_bonus is the unlink-specific extra weight (0 for
 * non-unlink kinds · computed by the caller in PR 4). */
static int anomaly_score_fold(uint32_t *score, uint8_t *applied_tier,
                               int pid, int kind, uint32_t burst_bonus) {
    if (pid < 1 || pid >= 16) return 0;
    score[pid] += anomaly_weight(kind) + burst_bonus;
    int target = (score[pid] >= ANOMALY_T2_THRESHOLD) ? 2
               : (score[pid] >= ANOMALY_T1_THRESHOLD) ? 1 : 0;
    if (target > applied_tier[pid]) {
        applied_tier[pid] = (uint8_t)target;
        printf("[anomaly-ext] pid=%d score=%u → Tier %d (T1=%u T2=%u)\n",
               pid, score[pid], target, ANOMALY_T1_THRESHOLD, ANOMALY_T2_THRESHOLD);
        return target;
    }
    return 0;
}

/* Spec B · fold one async-origin Tier-2 event into the unified score and
 * age the unlink-burst window.  The score_fold return is intentionally
 * ignored: async branches already applied the tier via their orch_ep
 * callback, and the monotonic applied_tier check makes this idempotent
 * (no double-promote, no downgrade).  Keeps the unified score the single
 * source of truth for suspicion even for network/curvature-driven escalation. */
static inline void anomaly_fold_async(int pid, int kind) {
    if (pid < 1 || pid >= 16) return;
    (void)anomaly_score_fold(anomaly_score, anomaly_applied_tier, pid, kind, 0);
    anomaly_events_since_unlink[pid]++;
}

/* PR 10 · anomaly dual-write helper · sends OP_SET_TIER to procd's badged
 * EP after the legacy ORCH_OP_PROMOTE_TIER round-trip has already flipped
 * the lucas writes_silenced/is_isolated flags.  procd publishes EV_TIER_CHANGED +
 * EV_FUNCTOR_REBOUND under the same seqlock so future SHM readers (lucas,
 * audit) observe a coherent tier transition.  No-op if either
 * (a) procd_ep is 0 (procd not wired · anomaly was spawned without a
 *     badged EP), or
 * (b) procd_slot is 0 (sotbox's procd slot hasn't been announced yet,
 *     usually because the sotbox spawned before procd came up).
 * Failure to deliver the procd write is non-fatal · the legacy path has
 * already done the work for the demo. */
static void anomaly_procd_set_tier(seL4_CPtr procd_ep,
                                    uint32_t procd_slot,
                                    uint32_t target_tier) {
    if (procd_ep == 0 || procd_slot == 0) return;
    seL4_SetMR(0, PROCD_OP_SET_TIER);
    seL4_SetMR(1, procd_slot);     /* caller_slot · sotbox procd slot */
    seL4_SetMR(2, target_tier);
    seL4_Call(procd_ep, seL4_MessageInfo_new(0, 0, 0, 3));
    int32_t result = (int32_t)seL4_GetMR(0);
    printf("[anomaly-ext] OP_SET_TIER slot=%u new_tier=%u rc=%d\n",
           procd_slot, target_tier, result);
}

/* Handle a sync-origin event (rides a lucas Call · reply carries tier).
 * Returns the authoritative target tier (0 = no change). */
static int anomaly_handle_sync(int pid, int kind, seL4_Word mr2,
                                uint32_t lucas_count, uint32_t pd_slot) {
    if (pid < 1 || pid >= 16) return 0;
    if (pd_slot != 0) anomaly_procd_slots[pid] = pd_slot;
    /* fresh-tenant reset · lucas's per-state monotonic counter dropping
     * below the stored value means a new sotbox took this slot. */
    if (lucas_count != 0 && lucas_count < anomaly_write_counts[pid]) {
        anomaly_score[pid] = 0; anomaly_applied_tier[pid] = 0;
        anomaly_unlink_run[pid] = 0; anomaly_events_since_unlink[pid] = 0;
        anomaly_promoted[pid] = false;
    }
    anomaly_write_counts[pid] = (lucas_count != 0) ? lucas_count
                                                    : anomaly_write_counts[pid] + 1;

    uint32_t burst_bonus = 0;
    /* UNLINK burst escalation · a run of consecutive unlinks (each within
     * K scored events of the previous) ramps super-linearly; spaced
     * cleanup deletes are aged out by non-unlink scored events and stay
     * flat at BASE.  CRED/EXEC/WRITE fold plainly but age the window. */
    switch (kind) {
        case ANOMALY_EV_UNLINK: {
            const uint32_t K = 8, BASE = 2, CAP = BASE * 6;
            uint32_t cred = (uint32_t)mr2 & 1u;
            if (anomaly_events_since_unlink[pid] > K) anomaly_unlink_run[pid] = 0;
            anomaly_unlink_run[pid]++;
            anomaly_events_since_unlink[pid] = 0;
            uint32_t step = BASE * anomaly_unlink_run[pid];
            if (step > CAP) step = CAP;
            burst_bonus = step - BASE;          /* score_fold adds BASE; top up to step */
            if (cred) burst_bonus += BASE;      /* cred/canary delete weighs higher */
            break;
        }
        case ANOMALY_EV_WRITE:
        case ANOMALY_EV_CRED_ACCESS:
        case ANOMALY_EV_EXEC:
            /* Non-unlink scored event ages the unlink-burst window so
             * spaced cleanup deletes decay instead of escalating. */
            anomaly_events_since_unlink[pid]++;
            break;
        default:
            return 0; /* not a sync kind */
    }
    int target = anomaly_score_fold(anomaly_score, anomaly_applied_tier,
                                     pid, kind, burst_bonus);
    if (target > 0)
        anomaly_procd_set_tier(anomaly_procd_ep, anomaly_procd_slots[pid],
                                (uint32_t)target);
    return target;
}

int main(int argc, char *argv[]) {
    seL4_CPtr recv_ep    = (argc > 1) ? (seL4_CPtr)atol(argv[1]) : 0;
    seL4_CPtr orch_ep    = (argc > 2) ? (seL4_CPtr)atol(argv[2]) : 0;
    seL4_CPtr procd_ep   = (argc > 3) ? (seL4_CPtr)atol(argv[3]) : 0;
    /* Spec B · mirror procd_ep to file scope so anomaly_handle_sync can
     * dual-write OP_SET_TIER without threading the cap through the dispatch
     * loop.  The local procd_ep stays in use by the async branches below. */
    anomaly_procd_ep = procd_ep;
    /* α · PR 4 · WAL EP slot (orch listen, unbadged copy minted by root).
     * 0 = WAL IPC disabled · g_wal_attached stays 0 and the mirror call
     * inside the dispatch loop becomes a no-op. */
    seL4_CPtr wal_ep     = (argc > 4) ? (seL4_CPtr)atol(argv[4]) : 0;

    if (recv_ep == 0) {
        printf("[anomaly-ext] FATAL · no event EP in argv[1]\n");
        /* Suspend rather than return so the process stays alive. */
        while (1) seL4_Yield();
        return 1;
    }

    if (wal_ep != 0) {
        g_sotfs_wal_ep = wal_ep;
        /* PR 4 · DEFER the gate flip · synchronous WAL IPC back into orch
         * would deadlock during anomaly-event handling because orch /
         * lucas invokes anomaly via seL4_Call and blocks waiting for
         * anomaly's reply.  A anomaly→orch WAL call inside that window
         * cannot complete.  Coverage parity is achieved by the
         * sotguard_emit hook (in orch's address space, direct call · no
         * IPC) which fires before the anomaly-ext IPC at every emitter
         * site.  PR 5 lands the async SHM-ring transport that lifts the
         * deadlock and flips this gate. */
        g_wal_attached = 0;
        printf("[anomaly-ext] WAL EP captured · wal_ep=%lu (g_wal_attached=0 · IPC deferred to PR 5)\n",
               (unsigned long)wal_ep);
    } else {
        printf("[anomaly-ext] WAL writer disabled · no wal_ep in argv[4]\n");
    }

    printf("[anomaly-ext] spawned · receiving on EP slot=%lu · orch callback EP=%lu · procd EP=%lu · wal EP=%lu\n",
           (unsigned long)recv_ep, (unsigned long)orch_ep,
           (unsigned long)procd_ep, (unsigned long)wal_ep);

    while (1) {
        seL4_Word badge = 0;
        seL4_MessageInfo_t info = seL4_Recv(recv_ep, &badge);
        seL4_Word op = seL4_MessageInfo_get_label(info);

        if (op != ORCH_OP_ANOMALY_EVENT) {
            printf("[anomaly-ext] unknown op=%lu · ignoring\n", (unsigned long)op);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));
            continue;
        }

        /* Event payload: MR(0) = pid, MR(1) = event_kind, MR(2) = arg */
        int pid  = (int)seL4_GetMR(0);
        int kind = (int)seL4_GetMR(1);
        seL4_Word arg = seL4_GetMR(2);

        printf("[anomaly-ext] event pid=%d kind=%d arg=%lu\n",
               pid, kind, (unsigned long)arg);

        /* α · PR 4 · WAL mirror is INTENTIONALLY NOT performed here.
         * Calling seL4_Call(g_sotfs_wal_ep) inside this loop would
         * deadlock because orch is blocked waiting for OUR reply (the
         * ANOMALY_EVENT IPC is a synchronous call from orch / lucas).
         * Orch's listen-EP is not in seL4_Recv during that window so a
         * anomaly→orch WAL call would never complete.  The equivalent
         * coverage is achieved by the sotguard_emit hook in
         * src/sotguard/event_bus.c · lucas-side emitters call it
         * BEFORE seL4_Call(anomaly_ep), so the WAL append happens in
         * orch's address space (direct sotos-sotfs link) where no IPC
         * is needed.  anomaly-ext's g_wal_attached + g_sotfs_wal_ep
         * stay populated for future post-reply mirror points (e.g.
         * tier-promote decisions) once the IPC ordering can guarantee
         * orch is back in seL4_Recv. */

        /* sotNet-δ Phase 3 · NET_PRECOMMIT must reply with a decision
         * BEFORE the caller can proceed.  Handle it first, then continue
         * to skip the default fire-and-forget reply below. */
        if (kind == ANOMALY_EV_NET_PRECOMMIT) {
            uint32_t dst_ip_be = (uint32_t)seL4_GetMR(2);
            uint32_t len       = (uint32_t)seL4_GetMR(3);
            /* Per-pid byte counter · cumulative per session. */
            static uint32_t pid_bytes_out[16] = {0};
            if (pid >= 0 && pid < 16) {
                pid_bytes_out[pid] += len;
            }

            int decision = 0;  /* 0 = COMMIT (default), 1 = ABORT, 2 = SYNTH */
            int promote_tier = 0;  /* reply MR(1) · 0 = no promote (reply-driven · no orch_ep callback) */
            const char *reason = "allow";

            /* Rule A · Local destination · 10.0.0.0/8 → always COMMIT (QEMU subnet). */
            uint8_t first_octet = dst_ip_be & 0xFF;
            if (first_octet == 10) {
                decision = 0;
                reason = "local-subnet-allow";
            }
            /* Rule B · Single-send rate-limit · >256 bytes to non-local → ABORT. */
            else if (len > 256) {
                decision = 1;
                reason = "rate-limit-single-send";
            }
            /* Rule C · Cumulative · pid_bytes > 4 KiB to non-local → ABORT. */
            else if (pid >= 0 && pid < 16 && pid_bytes_out[pid] > 4096) {
                decision = 1;
                reason = "rate-limit-cumulative";
            }
            /* Otherwise default COMMIT (small non-local sends OK for now). */

            /* Rule D · sustained exfil · SYNTH redirect + auto Tier-2.
             * Higher threshold than Rule C so we only flip to deception when
             * the malware is clearly persistent.  Fires once per pid · guarded
             * by promoted[]. */
            if (pid >= 1 && pid < 16 &&
                first_octet != 10 &&
                pid_bytes_out[pid] > 16384 &&
                !anomaly_promoted[pid] &&
                orch_ep != 0) {
                anomaly_promoted[pid] = true;
                decision = 2;  /* SYNTH */
                reason   = "sustained-exfil-synth";

                /* REPLY-DRIVEN promote (NO seL4_Call(orch_ep) · that re-entrant
                 * Call deadlocks when the send originates inside orch — e.g. a
                 * nested egress fault loop).  The tier rides the reply in MR(1);
                 * the in-orch sotnet emitter applies it via
                 * orch_anomaly_apply_promote().  Mirrors the reply-driven
                 * WRITE/CRED path. */
                promote_tier = 2;
                /* PR 10 dual-write · authoritative tier history in procd (a
                 * Call to procd, NOT orch · no orch reentrancy).  No-op if the
                 * procd slot was never observed (NET_PRECOMMIT-only paths). */
                anomaly_procd_set_tier(procd_ep, anomaly_procd_slots[pid], 2);
                printf("[tier2-auto] pid=%u escalated via NET_PRECOMMIT (cumulative %u B)\n",
                       (unsigned int)pid, (unsigned int)pid_bytes_out[pid]);

                anomaly_fold_async(pid, kind);  /* unified score + burst window */
            }

            printf("[anomaly-ext] net pre-commit · pid=%d dst=0x%x len=%u · decision=%s (%s · cum=%u)\n",
                   pid, dst_ip_be, len,
                   decision == 0 ? "COMMIT"
                                 : (decision == 2 ? "SYNTH" : "ABORT"),
                   reason,
                   (pid >= 0 && pid < 16) ? pid_bytes_out[pid] : 0);
            /* Reply · MR(0) = decision, MR(1) = reply-driven promote tier (0 = none). */
            seL4_SetMR(0, (seL4_Word)decision);
            seL4_SetMR(1, (seL4_Word)promote_tier);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 2));
            continue;  /* skip default reply at end of loop */
        }

        /* sotFS-θ · CURVATURE event · audit-log rule firings from graph_curvature.c. */
        if (kind == ANOMALY_EV_CURVATURE) {
            /* MR(2) = rule kind (1=RANSOMWARE, 2=LATERAL), MR(3) = severity */
            uint32_t rule_kind = (uint32_t)seL4_GetMR(2);
            uint32_t severity  = (uint32_t)seL4_GetMR(3);
            const char *rule_name = (rule_kind == 1) ? "RANSOMWARE"
                                  : (rule_kind == 2) ? "LATERAL"
                                                      : "UNKNOWN";
            printf("[anomaly-ext] curvature alert · pid=%d rule=%s severity=%u\n",
                   pid, rule_name, severity);

            /* CURVATURE-AUTOPROMOTE · if a real RANSOMWARE (1) or LATERAL (2)
             * signature fires AND we can attribute it to a sotbox pid,
             * escalate to Tier-2 so the isolated-write path deception layer
             * engages.  Single-fire per pid via promoted[].  Boot-time
             * curvature events from lazy_init carry pid=0 and remain
             * audit-only · the gate `pid >= 1` keeps the rule dormant
             * until a sotbox is actually attributed. */
            int curv_promote = 0;  /* reply MR(0) · reply-driven tier (no orch_ep callback) */
            if (pid >= 1 && pid < 16 && rule_kind >= 1 && rule_kind <= 2 &&
                !anomaly_promoted[pid] && orch_ep != 0) {
                anomaly_promoted[pid] = true;
                curv_promote = 2;  /* Tier-2 · isolated-write path · applied by the emitter */
                /* PR 10 dual-write · Call to procd (not orch · no reentrancy). */
                anomaly_procd_set_tier(procd_ep, anomaly_procd_slots[pid], 2);
                printf("[tier2-auto] pid=%d escalated via CURVATURE (rule=%s)\n",
                       pid, rule_name);
                anomaly_fold_async(pid, kind);  /* unified score + burst window */
            }
            /* Reply · MR(0) = reply-driven promote tier (0 = audit-only, no change). */
            seL4_SetMR(0, (seL4_Word)curv_promote);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
            continue;  /* skip default reply at end of loop */
        }

        /* sotNet-ε Phase 2 · DNS_HIT event · audit-log canary-domain lookups.
         * MR(0) = pid (DNS-PID-PREWORK · 0 = operator/bootstrap, >0 = sotbox)
         * MR(2) = ip_be (synth A record, network byte order)
         * MR(3..9) = domain bytes 0..55, packed 8 bytes per word (null-padded). */
        if (kind == ANOMALY_EV_DNS_HIT) {
            uint32_t ip_be = (uint32_t)seL4_GetMR(2);
            char     domain[57];
            memset(domain, 0, sizeof(domain));
            for (int i = 0; i < 7; ++i) {
                seL4_Word w = seL4_GetMR(3 + i);
                memcpy(domain + i * 8, &w, 8);
            }
            domain[56] = '\0';
            /* DNS-PID-PREWORK · keep the "operator-lookup canary-domain=" tag
             * (smoke regression depends on it) when pid==0; emit a sotbox-pid
             * tagged variant when the future interceptor passes a real pid. */
            if (pid == 0) {
                printf("[anomaly-ext] DNS HIT · operator-lookup canary-domain=%s ip=%u.%u.%u.%u (auditing only)\n",
                       domain,
                       ip_be & 0xFF, (ip_be >> 8) & 0xFF,
                       (ip_be >> 16) & 0xFF, (ip_be >> 24) & 0xFF);
            } else {
                printf("[anomaly-ext] DNS HIT · pid=%d canary-domain=%s ip=%u.%u.%u.%u (auditing only)\n",
                       pid, domain,
                       ip_be & 0xFF, (ip_be >> 8) & 0xFF,
                       (ip_be >> 16) & 0xFF, (ip_be >> 24) & 0xFF);
            }
            /* DNS-PID-PREWORK · DORMANT Tier-2 auto-promote rule.  When a real
             * sotbox pid arrives via the future lucas_sys_sendto UDP:53
             * interceptor, escalate the offending sotbox to Tier-2 (Mirror
             * Synth).  Today all callers pass pid=0 (operator / bootstrap),
             * so the gate `pid >= 1` keeps the rule dormant.  Existing
             * anomaly state uses a hardcoded 16 for the pid space. */
            int dns_promote = 0;  /* reply MR(0) · reply-driven tier (no orch_ep callback) */
            if (pid >= 1 && pid < 16 && !anomaly_promoted[pid] && orch_ep != 0) {
                anomaly_promoted[pid] = true;
                dns_promote = 2;   /* Tier-2 · isolated-write path · applied by the emitter */
                /* PR 10 dual-write · Call to procd (not orch · no reentrancy). */
                anomaly_procd_set_tier(procd_ep, anomaly_procd_slots[pid], 2);
                printf("[tier2-auto] pid=%d escalated via DNS_HIT (canary domain)\n",
                       pid);
                anomaly_fold_async(pid, kind);  /* unified score + burst window */
            }
            /* Reply · MR(0) = reply-driven promote tier (0 = audit-only, no change). */
            seL4_SetMR(0, (seL4_Word)dns_promote);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
            continue;  /* skip default reply at end of loop */
        }

        /* OBSD-ε MSYSCALL · syscall-site RIP outside ELF text range ·
         * shellcode signature · auto-promote to Tier-2 (isolated-write path).
         * MR(0) = pid, MR(2) = rip, MR(3) = sysno.  Single-fire per pid
         * via promoted[].  Audit-log when pid is unattributed (0). */
        if (kind == ANOMALY_EV_MSYSCALL) {
            uint32_t rip   = (uint32_t)seL4_GetMR(2);
            uint32_t sysno = (uint32_t)seL4_GetMR(3);
            printf("[anomaly-ext] MSYSCALL · pid=%d rip=0x%x sysno=%u\n",
                   pid, rip, sysno);
            int msys_promote = 0;  /* reply MR(0) · reply-driven tier (no orch_ep callback) */
            if (pid >= 1 && pid < 16 && !anomaly_promoted[pid] && orch_ep != 0) {
                anomaly_promoted[pid] = true;
                msys_promote = 2;  /* Tier-2 · applied by the emitter */
                /* PR 10 dual-write · Call to procd (not orch · no reentrancy). */
                anomaly_procd_set_tier(procd_ep, anomaly_procd_slots[pid], 2);
                printf("[tier2-auto] pid=%u escalated via MSYSCALL (shellcode rip=0x%x)\n",
                       (unsigned int)pid, rip);
                anomaly_fold_async(pid, kind);  /* unified score + burst window */
            }
            /* Reply · MR(0) = reply-driven promote tier (0 = audit-only, no change). */
            seL4_SetMR(0, (seL4_Word)msys_promote);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
            continue;
        }

        /* Spec B · sync-origin kinds ride a lucas Call and the reply
         * carries the authoritative target tier in MR(0); lucas applies
         * it locally (no orch_ep callback · that avoids the orch-blocked
         * deadlock).  WRITE/CRED/UNLINK are emitted today; EXEC lands in
         * PR 5. */
        if (kind == ANOMALY_EV_WRITE || kind == ANOMALY_EV_UNLINK ||
            kind == ANOMALY_EV_CRED_ACCESS || kind == ANOMALY_EV_EXEC) {
            uint32_t lucas_count = (uint32_t)seL4_GetMR(3);
            uint32_t pd_slot     = (uint32_t)seL4_GetMR(4);
            int sync_target = anomaly_handle_sync(pid, kind, seL4_GetMR(2),
                                                   lucas_count, pd_slot);
            seL4_SetMR(0, (seL4_Word)sync_target);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
            continue;
        }

        /* sotNet-δ-2 · TCP open audit + auto-promote on non-local connect.
         *   MR(0) = origin_pid · MR(2) = remote_ip_be (NBO)
         *   MR(3) = (remote_port_be << 16) | local_port_be (both BE, packed)
         * REPLY-DRIVEN: returns the promote tier in MR(0) (NO seL4_Call(orch_ep)
         * · that re-entrant Call deadlocks when the connect originates inside
         * orch, e.g. a nested egress fault loop).  The in-orch tcp_audit emitter
         * applies it via orch_anomaly_apply_promote(). */
        if (kind == ANOMALY_EV_TCP_OPEN) {
            uint32_t rip_be     = (uint32_t)seL4_GetMR(2);
            uint32_t ports_pack = (uint32_t)seL4_GetMR(3);
            uint16_t rport_be   = (uint16_t)((ports_pack >> 16) & 0xFFFF);
            uint16_t lport_be   = (uint16_t)( ports_pack        & 0xFFFF);
            uint16_t rport_h    = (uint16_t)(((rport_be & 0xFF) << 8) | ((rport_be >> 8) & 0xFF));
            uint16_t lport_h    = (uint16_t)(((lport_be & 0xFF) << 8) | ((lport_be >> 8) & 0xFF));
            printf("[anomaly-ext] TCP open · pid=%d remote=%u.%u.%u.%u:%u local=:%u\n",
                   pid, rip_be & 0xFF, (rip_be >> 8) & 0xFF,
                   (rip_be >> 16) & 0xFF, (rip_be >> 24) & 0xFF, rport_h, lport_h);

            int tcp_promote = 0;  /* reply MR(0) · reply-driven tier */
            /* TCP-OPEN-AUTOPROMOTE · attributed connect to a non-local IP
             * escalates the sotbox to Tier-2.  Local 10.x.x.x = QEMU subnet ·
             * always safe.  Single-fire per pid via promoted[]. */
            if (pid >= 1 && pid < 16 && !anomaly_promoted[pid] && orch_ep != 0 &&
                (uint8_t)(rip_be & 0xFFu) != 10) {
                anomaly_promoted[pid] = true;
                tcp_promote = 2;
                printf("[tier2-auto] pid=%d escalated via TCP_OPEN to non-local IP\n", pid);
                /* PR 10 dual-write · Call to procd (not orch · no reentrancy). */
                anomaly_procd_set_tier(procd_ep, anomaly_procd_slots[pid], 2);
                anomaly_fold_async(pid, kind);  /* unified score + burst window */
            }
            /* Reply · MR(0) = reply-driven promote tier (0 = audit-only, no change). */
            seL4_SetMR(0, (seL4_Word)tcp_promote);
            seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 1));
            continue;
        }

        /* Reply immediately so orch is not blocked (non-precommit events). */
        seL4_Reply(seL4_MessageInfo_new(0, 0, 0, 0));

        if (kind == ANOMALY_EV_OPERATOR_PROMOTE) {
            printf("[anomaly-ext] operator promoted pid=%d to tier=%lu\n",
                   pid, (unsigned long)arg);
        } else if (kind == ANOMALY_EV_PLEDGE_VIOLATION) {
            printf("[anomaly-ext] pid=%d pledge violation · sysno=%lu (tier already promoted by dispatcher)\n",
                   pid, (unsigned long)seL4_GetMR(2));
        }
    }
    return 0;
}
