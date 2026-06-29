/*
 * sotGuard · centralized correlation event bus.
 *
 * Foundation for the v0.22.0+ policy engine.  Producers (lucas fault
 * triggers, sotnet, sotfs, graph_curvature heuristics, canary-file readers) emit
 * `sotguard_event_t` records into a bounded ring buffer; consumers
 * (policy engine, telemetry, post-mortem dumps) read recent events to
 * evaluate temporal correlation rules.
 *
 * Design notes:
 *   - Single-producer / multi-consumer.  The orch is single-threaded so
 *     no locking is required in this batch.
 *   - Lossy: when the ring is full, the oldest event is overwritten.
 *     Correlation rules MUST tolerate dropped tail entries.
 *   - No malloc.  Static storage only.  Bounded path/domain fields use
 *     plain char arrays to keep events POD and copyable.
 *   - `timestamp` is a monotonic counter (per-emit), NOT wall-clock.
 *     The orch can mix in a real clock later by stamping events from
 *     the producer side.
 *
 * This batch only introduces the bus.  No producers are wired in yet;
 * sibling unit G2 adds the policy engine and future batches migrate
 * existing trigger sites to emit events.
 */
#ifndef SOTGUARD_EVENT_H
#define SOTGUARD_EVENT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    SG_EV_NONE         = 0,
    SG_EV_FS_READ      = 1,
    SG_EV_FS_WRITE     = 2,
    SG_EV_FS_OPEN      = 3,
    SG_EV_NET_CONNECT  = 4,
    SG_EV_NET_SEND     = 5,
    SG_EV_NET_RECV     = 6,
    SG_EV_DNS_LOOKUP   = 7,
    SG_EV_PLEDGE_VIOL  = 8,
    SG_EV_FAULT_SYSCALL= 9,
    SG_EV_GRAPH_CURVATURE_RANSOM = 10,
    SG_EV_GRAPH_CURVATURE_LATERAL= 11,
    SG_EV_CANARY_READ   = 12,
    SG_EV_SYSCALL_ENTER= 13,   /* sottrace · syscall decoded (args known) */
    SG_EV_SYSCALL_EXIT = 14,   /* sottrace · syscall return (ret known)  */
    SG_EV_TIER_ASSIGN  = 15,   /* sottrace · trust-tier transition       */
    SG_EV_INBOUND_ACCEPT = 16,  /* sottrace · inbound connection accepted */
    SG_EV_CONN_CLOSE     = 17,  /* sottrace · connection closed (byte totals) */
    SG_EV_ISOLATED_WRITE_DROP    = 18,  /* sottrace · Tier-2 shadow write silently dropped */
    SG_EV_RESPONSE_PROFILE_SERVED = 19,  /* sottrace · inbound response_profile reply served (HTTP/SSH/HTTPS) */
    SG_EV_CANARY_SCREENSHOT = 20, /* sottrace · L14a canary screenshot view mapped RO into a Tier-2 client */
    SG_EV_INPUT_INJECT     = 21, /* sottrace · L14b synthetic input event(s) injected into a Tier-2 seat */
    SG_EV_FORKBOMB_QUARANTINED  = 22, /* sottrace · P2b fork-bomb detected → quarantined + terminated */
    SG_EV_PERSISTENCE_INSTALL   = 23, /* sottrace · Tier-2 persistence-path install (crontab/etc) contained */
    SG_EV_PACKAGE_INSTALL       = 24, /* sottrace · Tier-2 apk/pkg install into the contained per-session upper */
} sotguard_event_type_t;

/* sotguard_emit accepts ONLY kinds 1..SG_EV_CANARY_READ (the security/
 * correlation + WAL ring). The sottrace kinds (SG_EV_SYSCALL_ENTER/EXIT/
 * TIER_ASSIGN, 13..15) are observability-plane-only: they are published via
 * sottrace's trace_emit into its own non-blocking rings and must NEVER be
 * passed to sotguard_emit (which would route them through blocking WAL I/O).
 * The validity gate in sotguard_emit rejects anything above this ceiling. */
#define SOTGUARD_EMIT_MAX_KIND  SG_EV_CANARY_READ

/* α · PR 9 · v0.26.0-persistence-substrate · audit event kinds.
 *
 * These reuse the uint16_t `kind` field in orch_anomaly_log_entry_t · the
 * values are picked at 0x70+ to leave 1..15 (existing ANOMALY_EV_*) and
 * the procd PR 15 block (9..15) untouched.  They surface in the
 * anomaly-log view via sotshell's anomaly_kind_label switch and let
 * an operator triage WAL exhaustion / torn records / simreboot cycles
 * from the same chronological audit dump as the rest of the security
 * events.  No producer-side wiring beyond the WAL/simreboot emit sites
 * is required · these are pure audit signals. */
typedef enum {
    SOTGUARD_KIND_WAL_FULL_DROP    = 0x70,
    SOTGUARD_KIND_WAL_TORN_RECORD  = 0x71,
    SOTGUARD_KIND_WAL_REPLAY_DONE  = 0x72,
    SOTGUARD_KIND_SIMREBOOT_BEGIN  = 0x73,
    SOTGUARD_KIND_SIMREBOOT_END    = 0x74,

    /* β · PR 11 · v0.27.0-init-cron · audit event kinds.
     *
     * These extend the 0x70+ block (PR 9 added WAL/simreboot at 0x70-0x74)
     * with one sub-block per init-cron-scheduler subsystem:
     *   0x90-0x94 · sotinit lifecycle (service start/exit/failed,
     *                                  cycle-detected, unit-invalid)
     *   0xA0-0xA1 · sotcron fire / fire-failed
     *   0xB0-0xB2 · lucas shellhook fired / skipped / failed
     *
     * Producer-side wiring lives in sotinit / sotcron / lucas (printf
     * audit lines today · routed into orch_anomaly_log_append once the
     * cross-process audit IPC channel lands · α PR 4 deferred work).
     * The anomaly_kind_label switch in sotshell decodes them so the
     * unified `sotos> anomaly-log` view surfaces a readable label as
     * soon as the routing arrives.  Scope-reduction note: the values are
     * stable contract today even though only the labels (and the printf
     * lines that mention them) are externally observable. */
    SOTGUARD_KIND_SOTINIT_SERVICE_START   = 0x90,
    SOTGUARD_KIND_SOTINIT_SERVICE_EXIT    = 0x91,
    SOTGUARD_KIND_SOTINIT_SERVICE_FAILED  = 0x92,
    SOTGUARD_KIND_SOTINIT_CYCLE_DETECTED  = 0x93,
    SOTGUARD_KIND_SOTINIT_UNIT_INVALID    = 0x94,
    SOTGUARD_KIND_SOTCRON_FIRE            = 0xA0,
    SOTGUARD_KIND_SOTCRON_FIRE_FAILED     = 0xA1,
    SOTGUARD_KIND_SHELLHOOK_FIRED         = 0xB0,
    SOTGUARD_KIND_SHELLHOOK_SKIPPED       = 0xB1,
    SOTGUARD_KIND_SHELLHOOK_FAILED        = 0xB2,
    SOTGUARD_KIND_PERSISTENCE_INSTALL         = 0xC0,
    SOTGUARD_KIND_PERSISTENCE_NEVER_ACTIVATE  = 0xC1,
    SOTGUARD_KIND_PERSISTENCE_NEVER_FIRE      = 0xC2,
    SOTGUARD_KIND_PACKAGE_INSTALL             = 0xC3, /* apk add into the per-session upper (contained) */
} sotguard_kind_t;

typedef struct {
    uint32_t pid;
    uint16_t type;          /* sotguard_event_type_t */
    uint16_t conn_id;
    uint64_t timestamp;     /* monotonic counter · not wall-clock */
    union {
        struct { uint64_t fd; uint64_t bytes; char path[64]; } fs;
        struct { uint32_t ip_be; uint16_t port_be; uint16_t pad; uint64_t len; } net;
        struct { uint32_t syscall_nr; uint64_t rip; } fault;
        struct { uint32_t rule_kind; uint32_t severity; } graph_curvature;
        struct { char domain[64]; uint32_t ip_be; } dns;
        struct { uint32_t sysno; int64_t ret; uint64_t rip; uint64_t args[6]; } syscall; /* 72B < fs's 80B */
        struct { uint32_t old_tier; uint32_t new_tier; } tier;                            /* 8B */
    } detail;
} sotguard_event_t;

_Static_assert(sizeof(sotguard_event_t) == 96,
    "sotguard_event_t must stay 96B (16B header + 80B fs/dns union arm); "
    "the sottrace syscall arm is 72B and must NOT grow the union");

#define SOTGUARD_RING_CAPACITY 256

/* Initialize the ring buffer (zeroed).  Called once at orch startup. */
void sotguard_event_init(void);

/* Emit an event into the ring.  Single-producer / multi-consumer.
 * If the ring is full, the oldest event is overwritten (lossy).
 * Returns 0 on success, -1 on bad event (NULL or invalid type). */
int sotguard_emit(const sotguard_event_t *ev);

/* Peek the most-recent N events.  Returns count filled.  Used by
 * the policy engine to evaluate temporal correlation rules. */
size_t sotguard_recent(sotguard_event_t *out, size_t want);

/* Total events emitted since init (monotonic). */
uint64_t sotguard_total_emitted(void);

#ifdef __cplusplus
}
#endif

#endif /* SOTGUARD_EVENT_H */
