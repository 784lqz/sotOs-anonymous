/* sotOs · sotcron · wire protocol · ABI v1.
 *
 * sotcron is a Path D process spawned by root · sibling of sotinit / procd ·
 * cron-like scheduler for systemd-style .timer units.  PR 7 ships the ELF
 * scaffold + TSC calibration + idle polling loop; subsequent PRs wire the
 * OnCalendar / OnUnitActiveSec parsers and the SOTINIT_OP_ACTIVATE fire
 * dispatch.
 *
 * Operators talk to sotcron via the SOTCRON_OP_* wire protocol once PR 9
 * lands.  PR 7 only emits diagnostic banners on stdout.
 *
 * Spec: init-cron-scheduler-design §4.
 */
#ifndef SOTCRON_PROTO_H
#define SOTCRON_PROTO_H

#include <stdint.h>

typedef enum {
    SOTCRON_OP_LIST     = 0x01,
    SOTCRON_OP_FIRE_NOW = 0x02,
} sotcron_op_t;

/* PR 9 · badge for the operator-driven listen EP forwarded into sotShell.
 * sotcron's non-blocking IPC drain (src/sotcron/main.c) uses the badge
 * to distinguish "real message arrived" from "no message pending" · the
 * kernel zeroes the badge register on doNBRecvFailedTransfer but writes
 * the cap badge into it on a successful seL4_NBRecv.  An unbadged listen
 * EP (badge==0 for both states) leaves no way to disambiguate.
 *
 * Distinct from BADGE_ORCH_ANOMALY_EVENT (0xA004) / SET_TIER (0xA009)
 * so any future audit consumers can attribute the call site. */
#define BADGE_SOTCRON_OPERATOR  0xC0FFE9UL

typedef struct {
    uint32_t op;
    char     name[64];
} sotcron_request_t;

typedef struct {
    int32_t  result;
    uint32_t timer_count;
    uint64_t next_fire_tsc;
} sotcron_reply_t;

#endif
