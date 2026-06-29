#ifndef LUCAS_ANOMALY_H
#define LUCAS_ANOMALY_H

#include <stdint.h>

struct lucas_state;
void anomaly_on_write(struct lucas_state *st, uint64_t fd, uint64_t bytes);

/* Spec B · shared sync-event forwarder + reply-tier applier.  Extern so the
 * cred/unlink/exec emitters (PR 3-5 · handlers_fs.c, src/orch/execve.c) can
 * forward their own kinds and apply the authoritative reply tier. */
int  anomaly_forward_sync(struct lucas_state *st, int kind, uint64_t magnitude);
void anomaly_apply_reply_tier(struct lucas_state *st, int target);

#endif
