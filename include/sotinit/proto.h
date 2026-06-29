/* sotOs · sotinit · wire protocol · ABI v1.
 *
 * The init scheduler (sotinit) is a Path D process spawned by root.  It
 * owns the systemd-style unit registry (services / timers / targets) and
 * relies on procd for OP_SPAWN/OP_EXIT lifecycle when activating units.
 *
 * Operators talk to sotinit via the SOTINIT_OP_* wire protocol.  Boot is
 * the implicit BOOT op (root triggers it before handing control to the
 * shell); LIST / STATUS / ACTIVATE / START / STOP are operator-driven.
 *
 * Spec: init-cron-scheduler-design §3.
 */
#ifndef SOTINIT_PROTO_H
#define SOTINIT_PROTO_H

#include <stdint.h>

typedef enum {
    SOTINIT_OP_BOOT        = 0x01,
    SOTINIT_OP_LIST        = 0x02,
    SOTINIT_OP_STATUS      = 0x03,
    SOTINIT_OP_ACTIVATE    = 0x04,
    SOTINIT_OP_START       = 0x05,
    SOTINIT_OP_STOP        = 0x06,
    /* PR 6 · orch → sotinit one-way notification.  Sent by orch's
     * orch_procd_drain when a PROCD_EV_PROC_EXITED event arrives from
     * procd's event ring · sotinit looks up the unit bound to that
     * procd slot and applies the unit's Restart= policy (no /
     * on-failure / always) with a 500 ms backoff.  Fired via NBSend
     * (orch must not block on sotinit) · the listen-loop reads
     * MR(1)=slot, MR(2)=exit_code and does NOT seL4_Reply. */
    SOTINIT_OP_PROC_EXITED = 0x07,
} sotinit_op_t;

typedef struct {
    uint32_t op;
    uint32_t arg32;
    char     name[64];
} sotinit_request_t;

typedef struct {
    int32_t  result;
    uint32_t state;
    uint32_t procd_slot;
} sotinit_reply_t;

#endif
