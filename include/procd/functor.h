/* sotOs · procd · functor binding identifiers + default table.
 *
 * Spec: procd-process-server-design §6.2.
 */
#ifndef PROCD_FUNCTOR_H
#define PROCD_FUNCTOR_H

#include <stdint.h>
#include <procd/proc.h>

/* Filesystem-functor instances · F_sotFS */
enum {
    FFS_IDENTITY = 0,    /* T0 · sin engaño */
    FFS_WRITE_SILENCED    = 1,    /* T1 · escrituras silenciadas + rollback */
    FFS_ISOLATED   = 2,    /* T2 · escrituras a vista shadow */
    FFS_REVOKED  = 3,    /* T3 · capacidades anuladas */
};

/* Network-functor instances · F_sotNet */
enum {
    FNET_IDENTITY = 0,
    FNET_SYNTH  = 1,
    FNET_REVOKED  = 2,
};

/* Process-functor instances · F_proc */
enum {
    FPROC_IDENTITY      = 0,
    FPROC_SYNTH_FORK  = 1,    /* fork returns synth slot */
    FPROC_REVOKED       = 2,
};

typedef struct {
    uint16_t fs;
    uint16_t net;
    uint16_t proc;
    uint16_t _pad;
} functor_binding_t;

/* Default binding per tier · used unless OP_REBIND_FUNCTOR overrides. */
static const functor_binding_t procd_default_functor_for_tier[4] = {
    [PROC_TIER_0] = { .fs = FFS_IDENTITY, .net = FNET_IDENTITY, .proc = FPROC_IDENTITY },
    [PROC_TIER_1] = { .fs = FFS_WRITE_SILENCED,    .net = FNET_IDENTITY, .proc = FPROC_IDENTITY },
    [PROC_TIER_2] = { .fs = FFS_ISOLATED,   .net = FNET_SYNTH,  .proc = FPROC_SYNTH_FORK },
    [PROC_TIER_3] = { .fs = FFS_REVOKED,  .net = FNET_REVOKED,  .proc = FPROC_REVOKED },
};

#endif /* PROCD_FUNCTOR_H */
