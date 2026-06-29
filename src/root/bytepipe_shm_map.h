/* sotOs · root · byte-channel cross-vspace SHM mapping.  Mirrors
 * procd_shm_map.h.  Allocates the two SPSC rings and maps c2p RW->orch /
 * RO->responder and p2c RW->responder / RO->orch at the fixed BYTEPIPE_*_VADDR
 * addresses (see include/sotnet/bytepipe.h).  Returns 0 on full success (all
 * four mappings installed), negative otherwise; on failure the caller leaves
 * the byte-channel disabled and both sides fall back to the message-register
 * path. */
#ifndef SOTOS_ROOT_BYTEPIPE_SHM_MAP_H
#define SOTOS_ROOT_BYTEPIPE_SHM_MAP_H

#include "bootstrap.h"            /* sotos_env_t */
#include <sel4utils/process.h>    /* sel4utils_process_t */

int root_map_bytepipe_shm(sotos_env_t *env,
                          sel4utils_process_t *orch,
                          sel4utils_process_t *responder);

/* N2-T · inbound framed transport · maps the SECOND ring pair (in_c2p RW->orch /
 * RO->responder, in_p2c RW->responder / RO->orch) at BYTEPIPE_IN_*_VADDR.  Same
 * 0/negative contract as root_map_bytepipe_shm. */
int root_map_bytepipe_shm2(sotos_env_t *env,
                           sel4utils_process_t *orch,
                           sel4utils_process_t *responder);

/* SSH canary shell (Phase B) · maps the THIRD ring pair carrying the decrypted
 * shell stream: SHELL_IN  (RW->responder/net-synth, RO->orch) and SHELL_OUT
 * (RW->orch, RO->responder) at BYTEPIPE_SHELL_IN/OUT_VADDR.  Same 0/negative
 * contract as root_map_bytepipe_shm2; same (env, orch, responder) signature. */
int root_map_bytepipe_shm3(sotos_env_t *env,
                           sel4utils_process_t *orch,
                           sel4utils_process_t *responder);

#endif /* SOTOS_ROOT_BYTEPIPE_SHM_MAP_H */
