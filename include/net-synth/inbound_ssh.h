/* sotOs · net-synth · N2-R Phase B · server-speaks-first SSH response_profile. */
#ifndef NET_SYNTH_INBOUND_SSH_H
#define NET_SYNTH_INBOUND_SSH_H
#include <stdint.h>
#include <stddef.h>
/* Drive the SSH response_profile for one inbound frame on a :22 conn. `req`/`reqlen` is
 * the client's bytes (len==0 = the ESTABLISHED greet). Writes the reply into
 * out[]; returns reply length (0 = nothing to send this frame). */
uint32_t ssh_respond(uint16_t conn_id, const uint8_t *req, uint32_t reqlen,
                     uint8_t *out, uint32_t outmax);

/* Phase B · SSH canary shell glue (called from net-synth/main.c, which owns the
 * SHELL_IN/OUT rings + the in_p2c reply channel). */

/* main.c tells the transport whether the shell rings mapped (R7 · degrade to the
 * Phase A echo when 0).  Set once at startup. */
void ssh_shell_rings_set_ready(int ready);

/* R2 · main.c marks a busybox shell live/dead so a 2nd concurrent shell-request
 * is refused with CHANNEL_FAILURE (one attacker shell at a time for v1). */
void ssh_shell_set_busy(int busy);

/* Returns 1 (and clears the flag) if conn_id has a pending shell-start signal
 * that main.c should turn into a SHELL_START frame on in_p2c; 0 otherwise. */
int ssh_take_shell_start(uint16_t conn_id);

/* Returns 1 (and clears the flag) if conn_id's attacker has gone (CHANNEL_EOF/
 * CLOSE) and main.c should push SHELL_KILL on in_p2c to reap busybox. */
int ssh_take_client_eof(uint16_t conn_id);

/* Wrap `data` as an encrypted CHANNEL_DATA on conn_id's channel (busybox stdout
 * → wire).  Returns bytes written to out, 0 on overflow / unknown conn. */
uint32_t ssh_emit_channel_data(uint16_t conn_id, const uint8_t *data, uint32_t len,
                               uint8_t *out, uint32_t outmax);

/* Emit CHANNEL_EOF + CHANNEL_CLOSE on conn_id's channel (busybox exited).
 * Returns bytes written to out, 0 on overflow / unknown conn. */
uint32_t ssh_emit_channel_close(uint16_t conn_id, uint8_t *out, uint32_t outmax);
#endif
