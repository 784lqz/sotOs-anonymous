#ifndef SOTNET_SYNTH_H
#define SOTNET_SYNTH_H
#include <stdint.h>
void synth_record_redirect(uint32_t pid, uint32_t dst_ip_be,
                              uint16_t dst_port_be, uint32_t len);
uint32_t synth_get_redirects(void);
uint32_t synth_get_bytes(void);
/* STAR Tier-2 · PER-PID-SYNTH-COUNTER · per-sotbox synth redirect count.
 * pid is synthetic_pid (slot+1), valid range 1..ORCH_STATUS_MAX_ENTRIES.
 * Out-of-range pids (e.g. the synthetic pid=99 boot trigger) return 0. */
uint32_t synth_get_redirects_pid(uint32_t pid);

/* PR 6 · WAL replay-applies for SOTNET_SYNTH records.  Bumps the
 * total + per-pid counters without firing the synthetic boot trigger
 * or the orch-event IPC · pure counter restoration so a cold-boot
 * `sotinfo` reflects pre-reboot redirect counts.  src_slot is the
 * synthetic_pid stored in the WAL record (lucas writes procd_slot when
 * bound, else synthetic_pid). */
void synth_replay_bump(uint32_t src_slot, uint32_t bytes);
#endif
