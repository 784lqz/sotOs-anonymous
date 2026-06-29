/*
 * sotOs · pidrand · deterministic, reproducible-by-design display pid.
 *
 * The per-sotbox display_pid (the pid a sotbox sees via getpid · OBSD-ζ
 * anti-fingerprinting cosmetic) used to be drawn from the GLOBAL arc4random
 * stream, which (a) made it non-reproducible across boots and (b) coupled it
 * positionally to the ASLR draws on that same stream.  sotos_pid_display is a
 * SEPARATE, stateless generator keyed on synthetic_pid (= slot+1, deterministic):
 *   - reproducible across boots (fixed compile-time seed),
 *   - independent of call order (stateless · the lazy re-draws reproduce the
 *     spawn-time value),
 *   - never returns 0 (POSIX-friendly),
 *   - does NOT touch the entropy-seeded arc4random/ASLR stream.
 *
 * See pidrand-c2-10-design.
 */
#ifndef SOTOS_PIDRAND_H
#define SOTOS_PIDRAND_H

#include <stdint.h>

uint32_t sotos_pid_display(uint32_t synthetic_pid);

#endif /* SOTOS_PIDRAND_H */
