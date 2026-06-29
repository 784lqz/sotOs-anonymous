#ifndef SOTOS_LUCAS_ANTIDOS_H
#define SOTOS_LUCAS_ANTIDOS_H
#include "state.h"
#include <stdint.h>

/* P2b · fork-bomb quota: max LIVE (un-reaped) child forks before a sotbox is judged
 * a fork-bomb and quarantined.  Counts concurrent children (decremented on wait4),
 * so it must clear realistic concurrency — `make -jN`, a ./configure probe storm,
 * `xargs -P`, a build system — which a 16-child cap killed (exit 137), a glaring
 * detection tell no real host shows.  A true bomb forks exponentially and blows
 * past this ceiling in milliseconds, so the gate still fires; it just no longer
 * trips on a normal parallel workload. */
#define SOTBOX_FORK_QUOTA  256

/* Quarantine + terminate the offending cell (Tier-2 + suspend subtree + flag children for teardown +
 * trace) and reap the parent via the exit path. Returns the syscall value the fork
 * handler should return (the exit-path return — the cell is terminating). */
int64_t lucas_antidos_quarantine(lucas_state_t *st);

#endif
