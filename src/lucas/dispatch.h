#ifndef SOTOS_LUCAS_DISPATCH_H
#define SOTOS_LUCAS_DISPATCH_H

#include "handlers.h"
#include <stdint.h>

/* Forward declaration only; callers that use lucas_dispatch_call must
 * include state.h before dispatch.h so lucas_state_t is already defined. */
struct lucas_state;

/* Find the handler for syscall number `sysno`. Returns the ENOSYS stub
 * if not registered. */
lucas_handler_fn lucas_dispatch(unsigned int sysno);

/* obsd-δ: pledge gate + handler dispatch.
 * Checks the sotBox pledge bitmask before calling the handler.
 * On violation: promotes tier to 1 (silenced), logs, returns 0 (synthetic success).
 * Otherwise: calls the handler and returns its result. */
int64_t lucas_dispatch_call(struct lucas_state *st, unsigned int sysno,
                             uint64_t a0, uint64_t a1, uint64_t a2,
                             uint64_t a3, uint64_t a4, uint64_t a5);

#endif
