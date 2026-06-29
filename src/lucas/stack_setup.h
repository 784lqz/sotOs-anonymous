#ifndef SOTOS_LUCAS_STACK_SETUP_H
#define SOTOS_LUCAS_STACK_SETUP_H

#include <stdint.h>
#include <stddef.h>

struct lucas_state;

/* Allocate the client's initial stack and lay out argv/envp/auxv.
 * Sets st->stack_top to the resulting RSP value the client should start with.
 * Returns 0 on success. */
int lucas_stack_setup(struct lucas_state *st,
                       const char *const argv[],
                       const char *const envp[]);

#endif /* SOTOS_LUCAS_STACK_SETUP_H */
