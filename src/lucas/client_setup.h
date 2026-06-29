#ifndef SOTOS_LUCAS_CLIENT_SETUP_H
#define SOTOS_LUCAS_CLIENT_SETUP_H

struct lucas_state;

/* Allocate the client TCB + a minimal CSpace + an IPC buffer frame.
 * Bind the fault endpoint. Set initial registers (RIP=entry, RSP=stack_top).
 * Does NOT resume. Returns 0 on success. */
int lucas_client_setup(struct lucas_state *st);

/* Resume the client TCB. After this it begins executing the Linux ELF. */
int lucas_client_resume(struct lucas_state *st);

#endif /* SOTOS_LUCAS_CLIENT_SETUP_H */
