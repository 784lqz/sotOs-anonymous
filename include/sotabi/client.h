#ifndef SOTABI_CLIENT_H
#define SOTABI_CLIENT_H
/*
 * sotabi · the native client helpers (M4).
 *
 * A native sotOs binary links this to speak sotabi to orch's libsot endpoint
 * instead of hand-rolling seL4_Call sequences.  This is the seam where the
 * native runtime (sotcrt/sotlibc) reaches truth-core over IPC.  All calls take
 * the libsot endpoint cap handed to the binary at spawn (argv[1]).
 */
#include <sel4/sel4.h>
#include <stdint.h>

/* Handshake: read orch's SOTABI_VERSION into *out_version.
 * Returns 0 (SOTABI_OK) on success, or a negative status on mismatch/error. */
int sotabi_hello(seL4_CPtr ep, uint32_t *out_version);

/* Health: read the live session + process counts from truth-core. Returns 0. */
int sotabi_stats(seL4_CPtr ep, uint32_t *out_sessions, uint32_t *out_procs);

/* Pull the full render stream (orch renders the operator-chosen content op) and
 * hand each decoded chunk to `emit` (already NUL-terminated for printf("%s")).
 * Returns the total byte count streamed. */
int sotabi_render_stream(seL4_CPtr ep,
                         void (*emit)(const char *chunk, int nbytes, void *ctx),
                         void *ctx);

#endif /* SOTABI_CLIENT_H */
