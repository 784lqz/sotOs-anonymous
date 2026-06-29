/*
 * sotOs · sotctl — the NATIVE operator control CLI (sotabi · M4/M5).
 *
 * A native seL4 binary — NOT a Linux guest, NOT Wine.  Runs as its OWN sotbox
 * and reaches truth-core over the formal sotabi ABI (the libsot endpoint passed
 * in argv[1]), never /proc.  A Linux program sees the persona-curated /proc;
 * this native program sees the operative truth.
 *
 * It speaks sotabi through the client library (include/sotabi/client.h): an
 * OP_HELLO version handshake, an OP_STATS health read, then the render stream
 * (orch renders the operator-chosen content op and streams it back in chunks).
 * The wire format lives in ONE shared place (sotabi/{proto,wire}.h) — no
 * hand-rolled IPC.
 */
#include <sel4/sel4.h>
#include <stdio.h>
#include <stdlib.h>
#include <sotabi/proto.h>
#include <sotabi/client.h>

static void emit_chunk(const char *chunk, int nbytes, void *ctx)
{
    (void)nbytes; (void)ctx;
    printf("%s", chunk);            /* the rendered table already carries newlines */
}

int main(int argc, char *argv[])
{
    seL4_CPtr ep = (argc >= 2) ? (seL4_CPtr)strtoul(argv[1], NULL, 10) : 0;
    if (!ep) {
        printf("[sotctl-native] no libsot endpoint · cannot reach truth-core · exiting\n");
        return 1;
    }

    /* Handshake — refuse to proceed on an ABI mismatch. */
    uint32_t ver = 0;
    int hrc = sotabi_hello(ep, &ver);
    if (hrc != SOTABI_OK) {
        printf("[sotctl-native] sotabi handshake FAILED (rc=%d · orch ver=%u, mine=%u)\n",
               hrc, ver, (unsigned)SOTABI_VERSION);
        return 1;
    }
    printf("[sotctl-native] sotabi v%u handshake OK\n", ver);

    /* Health snapshot over the formal envelope. */
    uint32_t ns = 0, np = 0;
    if (sotabi_stats(ep, &ns, &np) == SOTABI_OK)
        printf("[sotctl-native] stats · %u session(s) · %u live process(es) (truth-core)\n",
               ns, np);

    /* The operator-chosen view, streamed from truth-core. */
    int total = sotabi_render_stream(ep, emit_chunk, NULL);
    printf("[sotctl-native] (render-stream complete · %d bytes over sotabi · truth-core)\n",
           total);
    return 0;
}
