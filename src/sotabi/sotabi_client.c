/*
 * sotabi · native client helpers (M4) — the native runtime's IPC to truth-core.
 *
 * Thin wrappers over seL4_Call that implement the formal sotabi envelope
 * (request MR0=op, reply MR0=status).  A native binary links this instead of
 * hand-rolling the IPC, so the wire format lives in ONE place shared with orch's
 * server via include/sotabi/{proto,wire}.h.
 */
#include <sotabi/client.h>
#include <sotabi/proto.h>
#include <sotabi/wire.h>

int sotabi_hello(seL4_CPtr ep, uint32_t *out_version)
{
    seL4_SetMR(0, SOTABI_OP_HELLO);
    seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 1));
    int status = (int)seL4_GetMR(0);
    uint32_t ver = (uint32_t)seL4_GetMR(1);
    if (out_version) *out_version = ver;
    if (status != SOTABI_OK) return -status;
    if (ver != SOTABI_VERSION) return -SOTABI_E_BADVER;
    return SOTABI_OK;
}

int sotabi_stats(seL4_CPtr ep, uint32_t *out_sessions, uint32_t *out_procs)
{
    seL4_SetMR(0, SOTABI_OP_STATS);
    seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 1));
    int status = (int)seL4_GetMR(0);
    if (out_sessions) *out_sessions = (uint32_t)seL4_GetMR(1);
    if (out_procs)    *out_procs    = (uint32_t)seL4_GetMR(2);
    return (status != SOTABI_OK) ? -status : SOTABI_OK;
}

int sotabi_render_stream(seL4_CPtr ep,
                         void (*emit)(const char *chunk, int nbytes, void *ctx),
                         void *ctx)
{
    int off = 0;
    for (;;) {
        seL4_SetMR(0, SOTABI_OP_RENDER_PULL);
        seL4_SetMR(1, (seL4_Word)off);
        seL4_Call(ep, seL4_MessageInfo_new(0, 0, 0, 2));
        int status = (int)seL4_GetMR(0);
        if (status != SOTABI_OK) break;
        int n = (int)seL4_GetMR(1);
        if (n <= 0) break;                       /* end of stream */
        if (n > SOTABI_CHUNK_BYTES) n = SOTABI_CHUNK_BYTES;

        /* Reply payload starts at MR2; the wire codec packs from word 0, so copy
         * MR2.. into a word buffer for sotabi_unpack_chunk. */
        uint64_t words[SOTABI_CHUNK_WORDS];
        int nwords = (n + 7) / 8;
        for (int w = 0; w < nwords; ++w) words[w] = (uint64_t)seL4_GetMR(2 + w);

        char chunk[SOTABI_CHUNK_BYTES + 1];
        sotabi_unpack_chunk(words, n, chunk);
        chunk[n] = '\0';
        if (emit) emit(chunk, n, ctx);
        off += n;
    }
    return off;
}
