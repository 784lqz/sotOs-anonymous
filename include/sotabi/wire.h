#ifndef SOTABI_WIRE_H
#define SOTABI_WIRE_H
/*
 * sotabi · the render-stream wire codec (M4).
 *
 * Header-only, pure (no seL4, no malloc): packs a byte chunk into 64-bit message
 * words (8 bytes/word, little-endian) and back.  Both orch (server) and the
 * native client include it and agree byte-for-byte; a host unit test exercises
 * the round-trip with plain `cc`.  Uses uint64_t (== seL4_Word on x86_64); the
 * caller casts to/from seL4 message registers.
 */
#include <stdint.h>
#include <sotabi/proto.h>

/*
 * sotabi_pack_chunk — pack up to SOTABI_CHUNK_BYTES bytes from src[off..off+rlen)
 * into words[].  Returns the byte count packed (n), and sets *out_words to the
 * number of 64-bit words written (ceil(n/8)).  n is clamped so a single chunk
 * never exceeds SOTABI_CHUNK_BYTES; n == 0 means the stream is exhausted.
 */
static inline int sotabi_pack_chunk(const char *src, int rlen, int off,
                                    uint64_t *words, int *out_words)
{
    int n = rlen - off;
    if (n < 0) n = 0;
    if (n > SOTABI_CHUNK_BYTES) n = SOTABI_CHUNK_BYTES;
    int nwords = (n + 7) / 8;
    for (int w = 0; w < nwords; ++w) {
        uint64_t v = 0;
        for (int b = 0; b < 8; ++b) {
            int rel = w * 8 + b;            /* byte index within this chunk */
            if (rel < n)
                v |= ((uint64_t)(unsigned char)src[off + rel]) << (b * 8);
        }
        words[w] = v;
    }
    if (out_words) *out_words = nwords;
    return n;
}

/*
 * sotabi_unpack_chunk — unpack n bytes (packed by sotabi_pack_chunk) from
 * words[] into dst[].  dst must hold at least n bytes.  Returns n.
 */
static inline int sotabi_unpack_chunk(const uint64_t *words, int n, char *dst)
{
    if (n < 0) n = 0;
    if (n > SOTABI_CHUNK_BYTES) n = SOTABI_CHUNK_BYTES;
    for (int i = 0; i < n; ++i)
        dst[i] = (char)((words[i / 8] >> ((i % 8) * 8)) & 0xff);
    return n;
}

#endif /* SOTABI_WIRE_H */
