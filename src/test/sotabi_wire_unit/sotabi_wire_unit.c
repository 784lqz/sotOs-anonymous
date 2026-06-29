/* Host unit · sotabi render-stream wire codec: pack a byte buffer into 64-bit
 * words and unpack it back, chunk by chunk, reconstructing the original exactly
 * (incl. partial last words, multi-chunk streams, empty/at-end). */
#include <assert.h>
#include <string.h>
#include <stdio.h>
#include "sotabi/wire.h"

/* Stream the whole buffer in SOTABI_CHUNK_BYTES chunks, reassemble, compare. */
static void roundtrip(const char *src, int rlen)
{
    char out[8192];
    int off = 0;
    while (1) {
        uint64_t words[SOTABI_CHUNK_WORDS];
        int nwords = 0;
        int n = sotabi_pack_chunk(src, rlen, off, words, &nwords);
        assert(nwords == (n + 7) / 8);
        if (n == 0) break;                       /* end of stream */
        char chunk[SOTABI_CHUNK_BYTES];
        assert(sotabi_unpack_chunk(words, n, chunk) == n);
        memcpy(out + off, chunk, n);
        off += n;
    }
    assert(off == rlen);
    assert(memcmp(out, src, rlen) == 0);
}

static void test_small(void) {
    const char *s = "[sotctl] hi\n";          /* < 1 word + partial */
    roundtrip(s, (int)strlen(s));
}

static void test_exact_word(void) {
    const char *s = "ABCDEFGH";                /* exactly 8 bytes = 1 word */
    roundtrip(s, 8);
}

static void test_exact_chunk(void) {
    char s[SOTABI_CHUNK_BYTES];                /* exactly one full chunk */
    for (int i = 0; i < SOTABI_CHUNK_BYTES; ++i) s[i] = (char)(i & 0xff);
    roundtrip(s, SOTABI_CHUNK_BYTES);
}

static void test_multi_chunk(void) {
    char s[3000];                              /* several chunks + partial tail */
    for (int i = 0; i < 3000; ++i) s[i] = (char)((i * 7 + 3) & 0xff);
    roundtrip(s, 3000);
}

static void test_empty(void) {
    uint64_t words[SOTABI_CHUNK_WORDS]; int nw = -1;
    int n = sotabi_pack_chunk("", 0, 0, words, &nw);
    assert(n == 0 && nw == 0);
}

static void test_at_end_offset(void) {
    /* offset == rlen → 0 bytes (the terminating pull) */
    const char *s = "abc";
    uint64_t words[SOTABI_CHUNK_WORDS]; int nw = -1;
    assert(sotabi_pack_chunk(s, 3, 3, words, &nw) == 0);
    assert(nw == 0);
}

static void test_binary_bytes(void) {
    /* high bytes / NULs survive the pack (it is byte-exact, not string-based) */
    char s[20]; for (int i = 0; i < 20; ++i) s[i] = (char)(0x80 | i);
    s[5] = '\0'; s[11] = (char)0xff;
    roundtrip(s, 20);
}

int main(void) {
    test_small();
    test_exact_word();
    test_exact_chunk();
    test_multi_chunk();
    test_empty();
    test_at_end_offset();
    test_binary_bytes();
    printf("sotabi_wire_unit: OK\n");
    return 0;
}
