/* Host unit test for src/sotlibc/sotlibc.c — the world-#3 freestanding C
 * runtime core (mem/str/strtoul/printf engine).  NOT part of `just build`:
 *   cc -I include src/test/sotlibc_unit/sotlibc_unit.c src/sotlibc/sotlibc.c \
 *      -o /tmp/sotlibc_unit && /tmp/sotlibc_unit
 *
 * sotlibc.c is platform-free (no seL4, no muslc, no host libc): it is exactly
 * the code that runs in the native binary, so passing here proves the engine.
 * The serial sink (sotlibc_serial.c) is seL4-only and not exercised here.
 */
#include <sotlibc/sotlibc.h>
#include <stdio.h>
#include <string.h>

static int fails = 0;
#define CHECK(c) do { if (!(c)) { printf("FAIL: %s (line %d)\n", #c, __LINE__); fails++; } } while (0)
#define CHECK_STR(got, want) do { \
    if (strcmp((got), (want)) != 0) { \
        printf("FAIL line %d: got \"%s\" want \"%s\"\n", __LINE__, (got), (want)); fails++; } \
    } while (0)

/* drive sot_snprintf and compare the produced string + returned length. */
static void fmt(const char *want, const char *fmtstr, ...) {
    char buf[128];
    va_list ap; va_start(ap, fmtstr);
    int n = sot_vsnprintf(buf, sizeof buf, fmtstr, ap);
    va_end(ap);
    CHECK_STR(buf, want);
    CHECK(n == (int)strlen(want));
}

int main(void)
{
    /* ── memory ─────────────────────────────────────────────────────────── */
    char a[8], b[8];
    sot_memset(a, 0x5a, sizeof a);
    for (int i = 0; i < 8; i++) CHECK(a[i] == 0x5a);
    sot_memcpy(b, a, sizeof b);
    CHECK(sot_memcmp(a, b, 8) == 0);
    b[3] = 0x00;
    CHECK(sot_memcmp(a, b, 8) > 0);          /* a[3]=0x5a > b[3]=0x00 */
    CHECK(sot_memcmp(b, a, 8) < 0);

    /* ── string ─────────────────────────────────────────────────────────── */
    CHECK(sot_strlen("") == 0);
    CHECK(sot_strlen("sotOs") == 5);
    CHECK(sot_strcmp("abc", "abc") == 0);
    CHECK(sot_strcmp("abc", "abd") < 0);
    CHECK(sot_strcmp("abd", "abc") > 0);
    CHECK(sot_strncmp("abcXX", "abcYY", 3) == 0);
    CHECK(sot_strncmp("abcXX", "abcYY", 4) != 0);

    /* ── strtoul · base 0 (auto), 10, 16, 8 ─────────────────────────────── */
    char *end;
    CHECK(sot_strtoul("0", &end, 10) == 0 && *end == '\0');
    CHECK(sot_strtoul("12345", &end, 10) == 12345 && *end == '\0');
    CHECK(sot_strtoul("  42rest", &end, 10) == 42 && end[0] == 'r');   /* skip ws, stop at non-digit */
    CHECK(sot_strtoul("0xFF", NULL, 16) == 255);
    CHECK(sot_strtoul("0x10", NULL, 0) == 16);   /* auto-hex */
    CHECK(sot_strtoul("010", NULL, 0) == 8);     /* auto-octal */
    CHECK(sot_strtoul("99", NULL, 0) == 99);     /* auto-decimal */
    CHECK(sot_strtoul("4294967295", NULL, 10) == 4294967295UL);  /* a real argv cap */

    /* ── printf engine · the conversions sotctl uses ────────────────────── */
    fmt("hello", "hello");
    fmt("pct %", "pct %%");
    fmt("str=sotOs.", "str=%s.", "sotOs");
    fmt("null=(null)", "null=%s", (char *)NULL);
    fmt("c=A", "c=%c", 'A');
    fmt("d=0", "d=%d", 0);
    fmt("d=42", "d=%d", 42);
    fmt("d=-42", "d=%d", -42);
    fmt("u=4294967295", "u=%u", 4294967295U);
    fmt("x=deadbeef", "x=%x", 0xdeadbeefU);
    fmt("ld=-5", "ld=%ld", (long)-5);
    fmt("lu=12345678901", "lu=%lu", 12345678901UL);
    fmt("lx=ff00ff00ff", "lx=%lx", 0xff00ff00ffUL);

    /* width + flags (the table-alignment cases) */
    fmt("[  7]", "[%3d]", 7);
    fmt("[7  ]", "[%-3d]", 7);
    fmt("[007]", "[%03d]", 7);
    fmt("[abc  ]", "[%-5s]", "abc");
    fmt("[  abc]", "[%5s]", "abc");

    /* %p renders 0x-prefixed lowercase hex */
    char pbuf[32];
    sot_snprintf(pbuf, sizeof pbuf, "%p", (void *)0x1000);
    CHECK_STR(pbuf, "0x1000");

    /* snprintf truncation: returns full length, buffer stays NUL-terminated */
    char small[4];
    int n = sot_snprintf(small, sizeof small, "%s", "abcdefg");
    CHECK(n == 7);                 /* would-be length */
    CHECK(small[3] == '\0');       /* never overruns */
    CHECK_STR(small, "abc");

    if (fails == 0) printf("sotlibc_unit: ALL PASS\n");
    else            printf("sotlibc_unit: %d FAIL(s)\n", fails);
    return fails ? 1 : 0;
}
