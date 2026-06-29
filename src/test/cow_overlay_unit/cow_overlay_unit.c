/* Host unit · per-session COW-lite overlay: a Tier-2 write is read back within
 * the session; the base is never mutated; reap frees the session's entries. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "lucas/cow_overlay.h"

int main(void) {
    lucas_cow_init();
    /* no overlay yet → has() false */
    assert(lucas_cow_has(7 /*session*/, "/etc/passwd") == 0);
    /* write to the overlay */
    const char *edit = "root:x:0:0:HACKED:/root:/bin/sh\n";
    assert(lucas_cow_write(7, "/etc/passwd", (const uint8_t*)edit, strlen(edit)) == 0);
    assert(lucas_cow_has(7, "/etc/passwd") == 1);
    /* read back returns the overlay */
    uint8_t buf[128]; int n = lucas_cow_read(7, "/etc/passwd", buf, sizeof(buf));
    assert(n == (int)strlen(edit) && memcmp(buf, edit, n) == 0);
    /* a different session does NOT see it */
    assert(lucas_cow_has(9, "/etc/passwd") == 0);
    /* overwrite replaces */
    const char *edit2 = "shorter\n";
    assert(lucas_cow_write(7, "/etc/passwd", (const uint8_t*)edit2, strlen(edit2)) == 0);
    n = lucas_cow_read(7, "/etc/passwd", buf, sizeof(buf));
    assert(n == (int)strlen(edit2) && memcmp(buf, edit2, n) == 0);
    /* reap session 7 frees it */
    lucas_cow_reap(7);
    assert(lucas_cow_has(7, "/etc/passwd") == 0);
    /* F3 · truncate shrinks an existing overlay entry; truncate-to-0 empties it. */
    assert(lucas_cow_write(7, "/etc/passwd", (const uint8_t*)edit, strlen(edit)) == 0);
    assert(lucas_cow_truncate(7, "/etc/passwd", 4) == 0);
    { uint8_t b2[128]; int m = lucas_cow_read(7, "/etc/passwd", b2, sizeof(b2));
      assert(m == 4 && memcmp(b2, edit, 4) == 0); }
    assert(lucas_cow_truncate(7, "/etc/passwd", 0) == 0);
    assert(lucas_cow_read(7, "/etc/passwd", (uint8_t[1]){0}, 1) == 0);  /* len 0 */
    /* truncate of a non-existent overlay entry → no-op success (0) */
    assert(lucas_cow_truncate(7, "/nope", 0) == 0);
    printf("[cow-overlay-unit] ALL PASS\n");
    return 0;
}
