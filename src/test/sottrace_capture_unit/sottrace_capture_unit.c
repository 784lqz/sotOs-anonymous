#include <sottrace/trace.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
int main(void) {
    const char *a = "GET /admin HTTP/1.0\r\n";
    sottrace_capture_append(7, SOTTRACE_DIR_IN, (const uint8_t*)a, (uint32_t)strlen(a));
    sottrace_capture_append(7, SOTTRACE_DIR_IN, (const uint8_t*)"x", 1);
    const sottrace_capture_t *c = sottrace_capture_get(7);
    assert(c && c->len == strlen(a) + 1 && c->dropped == 0);
    assert(memcmp(c->buf, a, strlen(a)) == 0);
    static uint8_t big[SOTTRACE_CAPTURE_CAP + 100];
    memset(big, 'A', sizeof(big));
    sottrace_capture_append(9, SOTTRACE_DIR_IN, big, sizeof(big));
    c = sottrace_capture_get(9);
    assert(c && c->len == SOTTRACE_CAPTURE_CAP && c->dropped == 100);
    /* OUT stream is independent of the IN stream on a given conn. */
    sottrace_capture_append(5, SOTTRACE_DIR_OUT, (const uint8_t*)"resp", 4);
    assert(sottrace_capture_get(5)->len_out == 4 && sottrace_capture_get(5)->len == 0);
    sottrace_capture_release(7);
    assert(sottrace_capture_get(7) == NULL);
    for (int id = 100; id < 100 + SOTTRACE_CAPTURE_SLOTS + 1; ++id)
        sottrace_capture_append((uint16_t)id, SOTTRACE_DIR_IN, (const uint8_t*)"z", 1);
    assert(sottrace_capture_get(100) == NULL);                          /* oldest evicted */
    assert(sottrace_capture_get(100 + SOTTRACE_CAPTURE_SLOTS) != NULL);  /* newest kept */
    fprintf(stderr, "sottrace_capture_unit OK\n");
    return 0;
}
