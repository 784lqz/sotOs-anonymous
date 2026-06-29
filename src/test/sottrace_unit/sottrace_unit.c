/* Host unit test for the sottrace ring. Compile + run on the host:
 *   cc -I include src/sottrace/trace.c src/test/sottrace_unit/sottrace_unit.c \
 *      -o /tmp/sottrace_unit && /tmp/sottrace_unit
 * Exercises publish ordering and snapshot newest-first semantics. */
#include <sottrace/trace.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

int main(void) {
    uint64_t args[6] = {1, 2, 3, 4, 5, 6};

    /* publish 3 events on slot 0: enter, exit, tier */
    trace_emit_enter(0, 7, 2 /*open*/, args, 0x400000);
    trace_emit_exit (0, 7, 2, 5 /*fd*/, 0x400000);
    trace_emit_tier (0, 7, 0, 1);

    sotguard_event_t out[8];
    uint32_t total = 0;
    uint32_t n = sottrace_peek_recent(out, 8, &total);

    assert(n == 3);
    assert(total == 3);
    /* newest-first: tier, exit, enter */
    assert(out[0].type == SG_EV_TIER_ASSIGN);
    assert(out[1].type == SG_EV_SYSCALL_EXIT);
    assert(out[2].type == SG_EV_SYSCALL_ENTER);
    assert(out[1].detail.syscall.ret == 5);
    assert(out[2].detail.syscall.args[0] == 1);

    /* overflow: push > N events on slot 1, peek caps at max and stays newest-first */
    for (int i = 0; i < SOTTRACE_RING_N + 50; ++i)
        trace_emit_exit(1, 9, 1, i, 0);
    n = sottrace_peek_recent(out, 4, &total);
    assert(n == 4);
    assert(out[0].timestamp >= out[1].timestamp);   /* sorted desc; rdtsc ties are legal */

    /* loss visibility (spec §8 crit 7): ring 1 now holds N+50 undrained events
     * (tail=0, head=N+50 ⇒ lag > N), so the live drain MUST report the drop.
     * Capture stdout to a file and assert the "(lost " line appears. */
    g_trace_live = 1;
    freopen("/tmp/sottrace_drain.txt", "w", stdout);
    sottrace_drain_to_serial();
    fflush(stdout);
    FILE *rf = fopen("/tmp/sottrace_drain.txt", "r");
    char fbuf[8192];
    size_t got = rf ? fread(fbuf, 1, sizeof(fbuf) - 1, rf) : 0;
    if (rf) fclose(rf);
    fbuf[got] = 0;
    int loss_ok = (strstr(fbuf, "(lost ") != NULL);

    /* v2.8 · dashboard formatter (the `watch` deception monitor view). */
    sotguard_event_t cev; memset(&cev, 0, sizeof cev);
    cev.type = SG_EV_CANARY_READ; cev.pid = 7;
    strncpy(cev.detail.fs.path, "/etc/passwd", sizeof(cev.detail.fs.path) - 1);
    char dl[160]; sottrace_format_dashboard_line(dl, sizeof dl, &cev);
    int dash_ok = (strstr(dl, "CANARY READ") != NULL) && (strstr(dl, "/etc/passwd") != NULL)
                  && (strstr(dl, "tsc=") == NULL);   /* clean view · no raw tsc */
    sotguard_event_t sev; memset(&sev, 0, sizeof sev);
    sev.type = SG_EV_SYSCALL_ENTER;                  /* syscall flood → not surfaced */
    sottrace_format_dashboard_line(dl, sizeof dl, &sev);
    dash_ok = dash_ok && (dl[0] == '\0');

    int ok = loss_ok && dash_ok;
    /* final status to stderr (stdout was redirected to the capture file) */
    fprintf(stderr, "sottrace_unit %s\n",
            ok ? "OK (publish/peek/overflow/loss-report/dashboard verified)"
               : (loss_ok ? "FAIL (dashboard format)" : "FAIL (drain did not report loss)"));
    return ok ? 0 : 1;
}
