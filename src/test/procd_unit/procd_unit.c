/* sotOs · procd unit tests · seqlock + slot allocator + ring.
 *
 * Standalone ELF spawned by root for the procd-unit smoke check.
 * Prints PASS/FAIL lines that smoke-procd.sh greps.
 */
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sel4/sel4.h>
#include <procd/proc.h>
#include <procd/shm.h>
#include <procd/events.h>

extern void procd_table_init(void *shm_base);
extern int  procd_slot_alloc(uint32_t *out_slot);
extern int  procd_slot_free(uint32_t slot);
extern int  procd_thread_alloc(uint32_t *out_tslot);
extern int  procd_thread_free(uint32_t tslot);

static uint8_t g_shm[PROCD_SHM_BYTES] __attribute__((aligned(4096)));

static int test_table_alloc_free(void) {
    procd_table_init(g_shm);
    uint32_t s = 0;
    if (procd_slot_alloc(&s) != 0) return 1;
    if (s == 0 || s >= PROCD_MAX_PROCS) return 2;
    if (procd_slot_free(s) != 0) return 3;
    return 0;
}

static int test_table_full(void) {
    procd_table_init(g_shm);
    uint32_t s = 0;
    int allocated = 0;
    for (int i = 0; i < PROCD_MAX_PROCS + 8; i++) {
        if (procd_slot_alloc(&s) == 0) allocated++;
    }
    if (allocated > PROCD_MAX_PROCS - 1) return 1;  /* slot 0 reserved */
    if (procd_slot_alloc(&s) == 0) return 2;        /* must fail when full */
    return 0;
}

static int test_seqlock_round_trip(void) {
    proc_t p;
    memset(&p, 0, sizeof(p));
    p.tier = PROC_TIER_0;
    p.version = 0;
    for (int i = 0; i < 1000; i++) {
        procd_seqlock_begin(&p);
        p.tier = (i & 1) ? PROC_TIER_2 : PROC_TIER_1;
        procd_seqlock_end(&p);
        proc_tier_t t = procd_tier_load(&p);
        if (t != p.tier) return 1;
    }
    return 0;
}

/* PR 4 · publish N + 100 events into a fresh ring then drain with
 * tail=0.  The consumer is now N+100 behind the writer · drain MUST
 * report overflow=1 and snap the tail forward.  Stack-allocate a
 * static ring (28 KiB) to keep it off the test's already-stretched
 * .bss budget. */
static procd_event_ring_t s_test_ring;

static int test_event_ring_overflow(void) {
    procd_event_ring_init(&s_test_ring);
    for (uint32_t i = 0; i < PROCD_EVENT_RING_N + 100; i++) {
        procd_event_publish(&s_test_ring, PROCD_EV_PROC_BORN, i, 0);
    }
    procd_event_t buf[32];
    uint64_t tail = 0;
    int overflow = 0;
    procd_event_drain(&s_test_ring, &tail, buf, 32, &overflow);
    return overflow ? 0 : 1;
}

int main(int argc, char *argv[]) {
    (void)argc; (void)argv;
    printf("[procd-unit] start\n");

    int rc;
    rc = test_table_alloc_free();
    printf("[procd-unit] %s test_table_alloc_free rc=%d\n",
           rc == 0 ? "PASS" : "FAIL", rc);
    if (rc) return 1;

    rc = test_table_full();
    printf("[procd-unit] %s test_table_full rc=%d\n",
           rc == 0 ? "PASS" : "FAIL", rc);
    if (rc) return 1;

    rc = test_seqlock_round_trip();
    printf("[procd-unit] %s test_seqlock_round_trip rc=%d\n",
           rc == 0 ? "PASS" : "FAIL", rc);
    if (rc) return 1;

    rc = test_event_ring_overflow();
    printf("[procd-unit] %s test_event_ring_overflow rc=%d\n",
           rc == 0 ? "PASS" : "FAIL", rc);
    if (rc) return 1;

    printf("[procd-unit] ALL PASS\n");
    while (1) seL4_Yield();
}
