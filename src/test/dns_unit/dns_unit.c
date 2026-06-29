/* Host unit test for the pure DNS helpers (no seL4, no net). cc -I include. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <sotguard/event.h>

uint16_t dns_query_qtype(const uint8_t *pkt, size_t len, int qname_consumed);
size_t   dns_synth_empty_noerror(const uint8_t *query, size_t qlen,
                                 uint8_t *out, size_t out_cap);

/* Stubs for seL4/sotguard/sottrace symbols pulled in by dns.c but not
 * needed for host unit testing. */
int  sotguard_emit(const sotguard_event_t *ev) { (void)ev; return 0; }
void trace_emit_dns(uint32_t pid, const char *d, uint32_t ip)
    { (void)pid; (void)d; (void)ip; }

static const uint8_t qA[] = {
    0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
    7,'e','x','a','m','p','l','e', 3,'c','o','m', 0,
    0x00,0x01, 0x00,0x01
};
static const uint8_t qAAAA[] = {
    0x12,0x34, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
    7,'e','x','a','m','p','l','e', 3,'c','o','m', 0,
    0x00,0x1c, 0x00,0x01
};

int main(void) {
    int consumed = 13;  /* "7example3com0" */
    assert(dns_query_qtype(qA,    sizeof qA,    consumed) == 0x0001);
    assert(dns_query_qtype(qAAAA, sizeof qAAAA, consumed) == 0x001c);
    assert(dns_query_qtype(qA, sizeof qA, 9999) == 0);

    uint8_t out[512];
    size_t n = dns_synth_empty_noerror(qAAAA, sizeof qAAAA, out, sizeof out);
    assert(n == sizeof qAAAA);
    assert(out[0] == 0x12 && out[1] == 0x34);
    assert((out[2] & 0x80) != 0);
    assert((out[3] & 0x0f) == 0x00);
    assert(out[6] == 0 && out[7] == 0);
    assert(out[4] == 0 && out[5] == 1);
    assert(memcmp(out + 12, qAAAA + 12, sizeof qAAAA - 12) == 0);

    /* qlen > out_cap → 0 (bounds error path). */
    assert(dns_synth_empty_noerror(qAAAA, sizeof qAAAA, out, 4) == 0);

    printf("dns_unit: ALL PASS\n");
    return 0;
}
