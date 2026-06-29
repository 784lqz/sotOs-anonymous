/* Host test: cc -I include src/test/bytepipe_frame_unit/bytepipe_frame_unit.c -o /tmp/bpf && /tmp/bpf */
#include <sotnet/bytepipe_frame.h>
#include <stdio.h>
#include <assert.h>
int main(void) {
    static bytepipe_ring_t ring;
    bytepipe_producer_init(&ring);
    uint32_t rd = 0;
    bytepipe_frame_hdr_t h; uint8_t buf[256];
    /* interleave two conns */
    assert(bytepipe_push_frame(&ring, 7, 80, (const uint8_t*)"AAAA", 4) == 12);
    assert(bytepipe_push_frame(&ring, 9, 22, (const uint8_t*)"BBBBBB", 6) == 14);
    assert(bytepipe_pull_frame(&ring, &rd, &h, buf, sizeof buf) == 1);
    assert(h.conn_id == 7 && h.local_port == 80 && h.len == 4 && memcmp(buf,"AAAA",4)==0);
    assert(bytepipe_pull_frame(&ring, &rd, &h, buf, sizeof buf) == 1);
    assert(h.conn_id == 9 && h.local_port == 22 && h.len == 6 && memcmp(buf,"BBBBBB",6)==0);
    assert(bytepipe_pull_frame(&ring, &rd, &h, buf, sizeof buf) == 0);   /* empty */
    /* partial frame: push a header claiming 100 payload, expect 0 until complete */
    uint32_t w_save = ring.w;
    bytepipe_frame_hdr_t ph = { 5, 80, 100 };
    bytepipe_push(&ring, (const uint8_t*)&ph, BYTEPIPE_FRAME_HDR_SZ);    /* header only */
    assert(bytepipe_pull_frame(&ring, &rd, &h, buf, sizeof buf) == 0);   /* incomplete */
    assert(rd == w_save);                               /* cursor NOT advanced */
    fprintf(stderr, "bytepipe_frame_unit OK\n");
    return 0;
}
