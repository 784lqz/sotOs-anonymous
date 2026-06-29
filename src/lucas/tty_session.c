#include "lucas/tty_session.h"
static int rd_u32(const uint8_t *p, size_t len, size_t *o, uint32_t *v) {
    if (*o + 4 > len) return -1;
    *v = ((uint32_t)p[*o]<<24)|((uint32_t)p[*o+1]<<16)|((uint32_t)p[*o+2]<<8)|p[*o+3];
    *o += 4; return 0;
}
int lucas_tty_ptyreq_winsize(const uint8_t *p, size_t len, uint16_t *cols, uint16_t *rows) {
    size_t o = 0; uint32_t slen, c, r;
    if (rd_u32(p, len, &o, &slen) != 0) return -1;       /* TERM string length */
    if (o + slen > len) return -1; o += slen;            /* skip TERM */
    if (rd_u32(p, len, &o, &c) != 0) return -1;
    if (rd_u32(p, len, &o, &r) != 0) return -1;
    *cols = (uint16_t)c; *rows = (uint16_t)r; return 0;
}
int lucas_tty_winch_winsize(const uint8_t *p, size_t len, uint16_t *cols, uint16_t *rows) {
    size_t o = 0; uint32_t c, r;
    if (rd_u32(p, len, &o, &c) != 0) return -1;
    if (rd_u32(p, len, &o, &r) != 0) return -1;
    *cols = (uint16_t)c; *rows = (uint16_t)r; return 0;
}
