/* Host unit · decode SSH pty-req + window-change winsize fields.
 * pty-req  (RFC 4254 §6.2):  string TERM, u32 cols, u32 rows, u32 wpx, u32 hpx, string modes
 * window-change (§6.7):       u32 cols, u32 rows, u32 wpx, u32 hpx   (after the req-type string) */
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "lucas/tty_session.h"

static void be32(uint8_t *p, uint32_t v){ p[0]=v>>24; p[1]=v>>16; p[2]=v>>8; p[3]=v; }

int main(void) {
    /* pty-req payload: string "xterm"(len5) | cols=120 | rows=40 | wpx=0 | hpx=0 | modes(len0) */
    uint8_t buf[64]; int o=0;
    be32(buf+o,5); o+=4; memcpy(buf+o,"xterm",5); o+=5;
    be32(buf+o,120); o+=4; be32(buf+o,40); o+=4; be32(buf+o,0); o+=4; be32(buf+o,0); o+=4;
    be32(buf+o,0); o+=4;
    uint16_t cols=0, rows=0;
    assert(lucas_tty_ptyreq_winsize(buf, o, &cols, &rows) == 0);
    assert(cols==120 && rows==40);

    /* window-change payload: cols=200 | rows=50 | wpx=0 | hpx=0 */
    uint8_t wc[16]; be32(wc,200); be32(wc+4,50); be32(wc+8,0); be32(wc+12,0);
    cols=rows=0;
    assert(lucas_tty_winch_winsize(wc, 16, &cols, &rows) == 0);
    assert(cols==200 && rows==50);

    /* truncated → error, no out-of-bounds */
    assert(lucas_tty_winch_winsize(wc, 4, &cols, &rows) != 0);
    printf("[tty-session-unit] ALL PASS\n");
    return 0;
}
