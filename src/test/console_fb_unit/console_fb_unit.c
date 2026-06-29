/* Host test for the pure console_fb renderer (scale-tolerant).
 *   cc -DCONSOLE_FB_HOST_TEST -I include src/test/console_fb_unit/console_fb_unit.c \
 *      src/orch/console_fb.c -o /tmp/cfb && /tmp/cfb
 * seL4/gpu calls are #ifdef-guarded out; the test installs a synthetic fb. The font
 * is scaled (CONSOLE_SCALE in console_fb.c), so checks scan whole cells rather
 * than fixed 1:1 pixels. A cell is at most 8*4=32 px; W/H are sized to hold 2 cells. */
#include <orch/console_fb.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void console_fb_test_install(uint8_t *fb, int w, int h, int stride);
static int fails = 0;
#define CHECK(c) do{ if(!(c)){printf("FAIL: %s (line %d)\n",#c,__LINE__);fails++;} }while(0)

/* count foreground (non-black) pixels in the rect [x0,x0+w) x [y0,y0+h). */
static int fg_in(const uint8_t *fb, int stride, int W, int H, int x0, int y0, int w, int h) {
    int n = 0;
    for (int y = y0; y < y0 + h && y < H; ++y)
        for (int x = x0; x < x0 + w && x < W; ++x) {
            const uint8_t *p = fb + (size_t)y*stride + (size_t)x*4;
            if (p[0] || p[1] || p[2]) ++n;
        }
    return n;
}

int main(void) {
    int W = 96, H = 48, stride = W*4;   /* >= 2 cells wide (max cell 32px), 1+ rows tall */
    uint8_t *fb = calloc((size_t)stride*H, 1);
    console_fb_test_install(fb, W, H, stride);
    console_fb_init();
    /* fresh screen: cell 0 is all black. */
    CHECK(fg_in(fb, stride, W, H, 0, 0, 32, 32) == 0);
    console_fb_putc('A');
    /* 'A' lights some foreground pixels in cell 0 (whatever the scale). */
    CHECK(fg_in(fb, stride, W, H, 0, 0, 32, 32) > 0);
    console_fb_putc('B');
    /* cursor advanced → cell 1 (x>=32px at the largest scale, but a small scale
     * puts it lower; scan from one min-cell-width on) has foreground too. */
    CHECK(fg_in(fb, stride, W, H, 24, 0, 40, 32) > 0);

    /* --- REGRESSION · backspace redraw (busybox emits ESC[J = erase cursor→end).
     * The bug: console_fb treated EVERY 'J' as clear-whole-screen + home, so a
     * backspace redraw wiped the screen.  ESC[J (param 0) must erase only from the
     * cursor onward — content BEFORE the cursor stays. */
    console_fb_init();                                   /* fresh black screen */
    console_fb_putc('A');                                /* 'A' at cell(0,0); cursor → col 1 */
    CHECK(fg_in(fb, stride, W, H, 0, 0, 16, 32) > 0);    /* 'A' present */
    for (const char *p = "\x1b[J"; *p; ++p) console_fb_putc(*p);   /* ESC[J · erase cursor→end */
    CHECK(fg_in(fb, stride, W, H, 0, 0, 16, 32) > 0);    /* 'A' (before cursor) MUST survive ← the fix */

    /* ESC[2J still clears the WHOLE screen (the startup-clear path must keep working). */
    console_fb_putc('X');
    for (const char *p = "\x1b[2J"; *p; ++p) console_fb_putc(*p);  /* ESC[2J · erase all */
    CHECK(fg_in(fb, stride, W, H, 0, 0, W, H) == 0);     /* everything cleared */

    if (!fails) printf("console_fb_unit: ALL PASS\n");
    return fails ? 1 : 0;
}
