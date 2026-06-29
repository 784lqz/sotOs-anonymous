#include <orch/console_fb.h>
#include "console_font8x8.h"   /* char font8x8_basic[128][8] (public domain) */
#include <stdint.h>
#include <string.h>

#ifndef CONSOLE_FB_HOST_TEST
#include <orch/virtio_gpu.h>
#else
static uint8_t *g_test_fb; static int g_test_w,g_test_h,g_test_stride;
uint8_t *gpu_fb(int*w,int*h,int*s){ if(w)*w=g_test_w; if(h)*h=g_test_h; if(s)*s=g_test_stride; return g_test_fb; }
void gpu_flush(int x,int y,int w,int h){ (void)x;(void)y;(void)w;(void)h; }
void console_fb_test_install(uint8_t*fb,int w,int h,int stride){ g_test_fb=fb; g_test_w=w; g_test_h=h; g_test_stride=stride; }
#endif

/* Font scale: each 8x8 glyph pixel becomes a CONSOLE_SCALE x CONSOLE_SCALE block.
 * 1x (8px) was unreadably tiny on 1280x800; 3x (24px) → ~53x33 chars was chunky;
 * 2x → 16px cells → ~80x50 chars (a standard terminal grid), more text on screen
 * and a tidier backdrop under the composited Wayland window. */
#define CONSOLE_SCALE 2
#define CELL (8 * CONSOLE_SCALE)
static uint8_t *g_fb; static int g_w, g_h, g_stride;
static int g_cols, g_rows, g_cx, g_cy;
static uint32_t g_fg = 0x00C0C0C0, g_bg = 0x00000000;  /* BGRX light grey on black */
static int g_in;
static int g_esc; static int g_params[8], g_nparam;
/* v2.9 · batch flushing: console_fb_putc gpu_flushes per char (a virtio-gpu
 * round-trip each) — fine for slow console output, but the deception-monitor
 * feed renders whole lines and the per-char flush stalls orch (it starved the
 * SSH attacker's network → `watch` made demos fail).  console_fb_puts() defers
 * the per-char flushes and does ONE flush per line. */
static int g_defer_flush;
static void fbflush(int x, int y, int w, int h) { if (!g_defer_flush) gpu_flush(x, y, w, h); }

static void put_px(int x, int y, uint32_t bgrx) {
    if ((unsigned)x >= (unsigned)g_w || (unsigned)y >= (unsigned)g_h) return;
    uint8_t *p = g_fb + (size_t)y*g_stride + (size_t)x*4;
    p[0]=(uint8_t)bgrx; p[1]=(uint8_t)(bgrx>>8); p[2]=(uint8_t)(bgrx>>16); p[3]=0xFF;
}
static void draw_glyph(int cx, int cy, unsigned char c) {
    const char *g = (c < 128) ? font8x8_basic[c] : font8x8_basic[(int)'?'];
    for (int row=0; row<8; ++row)
        for (int col=0; col<8; ++col) {
            uint32_t v = ((g[row]>>col)&1) ? g_fg : g_bg;
            int px = cx*CELL + col*CONSOLE_SCALE, py = cy*CELL + row*CONSOLE_SCALE;
            for (int dy=0; dy<CONSOLE_SCALE; ++dy)
                for (int dx=0; dx<CONSOLE_SCALE; ++dx)
                    put_px(px+dx, py+dy, v);
        }
}
static void clear_all(void){ for (int y=0;y<g_h;++y) for (int x=0;x<g_w;++x) put_px(x,y,g_bg); }
/* Erase the cell rectangle [cx0,cx1) x [cy0,cy1) to the background (clamped).
 * Backs the parameter-aware ESC[J / ESC[K (erase-in-display / erase-in-line). */
static void fill_cells(int cx0,int cy0,int cx1,int cy1){
    if(cx0<0)cx0=0; if(cy0<0)cy0=0;
    if(cx1>g_cols)cx1=g_cols; if(cy1>g_rows)cy1=g_rows;
    for(int y=cy0*CELL; y<cy1*CELL && y<g_h; ++y)
        for(int x=cx0*CELL; x<cx1*CELL && x<g_w; ++x)
            put_px(x,y,g_bg);
}
static void scroll_up(void) {
    memmove(g_fb, g_fb + (size_t)CELL*g_stride, (size_t)(g_h-CELL)*g_stride);
    for (int y=g_h-CELL; y<g_h; ++y) for (int x=0;x<g_w;++x) put_px(x,y,g_bg);
    fbflush(0,0,g_w,g_h);
}
static void newline(void){ g_cx=0; g_cy++; if (g_cy>=g_rows){ scroll_up(); g_cy=g_rows-1; } }

void console_fb_init(void) {
    int w,h,s; uint8_t *fb = gpu_fb(&w,&h,&s);
    if (!fb) { g_fb=0; return; }
    g_fb=fb; g_w=w; g_h=h; g_stride=s;
    g_cols=w/CELL; g_rows=h/CELL; g_cx=0; g_cy=0; g_esc=0; g_nparam=0;
    g_fg=0x00C0C0C0; g_bg=0x00000000;
    clear_all(); gpu_flush(0,0,w,h);
}
int console_fb_active(void){ return g_fb != 0; }

static uint32_t ansi_fg(int idx) {
    static const uint32_t rgb[8] = {0x000000,0xC00000,0x00C000,0xC0C000,
                                    0x0000C0,0xC000C0,0x00C0C0,0xC0C0C0};
    uint32_t v = rgb[idx & 7];
    uint8_t r=(v>>16)&0xFF, gg=(v>>8)&0xFF, b=v&0xFF;
    return (uint32_t)b | ((uint32_t)gg<<8) | ((uint32_t)r<<16);   /* -> BGRX */
}

void console_fb_putc(char ch) {
    if (!g_fb) return;
#ifndef CONSOLE_FB_HOST_TEST
    if (g_in) return;            /* gpu error -> printf -> serial_putc recursion */
#endif
    g_in = 1;
    unsigned char c = (unsigned char)ch;
    if (g_esc == 1) { g_esc = (c=='[')?2:0; if(g_esc==2){g_nparam=0;g_params[0]=0;} g_in=0; return; }
    if (g_esc == 2) {
        if (c>='0'&&c<='9'){ g_params[g_nparam]=g_params[g_nparam]*10+(c-'0'); g_in=0; return; }
        if (c==';'){ if(g_nparam<7){g_nparam++;g_params[g_nparam]=0;} g_in=0; return; }
        if (c=='m'){ for(int i=0;i<=g_nparam;++i){int p=g_params[i];
                       if(p==0)g_fg=0x00C0C0C0; else if(p>=30&&p<=37)g_fg=ansi_fg(p-30);
                       else if(p>=90&&p<=97)g_fg=ansi_fg(p-90);} }
        else if (c=='J'){ int p=g_params[0];   /* erase in display · parameter-AWARE */
            if(p==2){ clear_all(); g_cx=0; g_cy=0; }                 /* 2: whole screen (+home · the startup clear) */
            else if(p==1){ fill_cells(0,0,g_cols,g_cy); fill_cells(0,g_cy,g_cx+1,g_cy+1); }  /* 1: start->cursor */
            else { fill_cells(g_cx,g_cy,g_cols,g_cy+1); fill_cells(0,g_cy+1,g_cols,g_rows); } /* 0 (busybox redraw): cursor->end · cursor UNCHANGED */
            fbflush(0,0,g_w,g_h); }
        else if (c=='K'){ int p=g_params[0];   /* erase in line */
            if(p==2) fill_cells(0,g_cy,g_cols,g_cy+1);               /* whole line */
            else if(p==1) fill_cells(0,g_cy,g_cx+1,g_cy+1);          /* start->cursor */
            else fill_cells(g_cx,g_cy,g_cols,g_cy+1);                /* cursor->eol (default) */
            fbflush(0,g_cy*CELL,g_w,CELL); }
        else if (c=='A'){ int n=g_params[0]?g_params[0]:1; g_cy-=n; if(g_cy<0)g_cy=0; }       /* cursor up    */
        else if (c=='B'){ int n=g_params[0]?g_params[0]:1; g_cy+=n; if(g_cy>=g_rows)g_cy=g_rows-1; } /* cursor down  */
        else if (c=='C'){ int n=g_params[0]?g_params[0]:1; g_cx+=n; if(g_cx>=g_cols)g_cx=g_cols-1; } /* cursor right */
        else if (c=='D'){ int n=g_params[0]?g_params[0]:1; g_cx-=n; if(g_cx<0)g_cx=0; }       /* cursor left  */
        else if (c=='H'){ g_cy=g_params[0]?g_params[0]-1:0; g_cx=(g_nparam>=1&&g_params[1])?g_params[1]-1:0;
                          if(g_cy>=g_rows)g_cy=g_rows-1; if(g_cx>=g_cols)g_cx=g_cols-1; }
        g_esc=0; g_in=0; return;
    }
    switch (c) {
        case 0x1b: g_esc=1; break;
        case '\n': newline(); fbflush(0,(g_cy>0?g_cy-1:0)*CELL,g_w,2*CELL); break;
        case '\r': g_cx=0; break;
        case '\b': if(g_cx>0)g_cx--; break;
        case '\t': g_cx=(g_cx+8)&~7; if(g_cx>=g_cols)newline(); break;
        default:
            if (c>=0x20 && c<0x7f) {
                draw_glyph(g_cx,g_cy,c);
                fbflush(g_cx*CELL,g_cy*CELL,CELL,CELL);
                g_cx++; if(g_cx>=g_cols) newline();
            }
            break;
    }
    g_in = 0;
}

/* v2.9 · render a whole string with a SINGLE gpu_flush (one virtio-gpu round-trip
 * for the line, not one per char) — used by the deception-monitor feed so heavy
 * rendering doesn't stall orch's network servicing.  Pass the trailing '\n'. */
void console_fb_puts(const char *s) {
    if (!g_fb || !s) return;
    g_defer_flush = 1;
    for (; *s; ++s) console_fb_putc(*s);
    g_defer_flush = 0;
    gpu_flush(0, 0, g_w, g_h);   /* one flush for the whole line */
}
