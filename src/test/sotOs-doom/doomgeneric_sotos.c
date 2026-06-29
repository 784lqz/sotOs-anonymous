/* sotOs platform shim for doomgeneric.
 * Present = write the ARGB frame to /dev/fb0 (LUCAS hashes/dumps + blits to the
 * virtio-gpu plane). Input: /dev/doomkbd (raw virtio-keyboard events) when a
 * keyboard is present (just run-interactive) → real play; else a scripted
 * ENTER sequence + a frame cap (headless gates). */
#include "doomgeneric.h"
#include "d_event.h"   /* D_PostEvent · ev_mouse (mouse-look) */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/time.h>

static int g_fb = -1;
static int g_kbd = -1;                 /* /dev/doomkbd · >=0 ⇒ interactive */
static int g_mouse = -1;               /* /dev/doommouse · >=0 ⇒ mouse-look */
#define MOUSE_DIV 16                   /* tablet units → doom turn counts */
#define DOOM_MAX_FRAMES        400     /* headless cap (gates) */
#define DOOM_INTERACTIVE_CAP   200000  /* interactive safety cap (~play until quit) */
static int g_frames = 0;

/* headless scripted input (title→menu→E1M1) · KEY_ENTER=13 */
static int g_keyq = 0;
static const struct { int frame; int pressed; unsigned char key; } g_keyseq[] = {
    { 30,1,13},{ 31,0,13}, { 55,1,13},{ 56,0,13}, { 80,1,13},{ 81,0,13},
    {105,1,13},{106,0,13}, {130,1,13},{131,0,13}, {155,1,13},{156,0,13},
};

/* doomgeneric key constants (doomkeys.h) */
#define DK_RIGHT 0xae
#define DK_LEFT  0xac
#define DK_UP    0xad
#define DK_DOWN  0xaf
#define DK_ESC   27
#define DK_ENTER 13
#define DK_TAB   9
#define DK_FIRE  0x9d  /* KEY_RCTRL */
#define DK_USE   0x20  /* space */
#define DK_RSHIFT 0xb6 /* (0x80+0x36) run */
#define DK_RALT   0xb8 /* (0x80+0x38) strafe */
#define DK_BS    0x7f

/* Linux input keycode → doomgeneric key (0 = ignore). */
static int kc2doom(unsigned char kc) {
    switch (kc) {
        case 103: return DK_UP;    case 108: return DK_DOWN;
        case 105: return DK_LEFT;  case 106: return DK_RIGHT;
        case 28:  return DK_ENTER; case 1:   return DK_ESC;
        case 57:  return DK_USE;   case 15:  return DK_TAB;
        case 29: case 97: return DK_FIRE;    /* ctrl = fire */
        case 56: case 100: return DK_RALT;   /* alt = strafe */
        case 42: case 54: return DK_RSHIFT;  /* shift = run */
        case 14: return DK_BS;
    }
    if (kc >= 2 && kc <= 11) { static const char d[] = "1234567890"; return d[kc-2]; }
    if (kc >= 16 && kc <= 25) { static const char r[] = "qwertyuiop"; return r[kc-16]; }
    if (kc >= 30 && kc <= 38) { static const char r[] = "asdfghjkl";  return r[kc-30]; }
    if (kc >= 44 && kc <= 50) { static const char r[] = "zxcvbnm";    return r[kc-44]; }
    return 0;
}

void DG_Init(void) {
    g_fb = open("/dev/fb0", O_WRONLY);
    if (g_fb < 0) fprintf(stderr, "[doom-shim] /dev/fb0 open failed\n");
    g_kbd = open("/dev/doomkbd", O_RDONLY);   /* >=0 only when a keyboard is present */
    g_mouse = open("/dev/doommouse", O_RDONLY); /* >=0 only when a tablet is present */
    fprintf(stderr, "[doom-shim] input=%s%s\n",
            g_kbd >= 0 ? "keyboard (/dev/doomkbd)" : "scripted",
            g_mouse >= 0 ? " + mouse (/dev/doommouse)" : "");
}

/* Post a Doom mouse-look event from the tablet (relative turn + fire button).
 * Called each tick from DG_GetKey. */
static void drain_mouse(void) {
    if (g_mouse < 0) return;
    unsigned char mb[5];
    if (read(g_mouse, mb, 5) < 5) return;
    int dx  = (short)(mb[0] | (mb[1] << 8));
    int btn = mb[4];
    static int last_btn = 0;
    if (dx == 0 && btn == 0 && last_btn == 0) return;
    last_btn = btn;
    event_t ev;
    ev.type  = ev_mouse;
    ev.data1 = (btn & 1);          /* bit0 = left = fire */
    ev.data2 = dx / MOUSE_DIV;     /* X turn */
    ev.data3 = 0;                  /* no forward/back from the mouse */
    ev.data4 = 0;
    D_PostEvent(&ev);
}
void DG_DrawFrame(void) {
    if (g_fb >= 0)
        write(g_fb, DG_ScreenBuffer, (size_t)DOOMGENERIC_RESX * DOOMGENERIC_RESY * 4);
}

int DG_GetKey(int* pressed, unsigned char* key) {
    drain_mouse();   /* post mouse-look events each poll cycle */
    if (g_kbd >= 0) {
        /* raw 2-byte {keycode,down} events from LUCAS; one doom key per call. */
        static unsigned char ev[64]; static int evn = 0, evi = 0;
        for (;;) {
            if (evi + 2 > evn) {
                int r = (int)read(g_kbd, ev, sizeof(ev));
                if (r <= 0) return 0;
                evn = r; evi = 0;
            }
            unsigned char kc = ev[evi]; int down = ev[evi+1]; evi += 2;
            int dk = kc2doom(kc);
            if (dk == 0) continue;
            *pressed = down; *key = (unsigned char)dk; return 1;
        }
    }
    int n = (int)(sizeof(g_keyseq) / sizeof(g_keyseq[0]));
    if (g_keyq < n && g_keyseq[g_keyq].frame <= g_frames) {
        *pressed = g_keyseq[g_keyq].pressed;
        *key     = g_keyseq[g_keyq].key;
        g_keyq++;
        return 1;
    }
    return 0;
}
void DG_SetWindowTitle(const char* title) { (void)title; }
uint32_t DG_GetTicksMs(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint32_t)(ts.tv_sec * 1000u + ts.tv_nsec / 1000000u);
}
void DG_SleepMs(uint32_t ms) {
    struct timespec ts = { ms / 1000, (long)(ms % 1000) * 1000000L }; nanosleep(&ts, NULL);
}
int main(int argc, char** argv) {
    (void)argc; (void)argv;
    char* av[] = { "doom", "-iwad", "/doom1.wad", NULL };
    doomgeneric_Create(3, av);   /* calls DG_Init → sets g_kbd */
    int cap = (g_kbd >= 0) ? DOOM_INTERACTIVE_CAP : DOOM_MAX_FRAMES;
    for (g_frames = 0; g_frames < cap; ++g_frames) doomgeneric_Tick();
    printf("[doom-shim] %d frames ticked · exiting\n", g_frames);
    return 0;
}
