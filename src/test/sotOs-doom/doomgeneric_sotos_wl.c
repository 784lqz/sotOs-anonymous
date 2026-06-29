/* sotOs · v2.3-M5 · doomgeneric over REAL SDL2, OVER REAL WAYLAND (wl_shm,
 * NO EGL).  The real engine renders into the SDL2 SOFTWARE renderer, whose
 * window framebuffer is a wl_shm pool/buffer on the honest compositor (the
 * patches/sdl2/0002 Wayland_CreateWindowFramebuffer path, reached because the
 * SW renderer calls SDL_GetWindowSurface).  Each SDL_RenderPresent does a real
 * wl_surface attach/damage/commit → the compositor sees genuine Doom pixels.
 *
 * Differs from doomgeneric_sotos_sdl.c (the headless dummy-driver de-risk) only
 * in: SDL_VIDEODRIVER=wayland + SDL_FRAMEBUFFER_ACCELERATION=0, and it does NOT
 * write /dev/fb0 — the wl_shm commit IS the present here.  Built DYNAMICALLY
 * against the committed patched SDL2 fixture (src/test/sotOs-wayland-sdl/lib). */
#include "doomgeneric.h"
#define SDL_MAIN_HANDLED   /* we provide our own main · don't let SDL #define main→SDL_main */
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static SDL_Window   *g_win = NULL;
static SDL_Renderer *g_ren = NULL;
static SDL_Texture  *g_tex = NULL;
#define DOOM_MAX_FRAMES 200
static int g_frames = 0;

/* scripted ENTERs → title→menu→E1M1 (same cadence as the non-wl shim) */
static int g_keyq = 0;
static const struct { int frame; int pressed; unsigned char key; } g_keyseq[] = {
    { 30,1,13},{ 31,0,13}, { 55,1,13},{ 56,0,13}, { 80,1,13},{ 81,0,13},
    {105,1,13},{106,0,13}, {130,1,13},{131,0,13}, {155,1,13},{156,0,13},
};

void DG_Init(void) {
    SDL_SetMainReady();                              /* required when SDL_MAIN_HANDLED */
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
    setenv("WAYLAND_DISPLAY", "wayland-0", 1);
    setenv("SDL_VIDEODRIVER", "wayland", 1);         /* REAL wayland, not dummy */
    setenv("SDL_FRAMEBUFFER_ACCELERATION", "0", 1);  /* → wl_shm driver framebuffer (no EGL) */
    setenv("SDL_AUDIODRIVER", "dummy", 1);
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "[doom-wl] SDL_Init FAILED: %s\n", SDL_GetError());
    } else {
        printf("[doom-wl] SDL_Init OK · video driver=%s\n", SDL_GetCurrentVideoDriver());
    }
    g_win = SDL_CreateWindow("DOOM", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                             DOOMGENERIC_RESX, DOOMGENERIC_RESY, SDL_WINDOW_SHOWN);
    g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_SOFTWARE);  /* SOFTWARE → wl_shm */
    g_tex = SDL_CreateTexture(g_ren, SDL_PIXELFORMAT_ARGB8888,
                              SDL_TEXTUREACCESS_STREAMING, DOOMGENERIC_RESX, DOOMGENERIC_RESY);
    printf("[doom-wl] window=%p renderer=%p texture=%p (%dx%d)\n",
           (void*)g_win, (void*)g_ren, (void*)g_tex, DOOMGENERIC_RESX, DOOMGENERIC_RESY);
}

void DG_DrawFrame(void) {
    if (g_tex && g_ren) {                       /* the REAL SDL2 software render path */
        SDL_UpdateTexture(g_tex, NULL, DG_ScreenBuffer, DOOMGENERIC_RESX * sizeof(uint32_t));
        SDL_RenderClear(g_ren);
        SDL_RenderCopy(g_ren, g_tex, NULL, NULL);
        SDL_RenderPresent(g_ren);               /* → SDL_UpdateWindowSurface → wl_shm commit */
    }
}

int DG_GetKey(int* pressed, unsigned char* key) {
    SDL_Event e; while (SDL_PollEvent(&e)) { /* drain SDL events (the real path) */ }
    int n = (int)(sizeof(g_keyseq) / sizeof(g_keyseq[0]));
    if (g_keyq < n && g_keyseq[g_keyq].frame <= g_frames) {
        *pressed = g_keyseq[g_keyq].pressed; *key = g_keyseq[g_keyq].key; g_keyq++; return 1;
    }
    return 0;
}

void DG_SetWindowTitle(const char* t) { if (g_win) SDL_SetWindowTitle(g_win, t); }
uint32_t DG_GetTicksMs(void) { return SDL_GetTicks(); }
void DG_SleepMs(uint32_t ms) { SDL_Delay(ms); }

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    char* av[] = { "doom", "-iwad", "/doom1.wad", NULL };
    doomgeneric_Create(3, av);
    for (g_frames = 0; g_frames < DOOM_MAX_FRAMES; ++g_frames) doomgeneric_Tick();
    printf("[doom-wl] %d frames ticked over real SDL2/wl_shm · exiting clean\n", g_frames);
    SDL_Quit();
    return 0;
}
