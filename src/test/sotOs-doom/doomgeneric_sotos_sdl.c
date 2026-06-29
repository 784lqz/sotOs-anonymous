/* sotOs platform shim for doomgeneric OVER REAL SDL2 (Phase 2 de-risk · headless).
 * Exercises the actual SDL2 code path on sotOs — SDL_Init / SDL_CreateWindow /
 * SDL_CreateRenderer(SOFTWARE) / SDL_CreateTexture / SDL_RenderCopy /
 * SDL_RenderPresent / SDL_PollEvent — with the dummy video driver, then ALSO
 * writes the rendered frame to /dev/fb0 for the existing present-handler capture.
 * If SDL2 runs here, Chocolate Doom (also SDL2) is "just" a bigger build. */
#include "doomgeneric.h"
#define SDL_MAIN_HANDLED   /* we provide our own main · don't let SDL #define main→SDL_main */
#include <SDL.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>

static int g_fb = -1;
static SDL_Window   *g_win = NULL;
static SDL_Renderer *g_ren = NULL;
static SDL_Texture  *g_tex = NULL;
#define DOOM_MAX_FRAMES 400
static int g_frames = 0;

/* scripted ENTERs → title→menu→E1M1 (same as the non-SDL shim) */
static int g_keyq = 0;
static const struct { int frame; int pressed; unsigned char key; } g_keyseq[] = {
    { 30,1,13},{ 31,0,13}, { 55,1,13},{ 56,0,13}, { 80,1,13},{ 81,0,13},
    {105,1,13},{106,0,13}, {130,1,13},{131,0,13}, {155,1,13},{156,0,13},
};

void DG_Init(void) {
    SDL_SetMainReady();                       /* required when SDL_MAIN_HANDLED */
    setenv("SDL_VIDEODRIVER", "dummy", 1);   /* headless · no X11/Wayland/GL */
    setenv("SDL_AUDIODRIVER", "dummy", 1);
    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        fprintf(stderr, "[doom-sdl] SDL_Init FAILED: %s\n", SDL_GetError());
    } else {
        printf("[doom-sdl] SDL_Init OK · video driver=%s\n", SDL_GetCurrentVideoDriver());
    }
    g_win = SDL_CreateWindow("DOOM", SDL_WINDOWPOS_UNDEFINED, SDL_WINDOWPOS_UNDEFINED,
                             DOOMGENERIC_RESX, DOOMGENERIC_RESY, SDL_WINDOW_SHOWN);
    g_ren = SDL_CreateRenderer(g_win, -1, SDL_RENDERER_SOFTWARE);
    g_tex = SDL_CreateTexture(g_ren, SDL_PIXELFORMAT_ARGB8888,
                              SDL_TEXTUREACCESS_STREAMING, DOOMGENERIC_RESX, DOOMGENERIC_RESY);
    printf("[doom-sdl] window=%p renderer=%p texture=%p\n",
           (void*)g_win, (void*)g_ren, (void*)g_tex);
    g_fb = open("/dev/fb0", O_WRONLY);
}

void DG_DrawFrame(void) {
    if (g_tex && g_ren) {                       /* the REAL SDL2 render path */
        SDL_UpdateTexture(g_tex, NULL, DG_ScreenBuffer, DOOMGENERIC_RESX * sizeof(uint32_t));
        SDL_RenderClear(g_ren);
        SDL_RenderCopy(g_ren, g_tex, NULL, NULL);
        SDL_RenderPresent(g_ren);
    }
    if (g_fb >= 0)                              /* capture for the /dev/fb0 handler */
        write(g_fb, DG_ScreenBuffer, (size_t)DOOMGENERIC_RESX * DOOMGENERIC_RESY * 4);
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
    printf("[doom-sdl] %d frames ticked (over real SDL2) · exiting\n", g_frames);
    return 0;
}
