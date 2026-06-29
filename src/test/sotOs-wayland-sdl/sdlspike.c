/* sotOs · SDL2-over-real-Wayland smoke gate (committed fixture, runs every
 * headless boot before the captive bbsh). An UNMODIFIED real SDL2 app does
 * SOFTWARE rendering over the honest compositor via wl_shm, NO EGL/GL:
 *   win A: SDL_CreateRenderer(SOFTWARE) → clear+present (3 frames)
 *   win B: SDL_GetWindowSurface → fill + SDL_UpdateWindowSurface (3 frames)
 * Kept fast (small windows, few frames) so it doesn't slow the boot.  The full
 * pool lifetime/refcount stress (create/destroy/resize churn) lives in the
 * on-demand sdlspike-lifetime.c (v2.3-M4 gate). */
#include <SDL2/SDL.h>
#include <string.h>
#include <unistd.h>

#define SAY(s) write(1, s, sizeof(s)-1)
static void sayz(const char *s){ if(s) write(1, s, strlen(s)); }

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
    setenv("WAYLAND_DISPLAY", "wayland-0", 1);
    setenv("SDL_VIDEODRIVER", "wayland", 1);
    setenv("SDL_FRAMEBUFFER_ACCELERATION", "0", 1);   /* → wl_shm driver framebuffer */
    SAY("[sdlspike] start · real SDL2 over wayland (software / wl_shm)\n");

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        SAY("[sdlspike] SDL_Init FAIL: "); sayz(SDL_GetError()); SAY("\n"); return 1;
    }
    SAY("[sdlspike] SDL_Init(VIDEO) OK\n");
    { const char *d = SDL_GetCurrentVideoDriver();
      SAY("[sdlspike] video driver = "); SAY(d ? d : "(null)"); SAY("\n"); }

    /* win A · SDL_RENDERER_SOFTWARE */
    SDL_Window *wA = SDL_CreateWindow("sotos-sdl-renderer", SDL_WINDOWPOS_UNDEFINED,
                                      SDL_WINDOWPOS_UNDEFINED, 96, 64, 0);
    if (!wA) { SAY("[sdlspike] CreateWindow A FAIL: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1; }
    SDL_Renderer *ren = SDL_CreateRenderer(wA, -1, SDL_RENDERER_SOFTWARE);
    if (!ren) { SAY("[sdlspike] CreateRenderer(SOFTWARE) FAIL: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1; }
    SAY("[sdlspike] CreateRenderer(SOFTWARE) OK\n");
    for (int i = 0; i < 3; ++i) {
        SDL_SetRenderDrawColor(ren, 0x7E, 0x5A, 0x21, 0xFF);
        SDL_RenderClear(ren); SDL_RenderPresent(ren); SDL_PumpEvents(); SDL_Delay(8);
    }
    SAY("[sdlspike] renderer: rendered 3 frames via wl_shm · RENDERER PATH GREEN\n");
    SDL_DestroyRenderer(ren); SDL_DestroyWindow(wA);

    /* win B · SDL_GetWindowSurface */
    SDL_Window *wB = SDL_CreateWindow("sotos-sdl-surface", SDL_WINDOWPOS_UNDEFINED,
                                      SDL_WINDOWPOS_UNDEFINED, 64, 64, 0);
    if (!wB) { SAY("[sdlspike] CreateWindow B FAIL: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1; }
    SDL_Surface *s = SDL_GetWindowSurface(wB);
    if (!s) { SAY("[sdlspike] GetWindowSurface FAIL: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1; }
    SAY("[sdlspike] GetWindowSurface OK (wl_shm framebuffer)\n");
    for (int i = 0; i < 3; ++i) {
        SDL_FillRect(s, NULL, SDL_MapRGB(s->format, 0x21, 0x5A, 0x7E));
        if (SDL_UpdateWindowSurface(wB) != 0) { SAY("[sdlspike] UpdateWindowSurface FAIL\n"); SDL_Quit(); return 1; }
        SDL_PumpEvents(); SDL_Delay(8);
    }
    SAY("[sdlspike] surface: rendered 3 frames via wl_shm · SURFACE PATH GREEN\n");
    SDL_DestroyWindow(wB);

    SDL_Quit();
    SAY("[sdlspike] quit OK · exit clean · FULL PATH GREEN\n");
    return 0;
}
