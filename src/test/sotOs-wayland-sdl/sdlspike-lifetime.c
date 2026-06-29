/* sotOs Wayland-M4 gate · wl_shm pool lifetime/refcount.
 * An unmodified SDL2 app exercises window create/destroy/resize so the 4 global
 * orch shm pools must be FREED, not leaked. Uses SMALL windows (few 4K frames
 * per pool) so the per-frame alloc/free stays fast — the window size is
 * irrelevant to testing pool lifetime; the create/destroy/resize churn is.
 *   Phase 1: 6× create-window → framebuffer → render → destroy   (>4 cycles)
 *   Phase 2: 1 window, resize 6× (each recreates the framebuffer) (>4 resizes)
 *   Phase 3: 2 windows simultaneously, then destroy both
 *   Phase 4: recreate after destroy (proves slots were reclaimed)
 *   Phase 5: exit with a live window+pool (teardown sweep must free it)
 * If pools aren't freed, the 5th allocation exhausts the 4 slots → NULL surface. */
#include <SDL2/SDL.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SAY(s) write(1, s, sizeof(s)-1)
static void sayz(const char *s){ if(s) write(1, s, strlen(s)); }

static SDL_Surface *paint(SDL_Window *w, int tone) {
    SDL_Surface *s = SDL_GetWindowSurface(w);
    if (!s) return NULL;
    SDL_FillRect(s, NULL, SDL_MapRGB(s->format, 0x7E, tone & 0xFF, 0x21));
    SDL_UpdateWindowSurface(w);
    SDL_PumpEvents();
    return s;
}

int main(void) {
    setenv("XDG_RUNTIME_DIR", "/run/user/1000", 1);
    setenv("WAYLAND_DISPLAY", "wayland-0", 1);
    setenv("SDL_VIDEODRIVER", "wayland", 1);
    setenv("SDL_FRAMEBUFFER_ACCELERATION", "0", 1);
    SAY("[sdlspike] M4 wl_shm pool lifetime gate · start\n");

    if (SDL_Init(SDL_INIT_VIDEO) != 0) {
        SAY("[sdlspike] SDL_Init FAIL: "); sayz(SDL_GetError()); SAY("\n"); return 1;
    }
    SAY("[sdlspike] SDL_Init(VIDEO) OK\n");

    /* Phase 1 · 6 create/destroy cycles (only 1 pool live at a time IF freed). */
    for (int i = 0; i < 5; ++i) {   /* >4 */
        SDL_Window *w = SDL_CreateWindow("sotos-cycle", SDL_WINDOWPOS_UNDEFINED,
                                         SDL_WINDOWPOS_UNDEFINED, 64, 64, 0);
        if (!w) { SAY("[sdlspike] cycle CreateWindow FAIL: "); sayz(SDL_GetError()); SAY("\n"); return 1; }
        if (!paint(w, i * 30)) {
            SAY("[sdlspike] FAIL cycle pool exhausted: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1;
        }
        SDL_DestroyWindow(w);
    }
    SAY("[sdlspike] phase1: 5 create/destroy cycles OK (pools reclaimed)\n");

    /* Phase 2 · resize 6× (each SDL_GetWindowSurface recreates the framebuffer). */
    SDL_Window *wr = SDL_CreateWindow("sotos-resize", SDL_WINDOWPOS_UNDEFINED,
                                      SDL_WINDOWPOS_UNDEFINED, 48, 48, SDL_WINDOW_RESIZABLE);
    if (!wr || !paint(wr, 0)) { SAY("[sdlspike] resize base FAIL\n"); SDL_Quit(); return 1; }
    for (int r = 0; r < 5; ++r) {   /* >4 */
        SDL_SetWindowSize(wr, 48 + r * 16, 48 + r * 16);
        if (!paint(wr, r * 20)) {
            SAY("[sdlspike] FAIL resize pool exhausted: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1;
        }
    }
    SDL_DestroyWindow(wr);
    SAY("[sdlspike] phase2: 5 resizes OK (framebuffer recreated, pools reclaimed)\n");

    /* Phase 3 · two windows simultaneously (2 pools live at once). */
    SDL_Window *w1 = SDL_CreateWindow("sotos-two-a", SDL_WINDOWPOS_UNDEFINED,
                                      SDL_WINDOWPOS_UNDEFINED, 64, 64, 0);
    SDL_Window *w2 = SDL_CreateWindow("sotos-two-b", SDL_WINDOWPOS_UNDEFINED,
                                      SDL_WINDOWPOS_UNDEFINED, 80, 80, 0);
    if (!w1 || !w2 || !paint(w1, 90) || !paint(w2, 160)) {
        SAY("[sdlspike] FAIL two windows: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1;
    }
    SAY("[sdlspike] phase3: 2 simultaneous windows OK\n");
    SDL_DestroyWindow(w1);
    SDL_DestroyWindow(w2);

    /* Phase 4 · recreate after destroy (slots must have been reclaimed). */
    SDL_Window *w3 = SDL_CreateWindow("sotos-recreate", SDL_WINDOWPOS_UNDEFINED,
                                      SDL_WINDOWPOS_UNDEFINED, 72, 72, 0);
    if (!w3 || !paint(w3, 120)) {
        SAY("[sdlspike] FAIL recreate after destroy: "); sayz(SDL_GetError()); SAY("\n"); SDL_Quit(); return 1;
    }
    SAY("[sdlspike] phase4: recreate after destroy OK\n");
    /* Phase 5 · exit with w3 + its pool STILL LIVE (no SDL_Quit, no destroy):
     * the sotbox teardown sweep (orch_shm_pool_free_owner) must reclaim it. */
    SAY("[sdlspike] M4 GATE GREEN · exiting with 1 live window+pool (teardown must free)\n");
    return 0;
}
