# v2.3-M3 · real SDL2 software rendering over real Wayland (no EGL)

`sdlspike.c` is an **unmodified** real SDL2 app. Against sotOs's honest Wayland
compositor it does software rendering over `wl_shm` — `SDL_RENDERER_SOFTWARE`
**and** the `SDL_GetWindowSurface` framebuffer API — with **no EGL/GL/Mesa**.

This was the v2.3-M3 milestone: SDL2's wayland backend ships no native wl_shm
software framebuffer (software surfaces route through a GL texture → EGL), so we
added one to the SDL **library** (not the app):
`patches/sdl2/0002-wayland-shm-framebuffer.patch` — a native
`Wayland_CreateWindowFramebuffer`/`Update`/`Destroy` trio (wl_shm pool + buffer,
mirroring SDL_waylandmouse.c's cursor path), registered in the wayland device.
With `SDL_FRAMEBUFFER_ACCELERATION=0`, SDL routes to that driver hook.

OS-side enablers (committed):
- `src/orch/shm_pool.h` — `ORCH_SHM_MAX_FRAMES` 16→1024 (a 64 KiB pool can't
  hold a window framebuffer; 4 MiB/pool covers up to the 1280×720 output).
- `src/orch/shm_pool.c` — per-pool guest-vaddr stride (a client with >1 live
  pool, e.g. two windows, no longer collides at `LucAs_SHM_POOL_BASE`).
- `src/wayland-compositor/main.c` — `wl_shm_pool.destroy/resize`,
  `wl_buffer.destroy`, `xdg_wm_base.destroy` no-op acks (a real toolkit destroys
  the pool right after creating its buffer; an EPROTO there errors the client's
  wl_display and hangs it).

## Committed fixtures (repo-reproducible — no /tmp)

Everything is committed and wired into the build (`src/CMakeLists.txt`):
- `lib/` — the patched SDL2 2.30.9 + its dlopen closure (libwayland-client/
  cursor/egl, libxkbcommon, libffi), staged into the sysroot `/usr/lib`.
- `sdlspike.bin` — the smoke binary, baked into the binstore.
- `share/X11/xkb/` — an EMPTY dir (`xkb_context_new` only checks it exists; the
  smoke does no keyboard input so no keymap files are needed → ~4 MB saved).
- the interpreter is the in-tree `ld-musl` (`src/test/sotOs-hello-dyn/`), which
  is byte-identical to Alpine's musl 1.2.5 (verified sha256) — no separate ld.

`sdlspike` runs every headless boot (a `demo_commands[]` entry before `bbsh`):

    just build && just run-headless          # grep the [sdlspike] ... GREEN markers

## Rebuilding the SDL2 fixture (when bumping SDL or the patches)

In `alpine:3.20`: download SDL2 2.30.9, apply `patches/sdl2/0001` (dynapi off)
+ `patches/sdl2/0002` (wl_shm fb), `cmake -DSDL_WAYLAND=ON -DSDL_X11=OFF
-DSDL_VIDEO_VULKAN=OFF`, `strip --strip-debug`; copy `libSDL2-2.0.so.0.3000.9`
→ `lib/libSDL2-2.0.so.0` + the wayland/xkb closure from the same image; compile
`sdlspike.c` against `sdl2-dev` → `sdlspike.bin`; `git add -f`.

## sdlspike-lifetime.c · the v2.3-M4 pool lifetime gate (on-demand)

The heavier create/destroy/resize/2-window/exit-with-live stress.  Compile it in
place of `sdlspike.c` (same `gcc … $(pkg-config --cflags --libs sdl2)`), drop it
in as `sdlspike.bin`, boot, and check `alloc==freed+force-free`, no exhaustion,
zero EPROTO/faults (see `[orch-shm] … freed / force-free` lines).

## Expected (verified green, zero faults)

```
[sdlspike] SDL_Init(VIDEO) OK
[sdlspike] video driver = wayland
[wl-compositor] commit surf=9 buf=15 320x240 ... px0=0x007e5a21   (×3)
[sdlspike] renderer: rendered 3 frames via wl_shm · RENDERER PATH GREEN
[wl-compositor] commit surf=16 buf=22 256x256 ... px0=0x00215a7e  (×3)
[sdlspike] surface: rendered 3 frames via wl_shm · SURFACE PATH GREEN
[sdlspike] quit OK · exit clean · FULL PATH GREEN
```

## v2.3-M4 · pool lifetime/refcount (the pool-leak follow-up — DONE)

`sdlspike.c` is now the M4 gate: an unmodified SDL2 app does >4 create/destroy
cycles, >4 resizes, 2 simultaneous windows, recreate-after-destroy, and exits
with a live window+pool — all without exhausting the 4 global pools. The orch
shm pool is now **refcounted and freed**: rc = the wl_shm_pool object (alloc→
`wl_shm_pool.destroy`) + each wl_buffer (`create_buffer`→`wl_buffer.destroy`);
at rc==0 the backing is freed (guest `vspace_unmap_pages`+reservation,
compositor `seL4_X86_Page_Unmap`, `vka_free_object` frames + copy caps). A sotbox
exit force-frees its still-referenced pools (`orch_shm_pool_free_owner`). The
memfd close is **not** a ref (immediate, races libwayland's buffered
`wl_buffer.destroy`); the SDL patch flushes in `DestroyWindowFramebuffer` so the
free is prompt. The compositor object table recycles slots on destroy
(`obj_del`) so create/destroy churn doesn't exhaust it. Verified green:
`alloc==freed+force-free`, no exhaustion, zero EPROTO, zero faults; wire-events
keyed on `(owner pid, connection fd)` so a hostile guest's 2nd wayland
connection can't collide wire-ids; `create_buffer` only counts a ref it can
later drop (>`SHM_BUF_WIRE_MAX` buffers stay untracked, reclaimed at teardown).

Boot the gate the same way as M3 (re-instate the SPIKE-TEMP harness) — but note
the gate uses SMALL windows so the per-4K-frame alloc/free stays fast within the
boot window (window size is irrelevant to lifetime; the churn is the test).

## Known limits (follow-ups)

- A committed gate needs the SDL libs + spike committed as fixtures (like
  `doomsdl.bin`) and a single in-tree `ld-musl` shared by all dynamic fixtures
  (the Alpine ld already loads them — verified by the green real-vfs gate in
  every spike boot — but making it the default is a separate decision).
- Compositor `obj_del` is latest-binding-wins on a global table — a single-client
  assumption (per-connection object tables are the L14 multi-client refinement).
