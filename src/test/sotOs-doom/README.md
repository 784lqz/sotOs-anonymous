# sotOs-doom — Phase 1a: headless doomgeneric static build

Doom running on sotOs as a sandboxed sotbox process. Phase 1a is headless:
doomgeneric ticks 200 frames of the title-screen demo loop and writes each
ARGB frame to `/dev/fb0` (handled by a later task).

## Prerequisites

**musl-cross toolchain** — must exist at `/tmp/x86_64-linux-musl-cross`:

```sh
curl -L https://musl.cc/x86_64-linux-musl-cross.tgz | tar -xz -C /tmp
```

## Two-command rebuild

```sh
bash fetch-doomgeneric.sh   # vendors ozkl/doomgeneric into external/doomgeneric/
make -f Makefile.fixture    # compiles doom.bin (static musl ELF, ~500 KB)
```

`doom.bin` is a static-pie Linux ELF containing the full doomgeneric engine
plus the sotOs shim (`doomgeneric_sotos.c`). It is gitignored by default
(matches `*.bin`); it is committed prebuilt alongside `freedoom1.wad` via
`git add -f` in a later task.

## v2.3-M5 — Doom over REAL Wayland (`doomwl.bin`, wl_shm, NO EGL)

`doomwl.bin` is the doomgeneric engine over the **patched DYNAMIC SDL2** fixture
(`src/test/sotOs-wayland-sdl/lib/libSDL2-2.0.so.0`, 2.30.9 + patches/sdl2/0001
dynapi-off + 0002 wl_shm software framebuffer).  The shim
(`doomgeneric_sotos_wl.c`) sets `SDL_VIDEODRIVER=wayland` +
`SDL_FRAMEBUFFER_ACCELERATION=0`, so the `SDL_RENDERER_SOFTWARE` renderer's
window framebuffer is a **wl_shm pool/buffer on the honest compositor** — every
`SDL_RenderPresent` is a real `wl_surface` attach/damage/commit.  No `/dev/fb0`,
no EGL/GL/Mesa.

Triggered by the `doomwl` sotShell command (`ORCH_OP_DOOMWL`), spawned Tier-0
trusted via `orch_handle_doomwl` (mirrors `orch_handle_doom`).  Runs in the
headless auto-demo right after `sdlspike`.  Verified green: the compositor
receives 640x400 Doom commits over wl_shm with many distinct frame hashes
(title→menu→E1M1, a moving demo), the box exits clean, zero faults, no EPROTO.

- Gate: `tools/doomwl-gate.sh` (boot + assert commits/hashes/clean-exit/no-fault).
- Boot+summary: `just run-doomwl`.
- Rebuild (dynamic, alpine:3.20): see `Makefile.fixture.wl` (the static
  `Makefile.fixture.sdl` / dummy-driver `doomsdl.bin` is the earlier headless
  de-risk; `doomwl.bin` is the real-wayland milestone).

## Files

| File | Purpose |
|------|---------|
| `doomgeneric_sotos.c` | sotOs platform shim — 5 DG_* callbacks + main (headless /dev/fb0) |
| `doomgeneric_sotos_sdl.c` | de-risk shim — real SDL2 (static), dummy video driver, /dev/fb0 |
| `doomgeneric_sotos_wl.c` | **v2.3-M5** — real SDL2 (dynamic), wayland backend, wl_shm (no EGL) |
| `Makefile.fixture` | static-musl build recipe (`doom.bin`) |
| `Makefile.fixture.sdl` | static SDL2 build recipe (`doomsdl.bin`) |
| `Makefile.fixture.wl` | dynamic SDL2 / wayland build recipe (`doomwl.bin`) |
| `fetch-doomgeneric.sh` | vendors ozkl/doomgeneric into `external/doomgeneric/` |

## Notes

- `external/doomgeneric/` is gitignored — run `fetch-doomgeneric.sh` to re-vendor.
- The build excludes all upstream platform files (xlib, sdl, allegro, emscripten, linuxvt, soso, sosox, win) and their SDL/allegro sound backends to avoid missing-header failures.
- `doom.bin` will segfault on a plain Linux host (it expects `/dev/fb0` and `/freedoom1.wad` via the sotOs kernel). This is expected — run it only inside sotOs.
