# v2.3-M5 · doomgeneric over REAL Wayland → doomwl.bin (DYNAMIC, real SDL2).
#
# Unlike Makefile.fixture.sdl (static-musl, dummy video driver, /dev/fb0), this
# builds doomwl.bin DYNAMICALLY against the patched SDL2 fixture so it runs the
# real wayland backend + SOFTWARE renderer → wl_shm framebuffer on the honest
# compositor (patches/sdl2/0002, NO EGL).  The runtime SDL2 is the committed
# fixture src/test/sotOs-wayland-sdl/lib/libSDL2-2.0.so.0 (2.30.9 patched); the
# interpreter is the in-tree ld-musl (byte-identical to Alpine musl 1.2.5).
#
# Build it in alpine:3.20 (musl-consistent · same image the SDL2 fixture is built
# from).  Alpine 3.20 ships SDL2 2.28.5 for the link-time -dev headers/stub; the
# public ABI is identical to the 2.30.9 runtime fixture (the patch only ADDS
# internal framebuffer hooks), so link against alpine's libSDL2 and RUN against
# the fixture.  The local pinned doomgeneric source is fed via a stdin tar so the
# build does not depend on network or a bind-mount (SELinux/rootless-userns).
#
#   SHIM_B64=$(base64 -w0 src/test/sotOs-doom/doomgeneric_sotos_wl.c)
#   tar -C external/doomgeneric/doomgeneric -cf - . | \
#   podman run -i --rm -e SHIM_B64="$SHIM_B64" alpine:3.20 sh -c '
#     apk add --no-cache gcc musl-dev sdl2-dev sdl2 >&2
#     mkdir -p /dg /out && tar -C /dg -xf -
#     echo "$SHIM_B64" | base64 -d > /dg/doomgeneric_sotos_wl.c
#     cd /dg
#     SRC=$(ls *.c | grep -vE "^doomgeneric_(xlib|sdl|allegro|emscripten|linuxvt|soso|sosox|win|soundtest|sotos|sotos_sdl|sotos_wl)\.c$|^i_(sdlmusic|sdlsound|allegromusic|allegrosound)\.c$")
#     gcc -O2 -DNORMALUNIX -DLINUX -DDOOMGENERIC -I/dg $(pkg-config --cflags sdl2) \
#         -o /out/doomwl.bin doomgeneric_sotos_wl.c $SRC $(pkg-config --libs sdl2) -lm -lpthread >&2
#     strip /out/doomwl.bin
#     tar -C /out -cf - doomwl.bin' > /tmp/doomwl.tar
#   tar -C src/test/sotOs-doom -xf /tmp/doomwl.tar && git add -f src/test/sotOs-doom/doomwl.bin
#
# Verify: readelf -d doomwl.bin → NEEDED libSDL2-2.0.so.0 + libc.musl-x86_64.so.1
#         readelf -l doomwl.bin → INTERP /lib/ld-musl-x86_64.so.1
.PHONY: help
help:
	@echo "doomwl.bin is built in alpine:3.20 · see the recipe in this file's header"
