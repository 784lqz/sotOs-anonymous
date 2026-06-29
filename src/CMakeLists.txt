cmake_minimum_required(VERSION 3.16.0)

# Project-level CMakeLists exposed to the seL4 build via the symlink
# projects/sotOs -> ../src. The seL4 cmake-tool's projects.cmake GLOBs
# projects/*/CMakeLists.txt and add_subdirectory()s each.
#
# Order matters: root/ bundles sto and test ELFs into a CPIO archive via
# generator expressions ($<TARGET_FILE:...>), so those targets must be
# declared first.

# PR 7 · the PROCD_TAKEOVER_SPAWN gate has been removed.  The
# announce path (orch → procd OP_SPAWN/OP_FORK/OP_EXIT/OP_WAIT/OP_EXEC)
# is unconditional from this point forward.  The legacy "procd-off"
# fallback branches in orch + lucas have been deleted with the gate.
# Cross-process untyped delegation (procd owning TCB/CSpace/VSpace
# creation) remains a future PR · for now procd still owns only
# the proc_t accounting · see src/procd/handlers_lifecycle.c for the
# scope-reduction rationale carried forward from PR 5/6.

add_subdirectory(bearssl)
add_subdirectory(sotos)
add_subdirectory(sotguard)
add_subdirectory(sottrace)
add_subdirectory(sotfs)
add_subdirectory(sto)
add_subdirectory(sotlibc)  # world-#3 native C runtime (freestanding · NO muslc symbols)
add_subdirectory(sotcrt)   # world-#3 crt0/bridge (over sel4runtime)
add_subdirectory(sotctl)   # native operator CLI (sotabi · M4/M5)
add_subdirectory(test)
add_subdirectory(bench)
add_subdirectory(lucas)
add_subdirectory(vdso)    # host-gcc PIC vdso.so stub · Task 3 · MUST precede orch (orch embeds the blob · Task 4)
add_subdirectory(orch)
add_subdirectory(sotshell)
add_subdirectory(anomaly)
add_subdirectory(net-synth)
add_subdirectory(procd)
add_subdirectory(sotinit)
add_subdirectory(sotcron)
add_subdirectory(wayland-compositor)
add_subdirectory(wayland-canary)
add_subdirectory(root)

# sotFS-γ Phase 2a · backing image for virtio-blk.  4 MiB zero-filled raw file
# created at build time.  Phase 2b+ wires the driver to read/write this.
# Phase 2d swaps the WAL RAM backend to virtio-blk so the log persists.
set(SOTFS_IMG_PATH "${CMAKE_BINARY_DIR}/images/sotfs.img")
set(SOTFS_PACKER "${CMAKE_SOURCE_DIR}/scripts/build-python-stdlib-zip.sh")
set(SOTFS_BINSTORE_PACKER "${CMAKE_SOURCE_DIR}/scripts/build-binstore.sh")
# N3/D1 · dynamic-linker fixtures baked into the binstore.
set(LUCAS_LD_MUSL "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-dyn/ld-musl-x86_64.so.1")
set(LUCAS_HELLO_DYN "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-dyn/hello_dyn.bin")
# N3/D2 · multi-lib dynamic fixtures.
set(LUCAS_LIBONEFN "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-dyn2/libonefn.so")
set(LUCAS_HELLO_DYN2 "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-dyn2/hello_dyn2.bin")
# N3/D3 · OpenSSL bait · real libcrypto.so.3 (4.48 MB · lazy-mmap'd) + the binary.
set(LUCAS_LIBCRYPTO "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-ssl/libcrypto.so.3")
set(LUCAS_HELLO_SSL "${CMAKE_SOURCE_DIR}/src/test/sotOs-hello-ssl/hello_ssl.bin")
# egress P2 · the REAL Alpine OpenSSL 3.3.7 CLI (musl-dynamic) + its libssl.so.3 —
# busybox `wget https://…` spawns `openssl s_client` as the TLS helper.  libcrypto
# (3.3.7) + ld-musl + libz are already staged; only libssl + the binary are new.
set(SOTFS_OPENSSL_BIN  "${CMAKE_SOURCE_DIR}/src/test/sotOs-openssl/bin/openssl")
set(SOTFS_OPENSSL_LIBSSL "${CMAKE_SOURCE_DIR}/src/test/sotOs-openssl/lib/libssl.so.3")
# egress · the real Alpine ca-certificates bundle → binstore "ca-certificates.crt",
# served read-only at /etc/ssl/cert.pem (backends_cacert.c) so the TLS client VERIFIES.
set(SOTFS_CACERT "${CMAKE_SOURCE_DIR}/src/test/sotOs-cacerts/ca-certificates.crt")
# v2-real-vfs · Gate E · dynamic PIE whose DT_NEEDED (libvfsprobe.so) is a
# symlink to libvfsprobe.so.1 in the committed sysroot tree (exercises the
# recursive sysroot symlink-follow path end-to-end).
set(LUCAS_VFSPROBE_BIN "${CMAKE_SOURCE_DIR}/src/test/sotOs-real-vfs/vfsprobe.bin")
# v2.3 · SDL2-over-real-Wayland fixtures (committed, repo-reproducible — no /tmp).
# An unmodified Alpine SDL2 2.30.9 (patches/sdl2/0001 dynapi-off + 0002 wl_shm
# software framebuffer) + its dlopen closure, baked into the sysroot /usr/lib;
# the sdlspike smoke binary into the binstore.  The interpreter is the in-tree
# ld-musl (byte-identical to Alpine's 1.2.5 — verified sha256), so NO separate
# ld is needed.  /usr/share/X11/xkb must merely EXIST for xkb_context_new.
set(SOTFS_SDL_FIXTURE_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-wayland-sdl")
set(SOTFS_SDL_SPIKE_BIN   "${SOTFS_SDL_FIXTURE_DIR}/sdlspike.bin")
# v2.4 · GTK3-over-real-Wayland spike fixture.  An unmodified Alpine GTK3 3.24
# (cairo software / wl_shm, no EGL) + its 57-lib dlopen closure + runtime data
# (gschemas, a font + fontconfig, gdk-pixbuf loaders) → sysroot /usr/lib + /usr/
# share; the gtkspike smoke binary → binstore.  Same in-tree ld-musl.
set(SOTFS_GTK_FIXTURE_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-wayland-gtk")
set(SOTFS_GTK_SPIKE_BIN   "${SOTFS_GTK_FIXTURE_DIR}/gtkspike.bin")
# v2.x · unmodified off-the-shelf GTK3 app (Alpine gtk+3.0-demo) → binstore · the
# "real Linux app, no per-app code" proof (NOT our gtkspike fixture).
set(SOTFS_GTK3DEMO_BIN    "${CMAKE_SOURCE_DIR}/src/test/sotOs-linux-gtk/gtk3-demo.bin")
# GTK fidelity (#2 · broader-apps) · the UNMODIFIED Alpine gtk3-widget-factory (the
# canonical GTK widget showcase) → binstore.  Same gtk+3.0-demo package + GTK env as
# gtk3-demo; its lib closure is a subset of gtk3-demo's (no new sysroot libs).
set(SOTFS_WIDGETFACTORY_BIN "${CMAKE_SOURCE_DIR}/src/test/sotOs-linux-gtk/widget-factory.bin")
# Wine-prep · MAP_FIXED-low gate fixture (static musl · the wine-preloader mmap
# PATTERN: reserve large PROT_NONE Windows ranges + commit via MAP_FIXED/mprotect).
set(SOTFS_MAPFIXED_BIN    "${CMAKE_SOURCE_DIR}/src/test/sotOs-linux-mmap/mapfixed.bin")
# Internet-egress Phase 1 · DNS forwarder gate fixture (static musl · resolves a
# name via UDP:53 + prints the first A record).  Spawned Tier-0e (real forward)
# AND non-egress (hermetic canary synth) by the egress-dns orch demo.
set(SOTFS_DNSPROBE_BIN    "${CMAKE_SOURCE_DIR}/src/test/sotOs-dnsprobe/dnsprobe.bin")
# Wine M1 SPIKE scaffolding · the minimal Wine subset staged by tools/wine-stage.sh
# into build/wine-sysroot (gitignored · regenerate on demand).  The `wine` loader
# (dynamic · ld-musl + Alpine libc) goes to the binstore; the /usr/lib/wine .so +
# PE-dll closure ships into the sysroot.  NOTE: spike-only build coupling — made
# reproducible (wine-stage as a build dep) in the production-hardening step.
# Compat-host · real Alpine git (musl-dynamic PIE) · committed fixture (NOT a
# build-time stage like wine — it ships in the tree so the demo is reproducible).
# git -> binstore (orch spawn + execve basename resolution); libz/libpcre2 ->
# sysroot /usr/lib (ld-musl resolves them by soname, like the SDL2/GTK3 closures).
set(SOTFS_GIT_FIXTURE_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-alpine-git")
set(SOTFS_GIT_BIN         "${SOTFS_GIT_FIXTURE_DIR}/bin/git")
# Attacker tool · REAL Alpine curl (musl-dynamic) → binstore; its 12-lib closure
# (libcurl/libssl/libcrypto/libcares/libnghttp2/libidn2/libpsl/libunistring/
# libzstd/libbrotli·common+dec/libz) → sysroot /usr/lib (ld-musl resolves by soname).
set(SOTFS_CURL_DIR        "${CMAKE_SOURCE_DIR}/src/test/sotOs-curl")
set(SOTFS_CURL_BIN        "${SOTFS_CURL_DIR}/bin/curl")
# apk-local-install · the real Alpine 3.20 apk.static (static-musl single binary).
set(SOTFS_APK_DIR  "${CMAKE_SOURCE_DIR}/src/test/sotOs-apk")
set(SOTFS_APK_BIN  "${SOTFS_APK_DIR}/bin/apk.static")
# persona-coherence · the real Alpine 3.20 musl bash (dynamically linked,
# interp /lib/ld-musl-x86_64.so.1) is the Tier-2 SSH honey login shell instead of
# the glibc debian-bash — a real Alpine box has NO /lib/x86_64-linux-gnu glibc
# multiarch dir.  Its .so closure (libreadline.so.8 → .8.2 + libncursesw.so.6) is
# cp -a'd into the sysroot /usr/lib so ld-musl resolves them by soname.
set(SOTFS_BASH_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-bash")
set(SOTFS_BASH_BIN "${SOTFS_BASH_DIR}/bin/alpine-bash")
# Compat-host · a glibc-static binary (real GNU/glibc libc, NOT musl) → binstore.
# Proves sotOs runs glibc binaries; the entire ABI is already supported (static
# avoids the ld-linux loader · that's the glibc-dynamic arc).
set(SOTFS_GLIBC_PROBE     "${CMAKE_SOURCE_DIR}/src/test/sotOs-glibc/glibc-probe")
# Compat-host · real GNU tools (musl-dynamic, from Alpine): GNU coreutils 9.5
# (multi-call ls/cat/wc/…), grep, sed, gawk → binstore; their lib closure
# (libacl/libattr/libcrypto/libgmp/libskarnet/libutmps · libpcre2 already staged
# for git) → sysroot /usr/lib.
set(SOTFS_GNU_FIXTURE_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-gnu")
set(SOTFS_GNU_COREUTILS   "${SOTFS_GNU_FIXTURE_DIR}/bin/coreutils")
set(SOTFS_GNU_GREP        "${SOTFS_GNU_FIXTURE_DIR}/bin/grep")
set(SOTFS_GNU_SED         "${SOTFS_GNU_FIXTURE_DIR}/bin/sed")
set(SOTFS_GNU_GAWK        "${SOTFS_GNU_FIXTURE_DIR}/bin/gawk")
# Compat-host · glibc-DYNAMIC: an off-the-shelf PIE linked against glibc, loaded
# by the REAL ld-linux-x86-64.so.2 (not ld-musl).  The interp + the PIE → binstore
# (sotOs fetches the interp by basename); libc.so.6 → sysroot at the Debian
# multiarch path /usr/lib/x86_64-linux-gnu (ld-linux probes /lib/x86_64-linux-gnu,
# routed there via the /lib→/usr/lib alias).
set(SOTFS_GLIBCDYN_DIR    "${CMAKE_SOURCE_DIR}/src/test/sotOs-glibc-dyn")
set(SOTFS_GLIBCDYN_HELLO  "${SOTFS_GLIBCDYN_DIR}/bin/hello-glibc-dyn")
set(SOTFS_GLIBCDYN_LD     "${SOTFS_GLIBCDYN_DIR}/loader/ld-linux-x86-64.so.2")
# A REAL off-the-shelf Debian binary: /bin/ls (glibc PIE).  Its full DT_NEEDED
# closure (libselinux/libcap/libpcre2-8 · libc.so.6 shared with the hello) ships
# in the same fixture lib/x86_64-linux-gnu and stages with the cp -a below.
set(SOTFS_GLIBCDYN_LS     "${SOTFS_GLIBCDYN_DIR}/bin/debian-ls")
# 2nd-persona (Debian 13) · the EXTENDED GNU coreutils set — real Debian 13 glibc
# binaries (coreutils 9.7 · glibc 2.41), so a Debian session's id/wc/tail/stat/…
# are GNU, not busybox.  Globbed (dedupe-safe · the explicit debian-cat/head/uname/
# sort/env/date + debian-ls/bash below are REMOVED from this list so each ships
# once).  Their lib closure (libacl/libattr added · libc/libselinux/libpcre2/libcap
# already present) ships in the glibc-dyn fixture lib → sysroot.
file(GLOB SOTFS_DEBIAN_COREUTILS "${SOTFS_GLIBCDYN_DIR}/bin/debian-*")
list(REMOVE_ITEM SOTFS_DEBIAN_COREUTILS
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-bash"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-ls"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-cat"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-head"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-uname"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-sort"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-env"
    "${SOTFS_GLIBCDYN_DIR}/bin/debian-date")
# TUI · xterm terminfo + ncurses closure for nano/less/vim.  ncurses/tinfo loads
# the xterm terminfo entry from /usr/share/terminfo/x/xterm (guests get TERM=xterm);
# libtinfo/libncursesw are the runtime shared libs.  Real Debian files (compiled
# terminfo is binary), staged like the glibc-dyn lib closure + the SDL/GTK share
# trees: lib closure → sysroot /usr/lib/x86_64-linux-gnu (ld-linux resolves them
# by soname · libc.so.6 already ships via the glibc-dyn fixture), terminfo data →
# sysroot /usr/share/terminfo/x.  A5 · the editor BINARIES (off-the-shelf Debian
# glibc-dynamic PIEs · vim-tiny chosen for the smaller ncurses surface) → binstore
# basename-keyed for orch spawn + execve resolution; their REMAINING lib closure
# (libm/libselinux/libacl/libpcre2-8 for vim-tiny) ships in the same
# sysroot/usr/lib/x86_64-linux-gnu and stages with the A4 cp -a below.
set(SOTFS_TUI_FIXTURE_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-tui/sysroot")
set(SOTFS_TUI_BIN_DIR     "${CMAKE_SOURCE_DIR}/src/test/sotOs-tui/bin")
set(SOTFS_TUI_LESS        "${SOTFS_TUI_BIN_DIR}/less")
set(SOTFS_TUI_NANO        "${SOTFS_TUI_BIN_DIR}/nano")
set(SOTFS_TUI_VIM         "${SOTFS_TUI_BIN_DIR}/vim")
# Install-arc P0.1 · the real Debian dpkg toolchain (glibc-dynamic, off-the-shelf
# debian:13-slim).  The 7 BINARIES (dpkg/dpkg-deb/dpkg-split/tar/xz/gzip/zstd) →
# binstore basename-keyed (orch spawn + execve resolution); their lib closure's
# NEW .so's (libmd/libz/liblzma/libzstd/libbz2/liblz4/libxxhash · libc/ld-linux/
# libselinux/libacl/libpcre2 already ship via glibc-dyn+tui) → sysroot
# /usr/lib/x86_64-linux-gnu (ld-linux resolves by soname).  The hello.deb is DATA
# → embedded as a blob installed to /tmp/hello.deb (src/lucas, NOT the binstore).
set(SOTFS_DPKG_BIN_DIR    "${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/bin")
set(SOTFS_DPKG_FIXTURE_DIR "${CMAKE_SOURCE_DIR}/src/test/sotOs-dpkg/sysroot")
set(SOTFS_DPKG_DPKG       "${SOTFS_DPKG_BIN_DIR}/dpkg")
set(SOTFS_DPKG_DPKGDEB    "${SOTFS_DPKG_BIN_DIR}/dpkg-deb")
set(SOTFS_DPKG_DPKGSPLIT  "${SOTFS_DPKG_BIN_DIR}/dpkg-split")
set(SOTFS_DPKG_TAR        "${SOTFS_DPKG_BIN_DIR}/tar")
set(SOTFS_DPKG_XZ         "${SOTFS_DPKG_BIN_DIR}/xz")
set(SOTFS_DPKG_GZIP       "${SOTFS_DPKG_BIN_DIR}/gzip")
set(SOTFS_DPKG_ZSTD       "${SOTFS_DPKG_BIN_DIR}/zstd")
# apt arc · Phase 0 · the real Debian trixie apt toolchain (glibc-dynamic, C++).
# Frontends -> binstore; libapt + C++ closure -> sysroot /usr/lib; the transport
# methods -> sysroot /usr/lib/apt/methods; gpgv + archive keyring -> sysroot.
# Sourced once by scripts/source-apt-fixtures.sh (committed under src/test/sotOs-apt).
set(SOTFS_APT_DIR      "${CMAKE_SOURCE_DIR}/src/test/sotOs-apt")
set(SOTFS_APT_APT      "${SOTFS_APT_DIR}/bin/apt")
set(SOTFS_APT_APTGET   "${SOTFS_APT_DIR}/bin/apt-get")
set(SOTFS_APT_APTCACHE "${SOTFS_APT_DIR}/bin/apt-cache")
set(SOTFS_WINE_STAGE      "${CMAKE_BINARY_DIR}/wine-sysroot")
set(SOTFS_WINE_LOADER     "${SOTFS_WINE_STAGE}/bin/wine")
set(SOTFS_WINE_PRELOADER  "${SOTFS_WINE_STAGE}/bin/wine-preloader")
set(SOTFS_WINE_SERVER     "${SOTFS_WINE_STAGE}/bin/wineserver")
set(SOTFS_WINE_HELLO      "${CMAKE_SOURCE_DIR}/src/test/sotOs-wine/hello.exe")
# Wine M2 · the real-CRT (msvcrt printf/malloc) test PE · built next to hello.exe
# by tools/wine-stage.sh (regenerate on demand; a no-op copy if absent).
set(SOTFS_WINE_HELLO_CRT  "${CMAKE_SOURCE_DIR}/src/test/sotOs-wine/hello_crt.exe")
# Wine GUI · a real Win32 GUI PE (user32/gdi32 → winewayland) · staged like the others.
set(SOTFS_WINE_HELLO_GUI  "${CMAKE_SOURCE_DIR}/src/test/sotOs-wine/hello_gui.exe")
# Wine M1 · /usr/bin sysroot tree.  Real apps + glibc/musl realpath() require
# /usr/bin to EXIST as a directory: wine derives its dll dir as
# <bindir>/../lib/wine and realpath()s it, stat-ing every component — so the
# loader MUST live at a real /usr/bin/wine (not just an alias).
set(SOTFS_SYSROOT_BIN     "${CMAKE_BINARY_DIR}/sysroot-bin")
# Merged /usr/share staging (the sysroot packer takes ONE share dir): SDL's
# X11/xkb + GTK's glib-2.0/schemas + fonts + fontconfig.
set(SOTFS_SYSROOT_SHARE "${CMAKE_BINARY_DIR}/sysroot-share")
# tcc-libc · musl sysroot packer.  Sources a SEPARATE STANDARD x86_64 musl
# (raw `syscall` · vendored under src/test/musl-x86_64/lib) — NOT the OS's
# x86_64_sel4 musl, whose syscalls route through a sel4 `__sysinfo` shim that a
# LUCAS Linux guest has no AT_SYSINFO for (→ SIGSEGV in __init_tp).  The OS
# musllibc build is left untouched (no OS relink).  libc.a + crt1/crti/crtn.o +
# the vendored libtcc1.a are assembled into a build-staging lib dir, packed
# with the committed external musl headers.
set(SOTFS_SYSROOT_PACKER "${CMAKE_SOURCE_DIR}/scripts/build-sysroot.sh")
set(SOTFS_SYSROOT_INCLUDE "${CMAKE_SOURCE_DIR}/src/test/musl-x86_64/include")
set(SOTFS_MUSL_LIB "${CMAKE_SOURCE_DIR}/src/test/musl-x86_64/lib")
set(SOTFS_LIBTCC1 "${CMAKE_SOURCE_DIR}/src/test/tcc-bin/libtcc1.a")
set(SOTFS_SYSROOT_LIB "${CMAKE_BINARY_DIR}/sysroot-lib")
# v2-real-vfs · committed recursive lib tree (subdirs + the libvfsprobe.so ->
# libvfsprobe.so.1 symlink) staged with `cp -a` so symlinks survive as LNK.
set(SOTFS_SYSROOT_TREE "${CMAKE_SOURCE_DIR}/src/test/sysroot-lib")
# ENCODINGS-3: always run the packer.  An OUTPUT-driven custom_command only
# fires when the output is missing or DEPENDS are newer · it cannot detect
# when sotfs.img exists but is corrupt (e.g. zeroed first 32 bytes, which
# we hit after a partial write or accidental truncation).  The packer is
# fully idempotent: it sha1-checks the existing header + embedded zip bytes
# and is a no-op when in sync (≈50 ms).  Running it on every build adds
# negligible overhead and prevents stale/zero'd images from silently
# breaking Python at runtime.
add_custom_target(sotfs-img ALL
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/images"
    COMMAND truncate -s 528M "${SOTFS_IMG_PATH}"
    COMMAND bash "${SOTFS_PACKER}" "${SOTFS_IMG_PATH}"
    COMMAND bash "${SOTFS_BINSTORE_PACKER}" "${SOTFS_IMG_PATH}" "${TCC_BIN}" "${LUCAS_PYTHON_BIN}" "${LUCAS_BUSYBOX_BIN}" "$<TARGET_FILE:sotOs-sto>" "$<TARGET_FILE:sotctl>" "$<TARGET_FILE:sotOs-shell>" "${LUCAS_LD_MUSL}" "${LUCAS_HELLO_DYN}" "${LUCAS_HELLO_DYN2}" "${LUCAS_HELLO_SSL}" "${DOOM_BIN}" "${DOOM_WAD}" "${DOOMSDL_BIN}" "${CHOCODOOM_BIN}" "${LUCAS_VFSPROBE_BIN}" "${SOTFS_SDL_SPIKE_BIN}" "${DOOMWL_BIN}" "${SOTFS_GTK_SPIKE_BIN}" "${SOTFS_GTK3DEMO_BIN}" "${SOTFS_WIDGETFACTORY_BIN}" "${SOTFS_MAPFIXED_BIN}" "${SOTFS_DNSPROBE_BIN}" "${SOTFS_WINE_LOADER}" "${SOTFS_WINE_PRELOADER}" "${SOTFS_WINE_SERVER}" "${SOTFS_GIT_BIN}" "${SOTFS_GLIBC_PROBE}" "${SOTFS_GNU_COREUTILS}" "${SOTFS_GNU_GREP}" "${SOTFS_GNU_SED}" "${SOTFS_GNU_GAWK}" "${SOTFS_GLIBCDYN_HELLO}" "${SOTFS_GLIBCDYN_LD}" "${SOTFS_GLIBCDYN_LS}" "${SOTFS_GLIBCDYN_DIR}/bin/debian-cat" "${SOTFS_GLIBCDYN_DIR}/bin/debian-head" "${SOTFS_GLIBCDYN_DIR}/bin/debian-uname" "${SOTFS_GLIBCDYN_DIR}/bin/debian-sort" "${SOTFS_GLIBCDYN_DIR}/bin/debian-env" "${SOTFS_GLIBCDYN_DIR}/bin/debian-date" "${SOTFS_GLIBCDYN_DIR}/bin/fedora-uname" "${SOTFS_GLIBCDYN_DIR}/bin/fedora-cat" "${SOTFS_GLIBCDYN_DIR}/bin/debian-bash" ${SOTFS_DEBIAN_COREUTILS} "${SOTFS_TUI_LESS}" "${SOTFS_TUI_NANO}" "${SOTFS_TUI_VIM}" "${SOTFS_DPKG_DPKG}" "${SOTFS_DPKG_DPKGDEB}" "${SOTFS_DPKG_DPKGSPLIT}" "${SOTFS_DPKG_TAR}" "${SOTFS_DPKG_XZ}" "${SOTFS_DPKG_GZIP}" "${SOTFS_DPKG_ZSTD}" "${SOTFS_OPENSSL_BIN}" "${SOTFS_CACERT}" "${SOTFS_CURL_BIN}" "${SOTFS_APK_BIN}" "${SOTFS_BASH_BIN}" "${SOTFS_APT_APT}" "${SOTFS_APT_APTGET}" "${SOTFS_APT_APTCACHE}"
    # tcc-libc · assemble the standard x86_64 musl (libc.a + crt1/crti/crtn.o)
    # + the vendored libtcc1.a into a build-staging lib dir, then bake the
    # sysroot tree (/usr/include + /usr/lib) into [64,112 MiB).  v2-real-vfs:
    # stage the committed recursive tree first (cp -a preserves the
    # libvfsprobe.so symlink → LNK), then the build-generated archives flat.
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${SOTFS_SYSROOT_LIB}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SOTFS_SYSROOT_LIB}"
    COMMAND bash -c "cp -a '${SOTFS_SYSROOT_TREE}/.' '${SOTFS_SYSROOT_LIB}/'"
    COMMAND ${CMAKE_COMMAND} -E copy
            "${SOTFS_MUSL_LIB}/libc.a" "${SOTFS_MUSL_LIB}/crt1.o"
            "${SOTFS_MUSL_LIB}/crti.o" "${SOTFS_MUSL_LIB}/crtn.o"
            "${SOTFS_LIBTCC1}" "${LUCAS_LIBONEFN}" "${LUCAS_LIBCRYPTO}" "${SOTFS_OPENSSL_LIBSSL}" "${SOTFS_SYSROOT_LIB}/"
    # Wine M1 · the dynamic loader ld-musl must ALSO be guest-openable at
    # /lib/ld-musl-x86_64.so.1 (→ /usr/lib via the alias): wine-preloader maps the
    # wine loader's PT_INTERP itself (LUCAS only loads the interp for the INITIAL
    # spawn; the preloader's userspace re-exec opens it as a file).
    COMMAND ${CMAKE_COMMAND} -E copy "${LUCAS_LD_MUSL}" "${SOTFS_SYSROOT_LIB}/"
    # v2.3 · stage the committed SDL2 closure into /usr/lib (ld-musl + SDL2's
    # dlopen find them by soname).  v2.4 · the GTK3 closure (incl. its
    # gdk-pixbuf-2.0/ loaders subtree) likewise into /usr/lib.
    COMMAND bash -c "cp -a '${SOTFS_SDL_FIXTURE_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/'"
    COMMAND bash -c "cp -a '${SOTFS_GTK_FIXTURE_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/'"
    # Compat-host · git's extra DT_NEEDED libs (libz.so.1, libpcre2-8.so.0) into
    # /usr/lib · ld-musl resolves them by soname (ld-musl + libc itself already here).
    COMMAND bash -c "cp -a '${SOTFS_GIT_FIXTURE_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/'"
    # Attacker tool · real curl's 12-lib closure → sysroot /usr/lib.
    COMMAND bash -c "test -d '${SOTFS_CURL_DIR}/lib' && cp -a '${SOTFS_CURL_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[curl] lib fixture absent'"
    # persona-coherence · the musl bash .so closure (libreadline.so.8 → .8.2 +
    # libncursesw.so.6) → sysroot /usr/lib · ld-musl (the Alpine loader) resolves
    # them by soname.  These live under /usr/lib (musl) — coherent with a real
    # Alpine box, NOT under the glibc /lib/x86_64-linux-gnu multiarch dir.
    COMMAND bash -c "test -d '${SOTFS_BASH_DIR}/lib' && cp -a '${SOTFS_BASH_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[bash] lib fixture absent'"
    # Compat-host · GNU tools' lib closure (libacl/libattr/libcrypto/libgmp/
    # libskarnet/libutmps) into /usr/lib.  Guarded · no-op if the fixture is absent.
    COMMAND bash -c "test -d '${SOTFS_GNU_FIXTURE_DIR}/lib' && cp -a '${SOTFS_GNU_FIXTURE_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[gnu] lib fixture absent'"
    # Compat-host · glibc-dynamic's libc.so.6 into the Debian multiarch dir
    # /usr/lib/x86_64-linux-gnu (the cp -a brings the x86_64-linux-gnu/ subdir).
    # ld-linux probes /lib/x86_64-linux-gnu/libc.so.6 → /usr/lib via the alias.
    COMMAND bash -c "test -d '${SOTFS_GLIBCDYN_DIR}/lib' && cp -a '${SOTFS_GLIBCDYN_DIR}/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[glibcdyn] lib fixture absent'"
    # TUI · ncurses closure (libtinfo.so.6, libncursesw.so.6) into the Debian
    # multiarch dir /usr/lib/x86_64-linux-gnu (the cp -a brings the
    # x86_64-linux-gnu/ subdir).  ld-linux resolves them by soname for nano/less;
    # libc.so.6 already staged by the glibcdyn fixture above.
    COMMAND bash -c "test -d '${SOTFS_TUI_FIXTURE_DIR}/usr/lib' && cp -a '${SOTFS_TUI_FIXTURE_DIR}/usr/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[tui] lib fixture absent'"
    # Install-arc P0.1 · the dpkg toolchain's NEW lib closure (libmd/libz/liblzma/
    # libzstd/libbz2/liblz4/libxxhash) into the Debian multiarch dir
    # /usr/lib/x86_64-linux-gnu (the cp -a brings the x86_64-linux-gnu/ subdir).
    # ld-linux resolves them by soname for dpkg/dpkg-deb/tar/xz/zstd; libc.so.6 +
    # libselinux/libacl/libpcre2 already staged by the glibcdyn/tui fixtures above.
    COMMAND bash -c "test -d '${SOTFS_DPKG_FIXTURE_DIR}/usr/lib' && cp -a '${SOTFS_DPKG_FIXTURE_DIR}/usr/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[dpkg] lib fixture absent'"
    # apt arc P0 · the apt toolchain's glibc lib closure into the GLIBC MULTIARCH
    # subdir /usr/lib/x86_64-linux-gnu — NOT the flat /usr/lib root.  This is the key
    # coexistence seam: glibc ld-linux's default search includes .../x86_64-linux-gnu
    # (where the dpkg fixture already stages glibc libz/liblzma/libzstd/libbz2/…),
    # while MUSL guests (curl/gnu/git) resolve the SAME sonames from the FLAT /lib
    # (their musl copies, NEEDing libc.musl-x86_64.so.1).  Two dirs, one soname each →
    # no collision.  Staging apt's copies FLAT broke the musl demos ("Error relocating
    # /lib/libz.so.1: __snprintf_chk: symbol not found" — glibc _FORTIFY symbols absent
    # in musl).  So: apt's own .so's (libapt-pkg/libapt-private/libstdc++/libgcrypt/
    # libgpg-error/libseccomp/libsystemd/libudev) AND the three glibc closure libs the
    # dpkg fixture does NOT stage (libcrypto/libssl/libgcc_s) all land in the multiarch
    # subdir.  The rest (libz/libbz2/liblzma/liblz4/libzstd/libxxhash/libm/libc) are
    # already there as glibc via the dpkg fixture, so we don't re-copy them.
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SOTFS_SYSROOT_LIB}/x86_64-linux-gnu"
    COMMAND bash -c "for so in libapt-pkg.so.7.0 libapt-private.so.0.0 libstdc++.so.6 libgcrypt.so.20 libgpg-error.so.0 libseccomp.so.2 libsystemd.so.0 libudev.so.1 libcrypto.so.3 libssl.so.3 libgcc_s.so.1; do test -f '${SOTFS_APT_DIR}/lib/'\$so && cp -a '${SOTFS_APT_DIR}/lib/'\$so '${SOTFS_SYSROOT_LIB}/x86_64-linux-gnu/'\$so; done || echo '[apt] lib fixture absent'"
    # apt arc P0 · the transport methods → /usr/lib/apt/methods/{http,gpgv,store,copy}
    # (apt-get execs them as <libexec>/apt/methods/<scheme>).
    COMMAND bash -c "test -d '${SOTFS_APT_DIR}/methods' && mkdir -p '${SOTFS_SYSROOT_LIB}/apt/methods' && cp -a '${SOTFS_APT_DIR}/methods/.' '${SOTFS_SYSROOT_LIB}/apt/methods/' || echo '[apt] methods fixture absent'"
    # Wine M1 SPIKE · the /usr/lib/wine .so + PE-dll closure (winewayland/ntdll.so/
    # the x86_64-unix set + the x86_64-windows PE dlls) + the test PE at
    # /usr/lib/wine/hello.exe.  Guarded: a no-op if build/wine-sysroot is absent.
    COMMAND bash -c "test -d '${SOTFS_WINE_STAGE}/lib' && cp -a '${SOTFS_WINE_STAGE}/lib/.' '${SOTFS_SYSROOT_LIB}/' || echo '[wine] subset absent · run tools/wine-stage.sh'"
    # Stage the test PE in the x86_64-windows ARCH dir (next to the builtin PE dlls).
    # The launcher loads hello.exe as the main exe, so its app-dir becomes the FIRST
    # entry of wine's default DLL search path; placing it beside kernel32.dll lets the
    # launcher resolve builtin imports (kernel32/kernelbase/…) by that first probe —
    # without WINEBOOTSTRAPMODE (the arch-subdir append is bootstrap-gated in wine).
    COMMAND bash -c "test -f '${SOTFS_WINE_HELLO}' && test -d '${SOTFS_SYSROOT_LIB}/wine/x86_64-windows' && cp '${SOTFS_WINE_HELLO}' '${SOTFS_SYSROOT_LIB}/wine/x86_64-windows/hello.exe' || true"
    # Wine M2 · the real-CRT printf/malloc PE beside hello.exe (no-op if not staged).
    COMMAND bash -c "test -f '${SOTFS_WINE_HELLO_CRT}' && test -d '${SOTFS_SYSROOT_LIB}/wine/x86_64-windows' && cp '${SOTFS_WINE_HELLO_CRT}' '${SOTFS_SYSROOT_LIB}/wine/x86_64-windows/hello_crt.exe' || true"
    # Wine GUI · the Win32 GUI PE beside hello.exe (no-op if not staged).
    COMMAND bash -c "test -f '${SOTFS_WINE_HELLO_GUI}' && test -d '${SOTFS_SYSROOT_LIB}/wine/x86_64-windows' && cp '${SOTFS_WINE_HELLO_GUI}' '${SOTFS_SYSROOT_LIB}/wine/x86_64-windows/hello_gui.exe' || true"
    # Wine M1 · stage /usr/bin with the wine loader + preloader.  realpath() needs
    # /usr/bin to be a REAL directory: the loader at /usr/bin/wine → its dll dir
    # /usr/bin/../lib/wine = /usr/lib/wine resolves; the preloader open()s the
    # loader at /usr/bin/wine.  (The binstore copies are for orch's initial spawn.)
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${SOTFS_SYSROOT_BIN}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SOTFS_SYSROOT_BIN}"
    COMMAND bash -c "test -f '${SOTFS_WINE_LOADER}' && cp '${SOTFS_WINE_LOADER}' '${SOTFS_SYSROOT_BIN}/wine' || true"
    COMMAND bash -c "test -f '${SOTFS_WINE_PRELOADER}' && cp '${SOTFS_WINE_PRELOADER}' '${SOTFS_SYSROOT_BIN}/wine-preloader' || true"
    # Compat-host · git also at a real /usr/bin/git (execve resolution + realpath);
    # the binstore copy above is for orch's initial spawn.
    COMMAND bash -c "test -f '${SOTFS_GIT_BIN}' && cp '${SOTFS_GIT_BIN}' '${SOTFS_SYSROOT_BIN}/git' || true"
    # Install-arc P0.1 · the dpkg toolchain ALSO at real /usr/bin/<name> (dpkg
    # realpath()s + PATH-resolves its helpers dpkg-deb/dpkg-split/tar/xz/zstd
    # internally; the binstore copies are for orch's initial spawn + basename execve).
    COMMAND bash -c "for b in dpkg dpkg-deb dpkg-split tar xz gzip zstd; do test -f '${SOTFS_DPKG_BIN_DIR}/'\$b && cp '${SOTFS_DPKG_BIN_DIR}/'\$b '${SOTFS_SYSROOT_BIN}/'\$b; done || true"
    # apt arc P0 · the real GnuPG gpgv at /usr/bin/gpgv (the gpgv method execs it to
    # verify Release signatures).  The apt frontends also land in the binstore above
    # for orch spawn; gpgv is sysroot-only (apt-get PATH-resolves it internally).
    COMMAND bash -c "test -f '${SOTFS_APT_DIR}/bin/gpgv' && cp '${SOTFS_APT_DIR}/bin/gpgv' '${SOTFS_SYSROOT_BIN}/gpgv' || true"
    # Merge both fixtures' /usr/share trees (SDL X11/xkb + GTK glib schemas/fonts/
    # fontconfig) into one staging dir — the packer bakes a single share dir.
    COMMAND ${CMAKE_COMMAND} -E rm -rf "${SOTFS_SYSROOT_SHARE}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${SOTFS_SYSROOT_SHARE}"
    COMMAND bash -c "cp -a '${SOTFS_SDL_FIXTURE_DIR}/share/.' '${SOTFS_SYSROOT_SHARE}/'"
    COMMAND bash -c "cp -a '${SOTFS_GTK_FIXTURE_DIR}/share/.' '${SOTFS_SYSROOT_SHARE}/'"
    # TUI · the xterm terminfo entries → /usr/share/terminfo/x (ncurses/tinfo
    # reads /usr/share/terminfo/x/xterm at startup; guests get TERM=xterm).
    # Guarded: a no-op if the fixture is absent.
    COMMAND bash -c "test -d '${SOTFS_TUI_FIXTURE_DIR}/usr/share' && cp -a '${SOTFS_TUI_FIXTURE_DIR}/usr/share/.' '${SOTFS_SYSROOT_SHARE}/' || echo '[tui] share fixture absent'"
    # apt arc P0 · the Debian archive keyring → /usr/share/keyrings/debian-archive-keyring.pgp
    # (gpgv verifies Release sigs against it).  NOTE the .pgp suffix (trixie renamed
    # it from .gpg).  Guarded: a no-op if the fixture is absent.
    COMMAND bash -c "test -f '${SOTFS_APT_DIR}/keyrings/debian-archive-keyring.pgp' && mkdir -p '${SOTFS_SYSROOT_SHARE}/keyrings' && cp '${SOTFS_APT_DIR}/keyrings/debian-archive-keyring.pgp' '${SOTFS_SYSROOT_SHARE}/keyrings/debian-archive-keyring.pgp' || echo '[apt] keyring fixture absent'"
    # apt arc P0 · the dpkg arch tables → /usr/share/dpkg/{cputable,tupletable}.
    # libapt-pkg's APT::Configuration::getArchitectures() reads these to derive the
    # multiarch set; without them apt-get -h dies "E: Error reading the CPU table".
    # Guarded: a no-op if the fixture is absent.
    COMMAND bash -c "test -d '${SOTFS_APT_DIR}/share/dpkg' && mkdir -p '${SOTFS_SYSROOT_SHARE}/dpkg' && cp -a '${SOTFS_APT_DIR}/share/dpkg/.' '${SOTFS_SYSROOT_SHARE}/dpkg/' || echo '[apt] dpkg arch-table fixture absent'"
    # Wine M1 · /usr/share/wine/nls (locale.nls, l_intl.nls, codepage tables) —
    # ntdll reads these at init.  Guarded: a no-op if build/wine-sysroot/share is
    # absent (tools/wine-stage.sh not run).
    COMMAND bash -c "test -d '${SOTFS_WINE_STAGE}/share' && cp -a '${SOTFS_WINE_STAGE}/share/.' '${SOTFS_SYSROOT_SHARE}/' || echo '[wine] share subset absent'"
    COMMAND bash "${SOTFS_SYSROOT_PACKER}" "${SOTFS_IMG_PATH}"
            "${SOTFS_SYSROOT_INCLUDE}"
            "${SOTFS_SYSROOT_LIB}"
            "${SOTFS_SYSROOT_SHARE}"
            "${SOTFS_SYSROOT_BIN}"
    BYPRODUCTS "${SOTFS_IMG_PATH}"
    COMMENT "Verifying sotfs.img · 528 MiB layout · [0..28M)=stdlib, [28..96M)=binstore, [96..256M)=sysroot, [256..268M)=rwbinstore, [268..272M)=WAL, [272..528M)=data heap"
    VERBATIM
)
# The sysroot's musl is the vendored standard x86_64 build (src/test/musl-x86_64),
# NOT the OS musllibc output — so the sysroot no longer depends on muslc_gen.
# muslc_gen still builds the OS libc that the OS binaries link; keeping the
# (harmless) ordering edge avoids racing the shared images/ dir at build time.
add_dependencies(sotfs-img muslc_gen)
