#!/usr/bin/env bash
# sotOs · Wine M1 staging — assemble the MINIMAL console-Wine subset + a test PE.
#
# Wine ships ~350 MiB (81-pkg closure, i386 + x86_64).  A headless CONSOLE PE
# (`wine hello.exe`, WriteFile to stdout · no GUI) needs only a tiny slice:
#   • the x86_64-unix loader-side .so set (ntdll.so + win32u.so + winewayland.so …)
#   • wineserver + the wine/wine-preloader loaders
#   • a handful of x86_64-windows PE dlls (ntdll, kernel32, kernelbase, msvcrt …)
# That is ~5–10 MiB — fits a modest sysroot expansion.  i386 (171 MiB) is dropped
# (x86_64-only), as are GUI/mesa/GL/alsa/the 16-bit .drv set.
#
# Reproducible: builds in alpine:3.20 (the musl toolchain our fixtures use) and
# stages into build/wine-sysroot/ (gitignored · regenerate on demand).  hello.exe
# is also copied to src/test/sotOs-wine/ as the committed M1 test artifact.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
STAGE=build/wine-sysroot
ART=src/test/sotOs-wine
podman unshare rm -rf "$STAGE" 2>/dev/null || rm -rf "$STAGE" 2>/dev/null || true
mkdir -p "$STAGE" "$ART"

echo "[wine-stage] building hello.exe + extracting the minimal subset in alpine:3.20…"
# NO write bind-mount: rootless-podman userns/SELinux makes a host dir mounted at
# /out unreliably writable by container-root (env-specific "mkdir /out: Permission
# denied").  Instead the container assembles everything into container-local /out
# + /art, then emits ONE tar stream on stdout (prefixed out/ and art/) which the
# host unpacks below.  Robust regardless of subuid mapping or label policy.
TARBALL=$(mktemp)
trap 'rm -f "$TARBALL"' EXIT
podman run --rm docker.io/library/alpine:3.20 sh -c '
set -e
exec 3>&1 1>&2   # keep fd3 = real stdout for the final tar; all build chatter → stderr
mkdir -p /art
apk add --quiet mingw-w64-gcc wine >/dev/null 2>&1
# 1) a trivial x86_64 Windows console PE
cat > /tmp/hello.c <<EOF
#include <windows.h>
/* CRT-less console PE · custom entry "start", imports ONLY kernel32 (no msvcrt) so
 * it does not pull msvcrt.dll and trigger its DllMain locale/NLS init (the M1 wall).
 * Still exercises the full wine path: PE loader + kernel32 WriteFile->stdout +
 * wineserver IPC + segment ABI.  (CRT/msvcrt support is the POSIX-complete follow-up.) */
void start(void){ static const char m[]="hello from a Windows PE on sotOs\n"; DWORD w;
  WriteFile(GetStdHandle(STD_OUTPUT_HANDLE), m, sizeof(m)-1, &w, 0); ExitProcess(0); }
EOF
x86_64-w64-mingw32-gcc -O2 -nostdlib -nostartfiles -Wl,-e,start -o /art/hello.exe /tmp/hello.c -lkernel32
# 1b) Wine M2 · a REAL CRT PE · uses msvcrt printf/malloc (the C runtime).  This
# pulls msvcrt.dll and triggers its DllMain locale/NLS init (the M1 wall) + the
# mingw CRT startup (__getmainargs, _initterm, atexit…).  Built normally (no
# -nostdlib), so it links the mingw CRT + imports msvcrt.
cat > /tmp/hello_crt.c <<EOF
#include <stdio.h>
#include <stdlib.h>
/* Wine M2 target · exercise the real C runtime: printf (msvcrt _vfprintf →
 * WriteFile via the CRT stdout FILE), malloc/free (msvcrt heap), and a clean
 * return through the CRT exit path (atexit/_cexit → ExitProcess). */
int main(void){
  char *p = malloc(64);
  if (!p) return 2;
  snprintf(p, 64, "hello from msvcrt printf on sotOs (malloc=%p)\n", (void*)p);
  fputs(p, stdout);
  fflush(stdout);
  free(p);
  return 0;
}
EOF
x86_64-w64-mingw32-gcc -O2 -o /art/hello_crt.exe /tmp/hello_crt.c
# 1c) Wine GUI · a real Win32 GUI PE · RegisterClass + CreateWindowEx + ShowWindow
# + a paint, driving user32/gdi32/win32u → winewayland.so → wl_shm/xdg_shell on
# our compositor (the GTK/SDL/Doom path).  Pumps a few messages so winewayland
# flushes the surface commit, then destroys + exits clean.
cat > /tmp/hello_gui.c <<EOF
#include <windows.h>
#include <stdio.h>
static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l){
  if (m == WM_PAINT){
    PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps);
    RECT r; GetClientRect(h, &r);
    FillRect(dc, &r, (HBRUSH)(COLOR_WINDOW+1));
    TextOutA(dc, 20, 20, "hello from a Win32 GUI PE on sotOs", 33);
    EndPaint(h, &ps);
    fputs("[gui] WM_PAINT painted\n", stdout); fflush(stdout);
    return 0;
  }
  if (m == WM_DESTROY){ PostQuitMessage(0); return 0; }
  return DefWindowProcA(h, m, w, l);
}
int main(void){
  WNDCLASSA wc; memset(&wc, 0, sizeof(wc));
  wc.lpfnWndProc = WndProc; wc.hInstance = GetModuleHandleA(0);
  wc.lpszClassName = "sotwin"; wc.hbrBackground = (HBRUSH)(COLOR_WINDOW+1);
  if (!RegisterClassA(&wc)){ fputs("RegisterClass FAILED\n", stdout); return 2; }
  HWND h = CreateWindowExA(0, "sotwin", "sotOs Win32 GUI", WS_OVERLAPPEDWINDOW,
                           CW_USEDEFAULT, CW_USEDEFAULT, 400, 300, 0, 0, wc.hInstance, 0);
  if (!h){ fputs("CreateWindowEx FAILED\n", stdout); return 3; }
  printf("hello from a Win32 GUI PE on sotOs (hwnd=%p)\n", (void*)h); fflush(stdout);
  ShowWindow(h, SW_SHOW); UpdateWindow(h);
  for (int i = 0; i < 60; i++){
    MSG msg;
    while (PeekMessageA(&msg, 0, 0, 0, PM_REMOVE)){ TranslateMessage(&msg); DispatchMessageA(&msg); }
    Sleep(16);
  }
  fputs("[gui] presented · destroying window\n", stdout); fflush(stdout);
  DestroyWindow(h);
  return 0;
}
EOF
x86_64-w64-mingw32-gcc -O2 -o /art/hello_gui.exe /tmp/hello_gui.c -lgdi32 -luser32
# 2) the minimal loader-side + PE subset (x86_64 only)
mkdir -p /out/lib/wine/x86_64-unix /out/lib/wine/x86_64-windows /out/bin /out/share/wine/nls
cp -a /usr/lib/wine/x86_64-unix/*.so            /out/lib/wine/x86_64-unix/
cp -a /usr/bin/wineserver /usr/bin/wine /usr/bin/wine-preloader /out/bin/ 2>/dev/null || true
# NLS data · ntdll reads these at init from <bindir>/../share/wine/nls.  The full
# set is ~10 MiB (76 codepage tables for every language); a console run needs only
# locale.nls + l_intl.nls + the common ANSI/OEM codepages — ~1 MiB, which fits the
# sysroot region.  (Add more c_*.nls here if a guest needs other codepages.)
#   c_20127.nls (US-ASCII) is REQUIRED by the msvcrt.dll DllMain: wine resolves the
#   default "C" locale to codepage 20127, and without the table msvcrt fails to
#   initialize (run25: wineboot.exe → "msvcrt.dll failed to initialize", c0000142).
#   c_28591 (ISO-8859-1 / Latin-1) rounds out the common single-byte set.
#   normnfc.nls is the Unicode NFC normalization table (ntdll RtlNormalizeString).
#   (UTF-8 / cp65001 has no table — wine handles it algorithmically, no c_65001.nls.)
mkdir -p /out/share/wine/nls
NLSDIR=/usr/share/wine/nls
[ -d "$NLSDIR" ] || NLSDIR=/usr/lib/wine/nls   # alpine layout may vary
for n in locale.nls l_intl.nls sortdefault.nls normnfc.nls \
         c_20127.nls c_1252.nls c_1250.nls c_1251.nls c_437.nls c_850.nls c_28591.nls; do
  cp -a "$NLSDIR/$n" /out/share/wine/nls/ 2>/dev/null || true   # nls is optional · never abort
done
# core console PE dlls (+ a few likely transitive deps; the real closure is
# resolved at first run — this is the seed set to iterate from).
# apisetschema.dll is NOT a normal dll — it is the API-Set schema map that the
# UNIX ntdll loads at process init (load_apiset_dll); without it the loader logs
# "failed to load apiset" and peb->ApiSetMap stays NULL.  Real wine always ships
# it, so it must be staged for the spawned wineboot PE process_init.
for d in ntdll kernel32 kernelbase msvcrt win32u sechost ucrtbase combase \
         advapi32 rpcrt4 setupapi version apisetschema ws2_32 \
         userenv cfgmgr32 sspicli powrprof winsta wtsapi32 \
         ole32 coml2 oleaut32 shell32 shlwapi shcore \
         user32 gdi32 comctl32 imm32 \
         crypt32 secur32 bcrypt ncrypt wintrust \
         iphlpapi dnsapi netapi32 nsi; do
  f=/usr/lib/wine/x86_64-windows/$d.dll
  [ -f "$f" ] && cp -a "$f" /out/lib/wine/x86_64-windows/
done
# ^ The post-ntdll/kernel32 block is the wine SERVICE-STACK + SHELL closure
# (run31: services.exe needs userenv.dll, wineboot delay-loads shell32.dll →
# SHGetFolderPathW).  shell32 pulls the GUI base (user32/gdi32/comctl32/ole32/
# oleaut32/shlwapi/shcore); the rest cover services.exe/rpcss/plugplay (RPC/COM,
# crypto, net).  ~29 MiB of x86_64-windows PEs total — fits the sysroot region.
# wineboot init chain · the .exe PE builtins wine spawns for a fresh prefix
# (alpine wine ships these as pure PEs in x86_64-windows · no x86_64-unix .so).
# wineboot.exe (the new_process target for prefix --init) + start.exe (the
# launcher fallback) are the immediate needs; the rest are the wineboot
# service-chain spawns — staged ahead so the closure iterates fewer times.
for e in wineboot start services explorer plugplay svchost rpcss winedevice \
         conhost cmd rundll32; do
  f=/usr/lib/wine/x86_64-windows/$e.exe
  [ -f "$f" ] && cp -a "$f" /out/lib/wine/x86_64-windows/
done
echo "[stage] subset assembled" 1>&2
# emit the assembled tree as a single tar on the REAL stdout (fd3): out/ + art/
tar -cf - -C / out art 1>&3
' > "$TARBALL"
echo "[wine-stage] unpacking the staged tree onto the host…"
tar -xf "$TARBALL" -C "$STAGE" --strip-components=1 out      # out/...  → $STAGE/...
tar -xf "$TARBALL" -C "$ART"   --strip-components=1 art      # art/hello.exe → $ART/hello.exe
echo "[wine-stage] sizes:"
du -sh "$STAGE" "$STAGE"/lib/wine/x86_64-unix "$STAGE"/lib/wine/x86_64-windows 2>/dev/null || true
ls -l "$ART"/hello.exe
echo "[wine-stage] done · subset in $STAGE (gitignored) · test PE in $ART/hello.exe"
echo "[wine-stage] NEXT (M1 integration): grow the sysroot region + ship this subset,"
echo "             wire a spawn path (wine64 loader + wineserver), pre-bake a minimal"
echo "             wineprefix, then iterate the dll closure from the first-run errors."
