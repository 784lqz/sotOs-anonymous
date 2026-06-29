#!/usr/bin/env bash
# sotOs · Wine M1 · bake a MINIMAL, version-matched wineprefix in alpine:3.20.
#
# `wine hello.exe` against a FRESH prefix triggers the heavy wineboot bootstrap
# (which needs new_process + start.exe/services.exe — a deep rabbit hole).  A
# prefix that wine considers ALREADY initialized (its .update-timestamp matches
# the wine build + the registry hives load) makes wine SKIP wineboot and run the
# target directly in the launcher process.  Bake that prefix here, with the SAME
# wine our subset is staged from, so the version markers match exactly.
#
# Runtime-agnostic (podman or docker) and self-locating (no git dependency) so it
# runs from either the Ubuntu build distro or the podman-machine-default distro.
set -euo pipefail
SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SELF/.." && pwd)"
OUT="$REPO/build/wine-prefix-bake"
rm -rf "$OUT"; mkdir -p "$OUT"

if command -v podman >/dev/null 2>&1; then RT=podman
elif command -v docker >/dev/null 2>&1; then RT=docker
else echo "[bake] no podman/docker found" >&2; exit 1; fi
echo "[bake] runtime=$RT · out=$OUT"

"$RT" run --rm -v "$OUT":/out \
  docker.io/library/alpine:3.20 sh -c '
set -e
apk add --quiet wine >/dev/null 2>&1
export WINEPREFIX=/root/.wp HOME=/root WINEDEBUG=-all
export WINEDLLOVERRIDES="mscoree=d;mshtml=d"
timeout 180 wineboot --init >/dev/null 2>&1 || true
timeout 60  wineserver -w        >/dev/null 2>&1 || true
timeout 30  wineserver -k        >/dev/null 2>&1 || true
echo "[bake] prefix contents:"; ls -la /root/.wp 2>/dev/null || echo "(no prefix dir!)"
echo "[bake] sizes:"; wc -c /root/.wp/*.reg /root/.wp/.update-timestamp 2>/dev/null || true
# The wine INSTALL timestamp (what wine compares the prefix timestamp against).
cp -a /usr/share/wine/.update-timestamp /out/wine-install.update-timestamp 2>/dev/null || \
  find / -name .update-timestamp 2>/dev/null | head
for f in system.reg user.reg userdef.reg .update-timestamp; do
  [ -f "/root/.wp/$f" ] && cp -a "/root/.wp/$f" "/out/$f" || true
done
echo "[bake] captured:"; ls -la /out
'
# Stage the baked hives into the sysroot share tree so the sotfs-img build packs
# them at /usr/share/wine/baseprefix/ (read-only), where the runtime baked-prefix
# seeder (lucas_seed_baked_wineprefix) copies them into the writable /.wine graph.
# Also stage the install .update-timestamp at /usr/share/wine/.update-timestamp.
SR="$REPO/build/wine-sysroot/share/wine"
if [ -d "$REPO/build/wine-sysroot" ]; then
    mkdir -p "$SR/baseprefix"
    for f in system.reg user.reg userdef.reg .update-timestamp; do
        [ -f "$OUT/$f" ] && cp -f "$OUT/$f" "$SR/baseprefix/$f"
    done
    [ -f "$OUT/.update-timestamp" ] && cp -f "$OUT/.update-timestamp" "$SR/.update-timestamp"
    echo "[bake] staged baseprefix into $SR/baseprefix (packed read-only at /usr/share/wine/baseprefix)"
fi
echo "[bake] done · artifacts in $OUT"
ls -la "$OUT"
