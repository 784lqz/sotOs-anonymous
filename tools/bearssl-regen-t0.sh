#!/usr/bin/env bash
# Regenerate external/bearssl/src/ssl/ssl_hs_server.c from the .t0 source via
# the vendored T0 compiler (T0Comp.cs), run in a podman mono container — no
# host .NET/Mono needed. The generated .c is a T0 bytecode array (not
# hand-editable), so any change to ssl_hs_server.t0 must be followed by this.
#
# The recipe mirrors BearSSL's own mk/mkT0.sh + mk/Rules.mk:325-327. Verified
# (arc-gamma PoC) to regenerate the upstream .c byte-identically from the
# unchanged .t0, so the only diff is the intended .t0 change.
#
# Usage: tools/bearssl-regen-t0.sh
set -euo pipefail
cd "$(dirname "$0")/.." || exit 2
BS="$PWD/external/bearssl"
command -v podman >/dev/null || { echo "[regen] podman required"; exit 2; }
[ -f "$BS/src/ssl/ssl_hs_server.t0" ] || { echo "[regen] no external/bearssl — run bootstrap.sh first"; exit 2; }

OUT="$BS/src/ssl/ssl_hs_server.c"
TMP="$OUT.regen.$$"
# :z = Fedora SELinux relabel for the rootless bind-mount.
if podman run --rm -v "$BS:/bs:ro,z" docker.io/library/mono:latest sh -c '
    set -e
    cp -r /bs /work && cd /work
    mono-csc /out:T0Comp.exe /main:T0Comp /res:T0/kern.t0,t0-kernel T0/*.cs >/dev/null
    mono T0Comp.exe -o src/ssl/ssl_hs_server -r br_ssl_hs_server \
        src/ssl/ssl_hs_common.t0 src/ssl/ssl_hs_server.t0 >/dev/null
    cat src/ssl/ssl_hs_server.c
' > "$TMP" && [ -s "$TMP" ] && head -1 "$TMP" | grep -q .; then
    mv "$TMP" "$OUT"
    echo "[regen] ssl_hs_server.c regenerated ($(wc -l < "$OUT") lines)"
else
    rm -f "$TMP"
    echo "[regen] FAILED — ssl_hs_server.c left unchanged"; exit 1
fi
