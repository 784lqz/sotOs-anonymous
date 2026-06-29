#!/usr/bin/env bash
# Source the real Debian trixie apt toolchain (apt/apt-get/apt-cache + libapt
# closure + transport methods + gpgv + archive keyring) into src/test/sotOs-apt/.
# Repo-reproducible: run ONCE and commit the outputs. The build bakes the committed
# bytes (binstore + sysroot + honey base); the build does NOT call podman.
# Mirrors scripts/source-apk-fixtures.sh.
#   Usage:  bash scripts/source-apt-fixtures.sh   [RT=docker]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

OUT="src/test/sotOs-apt"
IMG="debian:13-slim"
RT="${RT:-podman}"
mkdir -p "$OUT/bin" "$OUT/lib" "$OUT/methods" "$OUT/keyrings" "$OUT/etc/apt/apt.conf.d" "$OUT/strace"

echo "[source-apt] pulling $IMG ..."
"$RT" pull "$IMG" >/dev/null 2>&1 || true

# Run a container that installs apt's full closure (apt is in the base, but ensure
# gpgv + the archive keyring are present), then we copy the resolved files out.
cid="$("$RT" run -d "$IMG" sh -c 'apt-get update >/dev/null 2>&1 || true; \
        apt-get install -y --no-install-recommends gpgv debian-archive-keyring >/dev/null 2>&1 || true; \
        sleep 120')"
cleanup() { "$RT" rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup EXIT
sleep 3

# Binaries (apt frontends + gpgv).
for b in /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config /usr/bin/gpgv; do
    "$RT" cp "$cid":"$b" "$OUT/bin/$(basename "$b")"
done

# Transport methods (apt's libexec).
for m in http gpgv store copy; do
    "$RT" cp "$cid":/usr/lib/apt/methods/"$m" "$OUT/methods/$m" 2>/dev/null \
        || echo "[source-apt] WARN method $m absent"
done

# Archive keyring (used only in Phase 3, staged now).
"$RT" cp "$cid":/usr/share/keyrings/debian-archive-keyring.gpg "$OUT/keyrings/" 2>/dev/null \
    || "$RT" cp "$cid":/etc/apt/trusted.gpg.d/debian-archive-keyring.gpg "$OUT/keyrings/" 2>/dev/null \
    || echo "[source-apt] WARN archive keyring absent"

# Resolve the FULL .so closure of every binary + method via ldd, copy each unique lib.
echo "[source-apt] resolving lib closure via ldd ..."
"$RT" exec "$cid" sh -c '
    for f in /usr/bin/apt /usr/bin/apt-get /usr/bin/apt-cache /usr/bin/apt-config \
             /usr/bin/gpgv /usr/lib/apt/methods/http /usr/lib/apt/methods/gpgv \
             /usr/lib/apt/methods/store /usr/lib/apt/methods/copy; do
        ldd "$f" 2>/dev/null | awk "{print \$3}" | grep -E "^/"
    done | sort -u' > /tmp/apt-libs.txt
while read -r lib; do
    [ -n "$lib" ] || continue
    "$RT" cp "$cid":"$lib" "$OUT/lib/$(basename "$lib")" 2>/dev/null || true
done < /tmp/apt-libs.txt

chmod 755 "$OUT/bin/"* "$OUT/methods/"* 2>/dev/null || true
echo "[source-apt] done. Binaries:"; ls -la "$OUT/bin" "$OUT/methods" "$OUT/lib" | sed 's/^/[source-apt]   /'
echo "[source-apt] NOTE: the interpreter is the in-tree glibc ld-linux (already staged by the dpkg arc) — verify the apt binaries' PT_INTERP matches /lib64/ld-linux-x86-64.so.2."
