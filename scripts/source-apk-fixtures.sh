#!/usr/bin/env bash
# Source the real Alpine 3.20 apk.static + signing keys + a tiny no-dep .apk
# fixture into src/test/sotOs-apk/. Repo-reproducible: run once and commit the
# outputs. The binstore + canary base bake the committed bytes at build time;
# the build does NOT call podman. Mirrors the sotOs-curl fixture layout.
#
# Usage:  bash scripts/source-apk-fixtures.sh
#         RT=docker bash scripts/source-apk-fixtures.sh
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

OUT="src/test/sotOs-apk"
IMG="alpine:3.20"
RT="${RT:-podman}"

mkdir -p "$OUT/bin" "$OUT/keys" "$OUT/deb" "$OUT/strace"

# ---------------------------------------------------------------------------
# Step 1: apk.static + signing keys from an alpine:3.20 container
# ---------------------------------------------------------------------------
echo "[source-apk] pulling $IMG ..."
"$RT" pull "$IMG" >/dev/null 2>&1 || true

echo "[source-apk] extracting apk.static + signing keys ..."
cid="$("$RT" create "$IMG" sh -c true)"
cleanup1() { "$RT" rm -f "$cid" >/dev/null 2>&1 || true; }
trap cleanup1 EXIT

# The base alpine:3.20 image ships /sbin/apk.static in the apk-tools-static
# package. Try copying it directly; if absent (some minimal builds), install it.
"$RT" cp "$cid":/sbin/apk.static "$OUT/bin/apk.static" 2>/dev/null || true

if [ ! -s "$OUT/bin/apk.static" ]; then
    echo "[source-apk] apk.static not in base image — installing apk-tools-static ..."
    trap - EXIT
    "$RT" rm -f "$cid" >/dev/null 2>&1 || true

    cid="$("$RT" run -d "$IMG" sh -c \
        'apk add --no-cache apk-tools-static >/dev/null 2>&1; sleep 60')"
    trap cleanup1 EXIT
    sleep 2
    "$RT" exec "$cid" sh -c 'cp /sbin/apk.static /tmp/apk.static'
    "$RT" cp "$cid":/tmp/apk.static "$OUT/bin/apk.static"
fi

chmod 755 "$OUT/bin/apk.static"

# Keys: Alpine 3.20 ships /etc/apk/keys/*.rsa.pub (usually 2-3 PEM files).
echo "[source-apk] copying signing keys ..."
"$RT" exec "$cid" sh -c 'ls /etc/apk/keys/' | while read -r k; do
    "$RT" cp "$cid":/etc/apk/keys/"$k" "$OUT/keys/$k"
done

# Pin a stable fixed symbol name: pick the Alpine 3.20 primary key.
# The main/community packages are signed by alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub
# (the 3.20 era key). We copy whatever key file(s) are present and create a
# stable symlink/copy alpine-3.20.rsa.pub pointing at the correct one.
PRIMARY_KEY=""
# Prefer the 6165ee59 key (alpine 3.10-3.20 era) then the 4a6a0840 key (3.17+).
for candidate in alpine-devel@lists.alpinelinux.org-6165ee59.rsa.pub \
                 alpine-devel@lists.alpinelinux.org-4a6a0840.rsa.pub; do
    if [ -f "$OUT/keys/$candidate" ]; then
        PRIMARY_KEY="$candidate"
        break
    fi
done
# Fallback: pick any .rsa.pub
if [ -z "$PRIMARY_KEY" ]; then
    PRIMARY_KEY="$(ls "$OUT/keys/"*.rsa.pub 2>/dev/null | head -1 | xargs -I{} basename {})"
fi
if [ -n "$PRIMARY_KEY" ] && [ "$PRIMARY_KEY" != "alpine-3.20.rsa.pub" ]; then
    cp "$OUT/keys/$PRIMARY_KEY" "$OUT/keys/alpine-3.20.rsa.pub"
    echo "[source-apk] pinned primary key: $PRIMARY_KEY → alpine-3.20.rsa.pub"
fi

trap - EXIT
"$RT" rm -f "$cid" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Step 2: A tiny TRULY-no-dependency .apk fixture (data-only)
# ---------------------------------------------------------------------------
# CRITICAL: the fixture MUST have NO shared-library (so:) dependencies. The canary
# base seeds an EMPTY apk DB, so apk's solver cannot satisfy any so:libc.musl /
# so:libreadline / etc. — a package like "bc" FAILS with "unable to select
# packages: so:libc.musl-x86_64.so.1 (no such package)". Only data-only packages
# (terminfo/tzdata/mailcap — no ELF, no so: deps) install cleanly against an empty
# DB with `apk --no-network add --allow-untrusted --force-non-repository <file>`.
# (An installed-BINARY-runs proof is covered separately by apk-upperexec-gate.sh.)
# Candidates (Alpine 3.20/main), ordered by preference (all verified no-dep):
#   1. "ncurses-terminfo-base" — ~22KB, ships etc/terminfo/* data files.
#   2. "mailcap" / "tzdata" — data-only fallbacks.
echo "[source-apk] fetching a tiny no-dependency .apk fixture ..."
cid="$("$RT" run -d "$IMG" sh -c 'sleep 120')"
trap 'rt_rm() { "$RT" rm -f "$cid" >/dev/null 2>&1 || true; }; rt_rm' EXIT

"$RT" exec "$cid" sh -c 'apk update >/dev/null 2>&1 || true'

# Try no-dep data packages in preference order (the first that fetches wins).
FETCHED_PKG=""
for pkg in ncurses-terminfo-base mailcap tzdata; do
    if "$RT" exec "$cid" sh -c "
        mkdir -p /pkgcache
        apk fetch --no-cache -o /pkgcache $pkg >/dev/null 2>&1 && ls /pkgcache/${pkg}-*.apk >/dev/null 2>&1
    "; then
        FETCHED_PKG="$pkg"
        echo "[source-apk] fetched package: $pkg"
        break
    fi
done

if [ -z "$FETCHED_PKG" ]; then
    echo "[source-apk] ERROR: could not fetch any candidate package" >&2
    exit 1
fi

"$RT" exec "$cid" sh -c "cp \$(ls -1 /pkgcache/${FETCHED_PKG}-*.apk | head -1) /fixture.apk"
"$RT" cp "$cid":/fixture.apk "$OUT/deb/fixture.apk"

trap - EXIT
"$RT" rm -f "$cid" >/dev/null 2>&1 || true

# ---------------------------------------------------------------------------
# Step 3: Summary
# ---------------------------------------------------------------------------
echo ""
echo "=== src/test/sotOs-apk/ ==="
ls -la "$OUT/bin/" "$OUT/keys/" "$OUT/deb/"
echo ""
echo "=== file + ldd ==="
file "$OUT/bin/apk.static"
ldd "$OUT/bin/apk.static" 2>&1 || true
echo ""
echo "=== fixture.apk contents (first 20 entries) ==="
tar -tzf "$OUT/deb/fixture.apk" 2>/dev/null | head -20 || true
echo ""
echo "[source-apk] DONE — commit: git add src/test/sotOs-apk scripts/source-apk-fixtures.sh"
