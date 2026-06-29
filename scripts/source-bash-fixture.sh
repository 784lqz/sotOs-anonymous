#!/usr/bin/env bash
# sotOs · source the musl Alpine bash + its .so closure from alpine:3.20.
#
# The Tier-2 SSH honey login shell is a musl-linked Alpine bash (NOT glibc
# debian-bash) so the Alpine persona is coherent — a real Alpine box has NO
# /lib/x86_64-linux-gnu glibc multiarch dir, and a musl bash loads its libs
# from /usr/lib (libreadline.so.8) + /lib (libncursesw.so.6), all coherent.
#
# Produces (committed · hermetic build, like sotOs-apk):
#   src/test/sotOs-bash/bin/alpine-bash            (real musl bash ELF, ~756KB)
#   src/test/sotOs-bash/lib/libreadline.so.8.2     (real ET_DYN)
#   src/test/sotOs-bash/lib/libncursesw.so.6       (real ET_DYN, musl build)
set -euo pipefail
RT="${RT:-podman}"
cd "$(git rev-parse --show-toplevel)"
D=src/test/sotOs-bash
mkdir -p "$D/bin" "$D/lib"

# Run a long-lived container, install bash inside it, copy the closure out.
cid=$("$RT" run -d alpine:3.20 sh -c 'apk add -q bash; sleep 60')
trap '"$RT" rm -f "$cid" >/dev/null 2>&1 || true' EXIT
# Wait for apk add to finish (bash to appear).
for _ in $(seq 1 30); do
    "$RT" exec "$cid" sh -c 'test -x /bin/bash' 2>/dev/null && break
    sleep 1
done
"$RT" exec "$cid" sh -c 'test -x /bin/bash' || { echo "FATAL: bash never installed" >&2; exit 1; }

"$RT" cp "$cid":/bin/bash "$D/bin/alpine-bash"
# libreadline real ET_DYN (the .8 soname is a symlink → .8.2).
"$RT" cp "$cid":/usr/lib/libreadline.so.8.2 "$D/lib/libreadline.so.8.2"
# libncursesw real ET_DYN.  Resolve the real file behind the soname (it may be a
# symlink chain libncursesw.so.6 → libncursesw.so.6.x); copy the dereferenced file.
real_ncurses=$("$RT" exec "$cid" sh -c 'readlink -f /usr/lib/libncursesw.so.6 2>/dev/null || readlink -f /lib/libncursesw.so.6')
"$RT" cp "$cid":"$real_ncurses" "$D/lib/libncursesw.so.6"

echo "=== sourced fixture ==="
file "$D"/bin/alpine-bash "$D"/lib/* || true
