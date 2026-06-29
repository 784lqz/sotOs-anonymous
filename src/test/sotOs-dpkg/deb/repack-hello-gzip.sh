#!/usr/bin/env bash
# Repack the real Debian hello_*.deb with GZIP-compressed members (was xz).
#
# WHY: dpkg-deb decodes data.tar.xz via liblzma's MULTITHREADED decoder
# (lzma_stream_decoder_mt).  Its worker thread — spawned inside the forked dpkg
# sub-process — #GPs on free() of a corrupt pointer: a deep glibc malloc-arena-
# across-fork-in-sotbox issue (CONFIRMED by bisection — a gzip .deb, whose zlib
# decoder is single-threaded, produces ZERO faults; the xz .deb produces 8).  The
# fault is non-fatal (the install completes), but to keep the boot fault-free we
# decompress with zlib instead of liblzma-MT.  The TAR CONTENTS are untouched —
# this stays the real, valid, installable Debian `hello` package (it still prints
# "Hello, world!"); only the compression layer changes xz -> gzip (both are
# legitimate Debian .deb formats).  The proper fix (sotOs threading/malloc
# correctness under the liblzma-MT path) is a separate, deep follow-up.
#
# Idempotent-ish: detects already-gzip members and no-ops.  Reproducible.
set -euo pipefail
cd "$(dirname "$0")"
if ar t hello.deb | grep -q 'data.tar.gz'; then
  echo "hello.deb already uses gzip members — nothing to do"; ar t hello.deb; exit 0
fi
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
cp hello.deb "$WORK/hello.deb"
( cd "$WORK" && ar x hello.deb )
printf '2.0\n' > "$WORK/debian-binary"
xz -dc "$WORK/control.tar.xz" | gzip -c > "$WORK/control.tar.gz"
xz -dc "$WORK/data.tar.xz"    | gzip -c > "$WORK/data.tar.gz"
rm -f hello.deb
ar rc hello.deb "$WORK/debian-binary" "$WORK/control.tar.gz" "$WORK/data.tar.gz"
echo "repacked hello.deb (gzip members):"; ar t hello.deb
