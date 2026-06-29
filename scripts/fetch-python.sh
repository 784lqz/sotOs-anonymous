#!/usr/bin/env bash
# scripts/fetch-python.sh
#
# L11-β-2 / δ-2 · Acquire the static CPython 3.12 binary (the runtime python
# demo loads it from the sotfs binstore) AND seed the stdlib cache consumed by
# build-python-stdlib-zip.sh — ONE download of the python-build-standalone
# tarball serves both. Idempotent: skips whatever is already in place.
#
#   binary       → external/python/python3.12-static   (stripped, ~24 MB)
#   stdlib cache → external/python/install/lib/python3.12
#
# Decompression: the zstd CLI when available, else Python >= 3.14's stdlib
# zstd support (PEP 784) — so this runs on a fresh Ubuntu/WSL before
# bootstrap has installed zstd.
#
# Provenance (δ-1 reference, see src/test/LucAs_python/CMakeLists.txt):
#   release 20260510 · cpython-3.12.13 x86_64-unknown-linux-musl lto+static-full
#   stripped-binary sha256: 9a5ea4d5431896b1a9778cacf61f42bc7966d0e1b9703959ddce2215ba5fcfff
#   (a differing local binutils/strip produces different bytes — warn, not fatal)

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PY_BIN="$REPO_ROOT/external/python/python3.12-static"
STDLIB_CACHE="$REPO_ROOT/external/python/install/lib/python3.12"
URL='https://github.com/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.12.13%2B20260510-x86_64-unknown-linux-musl-lto%2Bstatic-full.tar.zst'
REF_SHA="9a5ea4d5431896b1a9778cacf61f42bc7966d0e1b9703959ddce2215ba5fcfff"

log()  { printf '\033[1;34m[fetch-python]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }

if [[ -f "$PY_BIN" && -d "$STDLIB_CACHE" ]]; then
    log "python3.12-static + stdlib cache ya presentes · nada que hacer"
    exit 0
fi

command -v curl >/dev/null || die "curl no encontrado"

TMP=$(mktemp -d -t sotos-pyfetch-XXXXXX)
trap 'rm -rf "$TMP"' EXIT

log "descargando python-build-standalone 20260510 (~30 MB)..."
curl -sSL -o "$TMP/cpython.tar.zst" "$URL"

log "extrayendo..."
if command -v zstd >/dev/null 2>&1; then
    zstd -d -q "$TMP/cpython.tar.zst" -o "$TMP/cpython.tar"
    tar xf "$TMP/cpython.tar" -C "$TMP"
else
    python3 - "$TMP" <<'EOF'
import sys, tarfile
from compression import zstd   # Python >= 3.14 (PEP 784)
tmp = sys.argv[1]
with zstd.open(f"{tmp}/cpython.tar.zst", "rb") as zf:
    with tarfile.open(fileobj=zf, mode="r|") as t:
        t.extractall(tmp, filter="data")
EOF
fi

test -f "$TMP/python/install/bin/python3.12" \
    || die "layout inesperado del tarball · falta python/install/bin/python3.12"

if [[ ! -f "$PY_BIN" ]]; then
    mkdir -p "$(dirname "$PY_BIN")"
    strip -o "$PY_BIN" "$TMP/python/install/bin/python3.12"
    chmod +x "$PY_BIN"
    GOT_SHA=$(sha256sum "$PY_BIN" | awk '{print $1}')
    log "python3.12-static · $(stat -c %s "$PY_BIN") bytes · sha256=$GOT_SHA"
    if [[ "$GOT_SHA" == "$REF_SHA" ]]; then
        log "sha256 coincide con la referencia δ-1"
    else
        log "AVISO: sha256 difiere de la referencia δ-1 (esperable con otro binutils/strip)"
    fi
fi

if [[ ! -d "$STDLIB_CACHE" ]]; then
    mkdir -p "$(dirname "$STDLIB_CACHE")"
    mv "$TMP/python/install/lib/python3.12" "$STDLIB_CACHE"
    log "stdlib cacheada · build-python-stdlib-zip.sh la encontrará sin re-descargar"
fi

log "listo · 'just build' empaqueta python en sotfs.img (binstore + stdlib zip)"
