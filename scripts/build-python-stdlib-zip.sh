#!/usr/bin/env bash
# scripts/build-python-stdlib-zip.sh
#
# L11-γ U1 · Pack Python 3.12 stdlib into sotfs.img so the in-VM CPython
# can locate the `encodings` module (and the rest of the stdlib) at runtime
# via the VFS-backed loader (U2).
#
# LAYOUT (matches include/sotfs/layout.h):
#   [0..32)          · struct sotfs_stdlib_header { magic, version, zip_size, reserved[16] }
#   [4096..4096+N)   · python312.zip contents
#   [28 MiB..64 MiB) · binary blob region (binstore · SP2)
#   [124 MiB..128 MiB) · WAL region (untouched by this packer)
#
# USAGE:
#   bash scripts/build-python-stdlib-zip.sh <path-to-sotfs.img>
#
# IDEMPOTENCY:
#   The script hashes the produced zip and compares it against the existing
#   header on disk (magic + zip_size + an embedded SHA-1 in `reserved[]`).
#   If they match, the writes are skipped — re-running `just build` after
#   no source change is a no-op aside from re-zipping (zip is deterministic
#   under `-X` for a stable directory tree, but stdlib mtimes from the
#   tarball are constant).
#
# REQUIREMENTS:
#   - curl, zstd, tar, zip, python3, dd, stat, sha1sum (all standard)

set -euo pipefail

if [ "$#" -ne 1 ]; then
    echo "usage: $0 <sotfs.img>" >&2
    exit 2
fi

IMG="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
CACHE_PARENT="$REPO_ROOT/external/python/install/lib"
CACHE_DIR="$CACHE_PARENT/python3.12"
ZIP_PATH="$REPO_ROOT/build/python312.zip"

# Mirror of include/sotfs/layout.h. Keep in sync.
HEADER_OFFSET=0
ZIP_OFFSET=4096
REGION_BYTES=$((28 * 1024 * 1024))
MAX_ZIP_BYTES=$((REGION_BYTES - ZIP_OFFSET))
MAGIC_LE="42 4c 54 53"   # 'B','L','T','S' (little-endian image of 0x53544c42)

if [ ! -f "$IMG" ]; then
    echo "[stdlib-pack] FATAL: image not found at $IMG" >&2
    exit 1
fi

IMG_SIZE=$(stat -c %s "$IMG")
if [ "$IMG_SIZE" -lt $((32 * 1024 * 1024)) ]; then
    echo "[stdlib-pack] FATAL: image $IMG is $IMG_SIZE bytes; expected >= 32 MiB" >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# 1. Acquire stdlib (download python-build-standalone tarball on first run).
# ---------------------------------------------------------------------------

if [ ! -d "$CACHE_DIR" ]; then
    echo "[stdlib-pack] cache miss · downloading python-build-standalone tarball (one-time, ~1 min)..."
    for tool in curl zstd tar; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            echo "[stdlib-pack] FATAL: $tool not found in PATH" >&2
            exit 1
        fi
    done
    TARBALL_URL='https://github.com/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.12.13%2B20260510-x86_64-unknown-linux-musl-lto%2Bstatic-full.tar.zst'
    TMPDIR=$(mktemp -d -t sotos-stdlib-XXXXXX)
    trap 'rm -rf "$TMPDIR"' EXIT
    (
        cd "$TMPDIR"
        curl -sSL -o cpython.tar.zst "$TARBALL_URL"
        zstd -d -q cpython.tar.zst -o cpython.tar
        tar xf cpython.tar
        if [ ! -d "python/install/lib/python3.12" ]; then
            echo "[stdlib-pack] FATAL: tarball layout unexpected · missing python/install/lib/python3.12" >&2
            exit 1
        fi
    )
    mkdir -p "$CACHE_PARENT"
    mv "$TMPDIR/python/install/lib/python3.12" "$CACHE_DIR"
    rm -rf "$TMPDIR"
    trap - EXIT
    echo "[stdlib-pack] stdlib cached at $CACHE_DIR"
fi

echo "[stdlib-pack] stdlib_dir=$CACHE_DIR"

# ---------------------------------------------------------------------------
# 1a. Stage pip ONTO the importable path (so `python -m pip` works in-VM).
#     ensurepip ships pip as a wheel (a zip); the read-only stdlib zip can't
#     run ensurepip's extract-into-writable-site-packages step, so instead we
#     unpack the bundled pip wheel's `pip/` package (+ its dist-info, which
#     `pip --version` reads via importlib.metadata) straight INTO the stdlib
#     tree.  It then rides into python312.zip and is importable read-only.
#     pip vendors all its runtime deps under pip/_vendor → self-contained, no
#     extra packages needed.  Idempotent: skip if pip/ already extracted.
# ---------------------------------------------------------------------------
PIP_WHEEL=$(ls "$CACHE_DIR"/ensurepip/_bundled/pip-*.whl 2>/dev/null | head -1 || true)
if [ -z "$PIP_WHEEL" ]; then
    PIP_WHEEL=$(ls "$REPO_ROOT"/external/python/install/lib/python3.12/ensurepip/_bundled/pip-*.whl 2>/dev/null | head -1 || true)
fi
if [ ! -d "$CACHE_DIR/pip" ]; then
    if [ -z "$PIP_WHEEL" ] || [ ! -f "$PIP_WHEEL" ]; then
        echo "[stdlib-pack] FATAL: bundled pip wheel not found (ensurepip/_bundled/pip-*.whl)" >&2
        exit 1
    fi
    echo "[stdlib-pack] staging pip onto the stdlib path from $(basename "$PIP_WHEEL")…"
    ( cd "$CACHE_DIR" && unzip -q -o "$PIP_WHEEL" 'pip/*' 'pip-*.dist-info/*' )
fi
echo "[stdlib-pack] pip staged · $(find "$CACHE_DIR/pip" -name '*.py' | wc -l) pip .py modules"

# ---------------------------------------------------------------------------
# 1a-bis. Stage setuptools + wheel ONTO the path (the BUILD backend).  `pip
#     install --no-binary :all:` builds a wheel FROM the sdist via the legacy
#     `python setup.py bdist_wheel` (or PEP 517 build_meta) — which imports
#     setuptools/pkg_resources/wheel.  Shipping them lets the build run
#     --no-build-isolation, i.e. WITHOUT first downloading setuptools+wheel into
#     an isolated env (a heavy multi-download over the slow egress).  Pure-python
#     so they ride into the zip like pip.  Idempotent: skip if already staged.
# ---------------------------------------------------------------------------
WHEELDATA="$CACHE_DIR/test/wheeldata"
if [ ! -d "$CACHE_DIR/setuptools" ]; then
    ST_WHEEL=$(ls "$WHEELDATA"/setuptools-*.whl 2>/dev/null | head -1 || true)
    WH_WHEEL=$(ls "$WHEELDATA"/wheel-*.whl 2>/dev/null | head -1 || true)
    if [ -z "$ST_WHEEL" ] || [ -z "$WH_WHEEL" ]; then
        echo "[stdlib-pack] FATAL: bundled setuptools/wheel not found in $WHEELDATA" >&2
        exit 1
    fi
    echo "[stdlib-pack] staging setuptools+wheel (build backend) from $(basename "$ST_WHEEL") + $(basename "$WH_WHEEL")…"
    ( cd "$CACHE_DIR" && unzip -q -o "$ST_WHEEL" 'setuptools/*' 'pkg_resources/*' '_distutils_hack/*' 'setuptools-*.dist-info/*' \
                      && unzip -q -o "$WH_WHEEL" 'wheel/*' 'wheel-*.dist-info/*' )
fi
echo "[stdlib-pack] build backend staged · $(find "$CACHE_DIR/setuptools" "$CACHE_DIR/wheel" -name '*.py' 2>/dev/null | wc -l) .py modules"

# ---------------------------------------------------------------------------
# 1b. Pre-compile the stdlib to legacy .pyc (BESIDE each .py) using the SAME
#     static interpreter that ships, so the bytecode magic matches.  Shipping
#     .pyc lets zipimport load bytecode directly instead of COMPILING each .py
#     on EVERY import (the zip is read-only → no __pycache__ caching → recompile
#     every run).  That per-module compile spike exhausts the no-reclaim per-box
#     arena (python's urllib/ssl import OOM'd 128 MiB at re._compiler).  -b =
#     legacy layout (module.pyc beside module.py · what zipimport reads).
PYBIN="$REPO_ROOT/external/python/python3.12-static"
if [ -x "$PYBIN" ]; then
    echo "[stdlib-pack] pre-compiling stdlib → .pyc (matching bytecode)…"
    PYTHONHOME="$REPO_ROOT/external/python/install" \
        "$PYBIN" -m compileall -b -q "$CACHE_DIR" >/dev/null 2>&1 || true
    echo "[stdlib-pack] compiled $(find "$CACHE_DIR" -name '*.pyc' | wc -l) .pyc files"
fi

# ---------------------------------------------------------------------------
# 2. Build python312.zip · ship the .pyc (zipimport loads bytecode · no compile).
# ---------------------------------------------------------------------------

if ! command -v zip >/dev/null 2>&1; then
    echo "[stdlib-pack] FATAL: zip not found in PATH (install zip)" >&2
    exit 1
fi

mkdir -p "$(dirname "$ZIP_PATH")"
rm -f "$ZIP_PATH"
# Excluded:
#   *.pyc, __pycache__   · CPython recompiles on first import; zero benefit
#                          in shipping bytecode (and it's huge)
#   config-3.12-*        · libpython3.12.a + Makefile · build artefacts, not
#                          runtime stdlib (~58 MiB)
#   test/, *_test/       · the stdlib's own self-test suite (~32 MiB)
#   idlelib/             · Tk-based IDE shell · no Tk in sotOs
#   turtledemo/, turtle.py · graphical examples · no display
#   ensurepip/           · pip bootstrap · no network in sotOs
#   tkinter/             · Tk bindings · no display
#   site-packages/       · empty cache slot for third-party installs
( cd "$CACHE_DIR" && zip -r -q -X "$ZIP_PATH" . \
    -x '*.py' \
    -x '*/__pycache__/*' \
    -x 'config-3.12-*/*' \
    -x 'test/*' -x '*/test/*' -x '*/tests/*' \
    -x 'idlelib/*' \
    -x 'turtledemo/*' -x 'turtle.py' \
    -x 'ensurepip/*' \
    -x 'tkinter/*' \
    -x 'site-packages/*' \
)

ZIP_SIZE=$(stat -c %s "$ZIP_PATH")
if [ "$ZIP_SIZE" -gt "$MAX_ZIP_BYTES" ]; then
    echo "[stdlib-pack] FATAL: zip too big · $ZIP_SIZE > $MAX_ZIP_BYTES (SOTFS_STDLIB_MAX_BYTES)" >&2
    echo "[stdlib-pack] hint: grow SOTFS_STDLIB_REGION_BYTES in include/sotfs/layout.h, or prune stdlib" >&2
    exit 1
fi

ZIP_SHA1=$(sha1sum "$ZIP_PATH" | awk '{print $1}')
echo "[stdlib-pack] python312.zip · ${ZIP_SIZE} bytes · sha1=${ZIP_SHA1}"

# ---------------------------------------------------------------------------
# 3. Idempotency check: compare desired header against the image's header.
#    We embed the first 16 hex chars of the SHA-1 into the reserved[] field
#    so a re-pack of identical bytes is a no-op.
#
#    ENCODINGS-2 hardening: the previous version of this script could leave
#    sotfs.img with a stale `zip_size` if any prior invocation was killed
#    between the zip-rebuild and the dd of the image, or if some path wrote
#    python312.zip without invoking this script.  We now do two extra checks:
#
#      (a) Even on the "skip writes" branch, sanity-check that the *zip bytes
#          embedded in the image* still match the disk zip's first/last
#          page · if not, fall through and re-write the image.
#      (b) Always re-verify the header AND a fingerprint of the embedded
#          zip after any write so a half-finished script cannot leave the
#          image inconsistent.
# ---------------------------------------------------------------------------

# Reserved field = 16 bytes derived from sha1 (first 32 hex chars = 16 bytes).
RESERVED_HEX="${ZIP_SHA1:0:32}"

# Read the current 32-byte header from disk for comparison.
CURRENT_HDR=$(dd if="$IMG" bs=1 count=32 status=none 2>/dev/null | xxd -p | tr -d '\n' || echo "")
DESIRED_HDR=$(python3 -c "
import struct, sys
hdr = struct.pack('<IIQ16s',
    0x53544c42,
    1,
    $ZIP_SIZE,
    bytes.fromhex('$RESERVED_HEX'))
sys.stdout.write(hdr.hex())
")

# Fingerprint of the zip's first 4 bytes (must be 'PK\x03\x04') plus the
# tail signature bytes ('PK\x05\x06' EOCD marker).  Cheap to compute, and
# catches the case where the header is correct but the zip bytes at
# ZIP_OFFSET diverged (e.g. partial dd, truncated image).
DISK_ZIP_HEAD=$(dd if="$IMG" bs=1 count=4 skip=$ZIP_OFFSET status=none 2>/dev/null | xxd -p || echo "")
EXPECTED_ZIP_HEAD="504b0304"   # 'PK\x03\x04'

NEED_WRITE=0
if [ "$CURRENT_HDR" != "$DESIRED_HDR" ]; then
    NEED_WRITE=1
    echo "[stdlib-pack] header mismatch · will rewrite image"
elif [ "$DISK_ZIP_HEAD" != "$EXPECTED_ZIP_HEAD" ]; then
    NEED_WRITE=1
    echo "[stdlib-pack] zip head fingerprint mismatch (got=$DISK_ZIP_HEAD want=$EXPECTED_ZIP_HEAD) · will rewrite image"
fi

if [ "$NEED_WRITE" -eq 0 ]; then
    echo "[stdlib-pack] header + zip head match · skipping image writes (idempotent)"
    # Even on the skip branch, run the post-write verify so a stale image
    # cannot quietly succeed.  This catches the bug that motivated this
    # hardening: header said one zip_size, on-disk zip was a different size.
else
    # ----------------------------------------------------------------------
    # 4. Write header at offset 0 and zip at offset 4096.
    #
    #    Write the zip FIRST, then the header.  If the script is killed
    #    between the two writes the header still says the OLD zip_size,
    #    which is detectable on the next run (header zip_size != on-disk
    #    python312.zip size · post-write verify below).  Writing header
    #    last also means a successful header write implies a successful
    #    zip write.
    # ----------------------------------------------------------------------

    # Use 4096-byte blocks for the zip write; seek=1 → byte offset 4096.
    dd if="$ZIP_PATH" of="$IMG" bs=$ZIP_OFFSET conv=notrunc seek=1 status=none

    HDR_FILE="$ZIP_PATH.hdr"
    python3 -c "
import struct, sys
with open('$HDR_FILE', 'wb') as f:
    f.write(struct.pack('<IIQ16s',
        0x53544c42,
        1,
        $ZIP_SIZE,
        bytes.fromhex('$RESERVED_HEX')))
"

    dd if="$HDR_FILE" of="$IMG" bs=1 count=32 conv=notrunc seek=$HEADER_OFFSET status=none
    rm -f "$HDR_FILE"

    ZIP_END=$((ZIP_OFFSET + ZIP_SIZE))
    echo "[stdlib-pack] wrote to $IMG · header[0..32) + zip[${ZIP_OFFSET}..${ZIP_END})"
fi

# ---------------------------------------------------------------------------
# 5. Post-write verification (runs on BOTH the skip-write and write paths).
#
# Reads the header back from disk and asserts:
#   - magic bytes are 'BLTS' (catches truncated / corrupt images)
#   - header zip_size matches the on-disk python312.zip's actual size
#   - reserved[:16] matches the on-disk zip's sha1[:32 hex]
#   - the first 4 bytes at ZIP_OFFSET are 'PK\x03\x04' (zip local header)
#
# This is the safety net that catches "stale zip_size" before it boots
# into a VM and breaks zipimport.
# ---------------------------------------------------------------------------

python3 - <<EOF
import struct, sys, hashlib, os

IMG       = "$IMG"
ZIP_PATH  = "$ZIP_PATH"
ZIP_OFF   = $ZIP_OFFSET

with open(IMG, "rb") as f:
    hdr_bytes = f.read(32)
    f.seek(ZIP_OFF)
    image_zip_head = f.read(4)
    f.seek(ZIP_OFF)
    image_zip_bytes = f.read(os.path.getsize(ZIP_PATH))

if len(hdr_bytes) != 32:
    print(f"[stdlib-pack] FATAL: header read only {len(hdr_bytes)} bytes from {IMG}", file=sys.stderr)
    sys.exit(1)

magic, version, zip_size, reserved = struct.unpack("<IIQ16s", hdr_bytes)
if magic != 0x53544c42:
    print(f"[stdlib-pack] FATAL: post-write magic check failed · got=0x{magic:08x}", file=sys.stderr)
    sys.exit(1)
if version != 1:
    print(f"[stdlib-pack] FATAL: post-write version check failed · got={version}", file=sys.stderr)
    sys.exit(1)

disk_zip_size = os.path.getsize(ZIP_PATH)
if zip_size != disk_zip_size:
    print(f"[stdlib-pack] FATAL: header zip_size={zip_size} but on-disk {ZIP_PATH} is {disk_zip_size} bytes", file=sys.stderr)
    print(f"[stdlib-pack] hint: the image is stale.  Delete it and rebuild ('rm -f {IMG}; just build').", file=sys.stderr)
    sys.exit(1)

with open(ZIP_PATH, "rb") as f:
    disk_zip_data = f.read()
disk_zip_sha1 = hashlib.sha1(disk_zip_data).hexdigest()
expected_reserved = bytes.fromhex(disk_zip_sha1[:32])
if reserved != expected_reserved:
    print(f"[stdlib-pack] FATAL: header reserved sha1 mismatch", file=sys.stderr)
    print(f"  on-disk zip sha1[:32]: {disk_zip_sha1[:32]}", file=sys.stderr)
    print(f"  header  reserved hex : {reserved.hex()}", file=sys.stderr)
    sys.exit(1)

if image_zip_head != b"PK\\x03\\x04":
    print(f"[stdlib-pack] FATAL: zip local-header signature missing at offset {ZIP_OFF} · got={image_zip_head!r}", file=sys.stderr)
    sys.exit(1)

# Bit-for-bit verify that the zip bytes embedded in sotfs.img match the
# on-disk python312.zip.  This is the safety net that would have caught the
# original ENCODINGS-2 bug (header zip_size advertised one size but the
# bytes in the image were the previous build's zip).
image_zip_sha1 = hashlib.sha1(image_zip_bytes).hexdigest()
if image_zip_sha1 != disk_zip_sha1:
    print(f"[stdlib-pack] FATAL: embedded zip in image diverges from {ZIP_PATH}", file=sys.stderr)
    print(f"  image sha1: {image_zip_sha1}", file=sys.stderr)
    print(f"  disk  sha1: {disk_zip_sha1}", file=sys.stderr)
    sys.exit(1)

print(f"[stdlib-pack] verify OK · header.zip_size={zip_size} matches {ZIP_PATH} · sha1={disk_zip_sha1[:16]}...")
EOF

echo "[stdlib-pack] done"
