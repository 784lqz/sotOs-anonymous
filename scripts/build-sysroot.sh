#!/usr/bin/env bash
# sotOs · bake the musl sysroot tree into sotfs.img [96,256 MiB).
# Mirror of include/sotfs/layout.h + include/sotfs/sysroot.h · keep in sync.
# USAGE: bash scripts/build-sysroot.sh <sotfs.img> <include-dir> <lib-dir> [share-dir] [bin-dir]
#   <include-dir> → /usr/include;  <lib-dir> → /usr/lib;  [share-dir] → /usr/share;
#   [bin-dir] → /usr/bin (real apps + realpath() need /usr/bin to exist · Wine M1)
#   (all recursive · subdirs + symlinks preserved as LNK entries)
set -euo pipefail
{ [ "$#" -ge 3 ] && [ "$#" -le 5 ]; } || { echo "usage: $0 <sotfs.img> <include-dir> <lib-dir> [share-dir] [bin-dir]" >&2; exit 2; }
IMG="$1"; INC="$2"; LIB="$3"; SHARE="${4:-}"; BIN="${5:-}"

python3 - "$IMG" "$INC" "$LIB" "$SHARE" "$BIN" <<'PY'
import os, struct, sys
img, inc_dir, lib_dir = sys.argv[1], sys.argv[2], sys.argv[3]
share_dir = sys.argv[4] if len(sys.argv) > 4 and sys.argv[4] else ""
bin_dir   = sys.argv[5] if len(sys.argv) > 5 and sys.argv[5] else ""

SYSROOT_OFFSET = 96 * 1024 * 1024           # SOTFS_SYSROOT_OFFSET (60->64->72->76->84->88->96 MiB · install-arc P0.1 binstore +8 for the dpkg toolchain · apt arc P0 +8)
DATA_OFFSET    = SYSROOT_OFFSET + 512 * 1024 # SOTFS_SYSROOT_DATA_OFFSET (64K -> 512K header+table area)
REGION_END     = SYSROOT_OFFSET + 160 * 1024 * 1024  # SOTFS_SYSROOT_REGION_BYTES (16 -> 48 -> 64 -> 80 -> 128 -> 160 MiB · Wine M1 full PE + x86_64-unix .so subset)
MAGIC, VERSION = 0x52535953, 1
MAX_ENTRIES, NAME = 2048, 192               # SOTFS_SYSROOT_MAX_ENTRIES / SOTFS_SYSROOT_PATH_BYTES
DIR, FILE, LNK = 0, 1, 2                    # mirrors SOTFS_SYSROOT_TYPE_{DIR,FILE,LNK}

entries = []   # (path, type, offset, size)
blobs   = []   # (offset, bytes)
cur = DATA_OFFSET

def add_dir(relpath):
    entries.append((relpath, DIR, 0, 0))

def add_blob(relpath, typ, data):
    global cur
    off = cur
    blobs.append((off, data))
    entries.append((relpath, typ, off, len(data)))
    cur = (off + len(data) + 4095) // 4096 * 4096   # 4 KiB-align next

def add_file(relpath, data):
    add_blob(relpath, FILE, data)

def add_link(relpath, target):
    add_blob(relpath, LNK, target.encode())          # textual target, verbatim

def pack_tree(src_dir, prefix):
    """Recursive walk of src_dir under `prefix` (e.g. "include", "lib").
    Subdirs → DIR entries; regular files → FILE; symlinks (to files or dirs,
    dangling included) → LNK preserving the textual target.  dirs.sort()
    in-place keeps the descent order — and so the image — deterministic."""
    add_dir(prefix)
    for root, dirs, files in os.walk(src_dir):
        dirs.sort()
        rel = os.path.relpath(root, src_dir)
        base = prefix if rel == "." else prefix + "/" + rel.replace(os.sep, "/")
        for d in dirs:                               # symlinked dirs land here · not descended
            full = os.path.join(root, d)
            if os.path.islink(full):
                add_link(base + "/" + d, os.readlink(full))
            else:
                add_dir(base + "/" + d)
        for f in sorted(files):
            full = os.path.join(root, f)
            if os.path.islink(full):
                add_link(base + "/" + f, os.readlink(full))
            else:
                with open(full, "rb") as fh:
                    add_file(base + "/" + f, fh.read())

pack_tree(inc_dir, "include")   # /usr/include
pack_tree(lib_dir, "lib")       # /usr/lib
if share_dir:                   # /usr/share (optional · xkb data etc.)
    pack_tree(share_dir, "share")
if bin_dir:                     # /usr/bin (Wine M1 · real apps + realpath() need it)
    pack_tree(bin_dir, "bin")

# capacity guards · explicit (NOT assert: must survive PYTHONOPTIMIZE) and
# BEFORE any image write — an over-long path would ljust-PAD past NAME and
# byte-shift every later 216-byte entry under the C reader's fixed stride.
def die(msg):
    sys.exit(f"[sysroot-pack] FATAL: {msg}")

if len(entries) > MAX_ENTRIES:
    die(f"too many entries: {len(entries)} > {MAX_ENTRIES}")
if cur > REGION_END:
    die(f"sysroot overflows region: {cur} > {REGION_END}")
for p, *_ in entries:
    if len(p.encode()) >= NAME:
        die(f"path too long ({len(p.encode())} >= {NAME}): {p}")

# header + entry table at SYSROOT_OFFSET
hdr = struct.pack('<IIII', MAGIC, VERSION, len(entries), 0)
tbl = b''
for path, typ, off, size in entries:
    tbl += path.encode().ljust(NAME, b'\x00') + struct.pack('<IIQQ', typ, 0, off, size)
if len(hdr) + len(tbl) > DATA_OFFSET - SYSROOT_OFFSET:
    die(f"header+table overruns the reserved area: {len(hdr)+len(tbl)} > {DATA_OFFSET-SYSROOT_OFFSET}")

with open(img, 'r+b') as fh:
    fh.seek(SYSROOT_OFFSET); fh.write(hdr + tbl)
    for off, data in blobs:
        fh.seek(off); fh.write(data)
print(f"[sysroot-pack] {len(entries)} entries · data ends @ {cur} ({(cur-SYSROOT_OFFSET)//1024} KiB used of {(REGION_END-SYSROOT_OFFSET)//1024})")
PY
