#!/usr/bin/env bash
# sotOs · bake binaries into the sotfs.img binstore region [28 MiB, 64 MiB).
# Mirror of include/sotfs/layout.h + include/sotfs/binstore.h · keep in sync.
#
# USAGE: bash scripts/build-binstore.sh <sotfs.img> <bin-path> [<bin-path>...]
# Entry name = basename of each <bin-path>.
set -euo pipefail

if [ "$#" -lt 2 ]; then
    echo "usage: $0 <sotfs.img> <bin>..." >&2
    exit 2
fi

IMG="$1"; shift

BIN_OFFSET=$((28 * 1024 * 1024))      # SOTFS_BINSTORE_HEADER_OFFSET
DATA_OFFSET=$((BIN_OFFSET + 8192))    # SOTFS_BINSTORE_DATA_OFFSET (4 KiB-aligned)
REGION_END=$((96 * 1024 * 1024))      # SOTFS_SYSROOT_OFFSET · binstore must end before this (72->76 · A5 +4 -> 84 · install-arc P0.1 dpkg +8 · 88 -> 96 · apt arc P0)
                                      # (round-11 fix: chocodoom overran 60 MiB into the
                                      # sysroot region → its tail got overwritten with mtio.h)
MAX_ENTRIES=96                        # MUST match SOTFS_BINSTORE_MAX_ENTRIES (include/sotfs/binstore.h)
                                      # + the python header loop below.  48→51 for the install-arc
                                      # P0.1 dpkg toolchain (dpkg/dpkg-deb/dpkg-split/tar/xz/gzip/zstd).
                                      # header = 16 + 51*80 = 4096 B == the 4 KiB region (HARD ceiling;
                                      # backends_binstore.c static-asserts <= 4096).

# Entry-count guard.  The python packer writes a FIXED MAX_ENTRIES header slots but
# records the raw count; without this, a 17th binary would silently produce a header
# whose count > slots written → the runtime loader (backends_binstore.c) rejects the
# WHOLE store ("invalid count") and every binstore binary fails to load.  FATAL here
# turns that confusing boot failure into a clear build error.  Bumping the cap means
# growing SOTFS_BINSTORE_MAX_ENTRIES (binstore.h struct) + the python loop together.
if [ "$#" -gt "$MAX_ENTRIES" ]; then
    echo "[binstore-pack] FATAL: $# binaries > MAX_ENTRIES=$MAX_ENTRIES" >&2
    echo "[binstore-pack]   bump SOTFS_BINSTORE_MAX_ENTRIES (include/sotfs/binstore.h) + the" >&2
    echo "[binstore-pack]   header loop in this script, or drop a fixture." >&2
    exit 1
fi

names=(); offs=(); sizes=()
cur=$DATA_OFFSET
for bin in "$@"; do
    # A missing binary is SKIPPED (warn), not fatal: optional/spike artifacts (e.g.
    # the gitignored Wine subset in build/wine-sysroot, staged by tools/wine-stage.sh)
    # may be absent on a fresh checkout — the build must still succeed without them.
    [ -f "$bin" ] || { echo "[binstore-pack] skip (absent): $bin" >&2; continue; }
    name="$(basename "$bin")"
    size="$(stat -c %s "$bin")"
    end=$(( cur + size ))
    if [ "$end" -gt "$REGION_END" ]; then
        echo "[binstore-pack] FATAL: '$name' ends at $end > binstore region end $REGION_END" >&2
        echo "[binstore-pack]   binstore [$BIN_OFFSET, $REGION_END) overflows into the sysroot region." >&2
        echo "[binstore-pack]   Enlarge SOTFS_BINARIES_REGION_BYTES + SOTFS_SYSROOT_OFFSET (layout.h + build-sysroot.sh)." >&2
        exit 1
    fi
    # cur is 4 KiB-aligned · write in 4 KiB blocks (fast; dd handles a short tail).
    dd if="$bin" of="$IMG" bs=4096 seek=$((cur / 4096)) conv=notrunc status=none
    names+=("$name"); offs+=("$cur"); sizes+=("$size")
    cur=$(( (cur + size + 4095) / 4096 * 4096 ))   # advance, 4 KiB-aligned
    echo "[binstore-pack] $name · off=$((offs[-1])) size=$size"
done

python3 - "$IMG" "$BIN_OFFSET" "${#names[@]}" "${names[@]}" "${offs[@]}" "${sizes[@]}" <<'PY'
import struct, sys
img = sys.argv[1]
hdr_off = int(sys.argv[2])
count = int(sys.argv[3])
rest = sys.argv[4:]
names = rest[0:count]
offs  = rest[count:2*count]
sizes = rest[2*count:3*count]

MAGIC = 0x4e494253; VERSION = 1; MAX_ENTRIES = 96; NAME = 64  # MUST match binstore.h
buf = struct.pack('<IIII', MAGIC, VERSION, count, 0)
for i in range(MAX_ENTRIES):
    if i < count:
        nm = names[i].encode()[:NAME].ljust(NAME, b'\x00')
        buf += nm + struct.pack('<QQ', int(offs[i]), int(sizes[i]))
    else:
        buf += b'\x00' * (NAME + 16)

with open(img, 'r+b') as f:
    f.seek(hdr_off)
    f.write(buf)
print(f"[binstore-pack] wrote header @ {hdr_off} · {count} entr" + ("y" if count == 1 else "ies"))
PY
