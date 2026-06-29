#!/usr/bin/env python3
"""Host round-trip test for scripts/build-sysroot.sh.
Packs a fixture tree (regular file + subdir + nested file + symlinks) into a
scratch image, then reads the header + entry table back and asserts paths,
types, offsets, sizes, link targets, data alignment, and determinism (two
packs produce byte-identical sysroot regions).  Also asserts the packer FAILS
loudly on an over-long path.  No boot required.
All checks go through check() (NOT bare assert: must survive PYTHONOPTIMIZE).
Run: python3 tools/sysroot-pack-test.py"""
import hashlib, os, struct, subprocess, sys, tempfile

MAGIC = 0x52535953                       # SOTFS_SYSROOT_MAGIC
NAME = 192                               # SOTFS_SYSROOT_PATH_BYTES
ENTRY = NAME + 24                        # path + type(4)+pad(4)+offset(8)+size(8)
SYSROOT_OFFSET = 64 * 1024 * 1024        # SOTFS_SYSROOT_OFFSET
DATA_OFFSET = SYSROOT_OFFSET + 512 * 1024  # SOTFS_SYSROOT_DATA_OFFSET
REGION_END = SYSROOT_OFFSET + 48 * 1024 * 1024
IMG_BYTES = 128 * 1024 * 1024            # SOTFS_IMG_TOTAL_BYTES
DIR, FILE, LNK = 0, 1, 2
FIXTURE_NODES = 8   # include, include/stub.h, lib, lib/sub, libvfsprobe.so.1,
                    # libvfsprobe.so, lib/sub/nested.so, lib/sub/nested-link.so

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PACKER = os.path.join(ROOT, "scripts", "build-sysroot.sh")


def check(cond, msg):
    """assert that survives -O/PYTHONOPTIMIZE (bare asserts strip to no-ops
    and turn the whole test into a false-green)."""
    if not cond:
        raise SystemExit(f"[sysroot-pack-test] FAIL · {msg}")


def read_entries(img):
    with open(img, "rb") as f:
        f.seek(SYSROOT_OFFSET)
        magic, ver, count, _ = struct.unpack("<IIII", f.read(16))
        check(magic == MAGIC, f"bad magic 0x{magic:x}")
        check(ver == 1, f"bad version {ver}")
        out = []
        for _ in range(count):
            raw = f.read(ENTRY)
            path = raw[:NAME].split(b"\x00", 1)[0].decode()
            typ, _pad, off, size = struct.unpack("<IIQQ", raw[NAME:])
            out.append((path, typ, off, size))
        return out


def blob_at(img, off, size):
    with open(img, "rb") as f:
        f.seek(off)
        return f.read(size)


def region_sha1(img):
    h = hashlib.sha1()
    with open(img, "rb") as f:
        f.seek(SYSROOT_OFFSET)
        left = REGION_END - SYSROOT_OFFSET
        while left:
            chunk = f.read(min(left, 1 << 20))
            h.update(chunk)
            left -= len(chunk)
    return h.hexdigest()


def make_fixture(td):
    inc = os.path.join(td, "inc")
    lib = os.path.join(td, "lib")
    os.makedirs(inc)
    with open(os.path.join(inc, "stub.h"), "w") as fh:
        fh.write("/*h*/\n")
    os.makedirs(os.path.join(lib, "sub"))                       # a real subdir
    with open(os.path.join(lib, "libvfsprobe.so.1"), "wb") as fh:    # regular file
        fh.write(b"ELFDATA" * 100)
    os.symlink("libvfsprobe.so.1", os.path.join(lib, "libvfsprobe.so"))   # relative symlink
    with open(os.path.join(lib, "sub", "nested.so"), "wb") as fh:  # file in subdir
        fh.write(b"NESTED")
    os.symlink("nested.so", os.path.join(lib, "sub", "nested-link.so"))  # symlink in subdir
    return inc, lib


def pack(img, inc, lib, check_rc=True):
    with open(img, "wb") as fh:
        fh.truncate(IMG_BYTES)
    return subprocess.run(["bash", PACKER, img, inc, lib],
                          capture_output=True, text=True, check=check_rc)


def main():
    with tempfile.TemporaryDirectory() as td:
        inc, lib = make_fixture(td)
        img = os.path.join(td, "scratch.img")
        pack(img, inc, lib)
        raw = read_entries(img)

        # exact entry count + path uniqueness — a double-emit would be
        # invisible to the dict below (dup keys collapse, last wins) while the
        # C reader consumes all `count` entries linearly.
        check(len(raw) == FIXTURE_NODES,
              f"entry count {len(raw)} != {FIXTURE_NODES}: {[p for p, *_ in raw]}")
        check(len({p for p, *_ in raw}) == len(raw), f"duplicate paths: {raw}")

        # parent-before-child order — the C reader consumes the table linearly
        # and getdents64 relies on a DIR entry preceding its children; correct
        # today by os.walk top-down, but a reorder would otherwise ship green.
        seen = set()
        for p, *_ in raw:
            if "/" in p:
                parent = p.rsplit("/", 1)[0]
                check(parent in seen, f"{p} emitted before its parent {parent}")
            seen.add(p)

        ents = {p: (t, o, s) for p, t, o, s in raw}

        # directories (the backend needs them for getdents64)
        check(ents.get("include") == (DIR, 0, 0), f"include: {ents.get('include')}")
        check(ents.get("lib") == (DIR, 0, 0), f"lib: {ents.get('lib')}")
        check(ents.get("lib/sub") == (DIR, 0, 0), f"lib/sub: {ents.get('lib/sub')}")

        # regular files (include + lib + nested)
        t, o, s = ents["include/stub.h"]
        check(t == FILE and blob_at(img, o, s) == b"/*h*/\n", f"include/stub.h: {(t, s)}")
        t, o, s = ents["lib/libvfsprobe.so.1"]
        check(t == FILE and s == 700, f"lib/libvfsprobe.so.1: {(t, s)}")
        check(blob_at(img, o, s) == b"ELFDATA" * 100, "libvfsprobe.so.1 content mismatch")
        t, o, s = ents["lib/sub/nested.so"]
        check(t == FILE and blob_at(img, o, s) == b"NESTED", f"lib/sub/nested.so: {(t, s)}")

        # symlinks → LNK entries whose data bytes are the textual target
        t, o, s = ents["lib/libvfsprobe.so"]
        check(t == LNK, f"symlink not LNK: {t}")
        check(blob_at(img, o, s) == b"libvfsprobe.so.1", f"target: {blob_at(img, o, s)}")
        t, o, s = ents["lib/sub/nested-link.so"]
        check(t == LNK, f"subdir symlink not LNK: {t}")
        check(blob_at(img, o, s) == b"nested.so", f"target: {blob_at(img, o, s)}")

        # data placement: 4-KiB-aligned, inside [DATA_OFFSET, REGION_END)
        for p, t, o, s in raw:
            if t == DIR:
                check((o, s) == (0, 0), f"dir {p} carries data: {o},{s}")
            else:
                check(o % 4096 == 0, f"{p} data not 4 KiB aligned: {o}")
                check(DATA_OFFSET <= o and o + s <= REGION_END, f"{p} outside data region")

        # determinism: a second pack of the same tree is byte-identical
        img2 = os.path.join(td, "scratch2.img")
        pack(img2, inc, lib)
        check(region_sha1(img) == region_sha1(img2), "pack is not deterministic")

        # over-long path must fail loudly (clear error, nonzero exit)
        deep = os.path.join(lib, "x" * 200)
        os.makedirs(deep)
        with open(os.path.join(deep, "f"), "wb") as fh:
            fh.write(b"y")
        r = pack(img2, inc, lib, check_rc=False)
        check(r.returncode != 0, "packer accepted an over-long path")
        check("path too long" in r.stderr, f"no clear error: {r.stderr[-400:]}")

    print("[sysroot-pack-test] PASS · files + subdirs + symlink LNK round-trip OK")


if __name__ == "__main__":
    sys.exit(main())
