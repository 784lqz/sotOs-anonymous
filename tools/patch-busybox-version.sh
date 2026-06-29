#!/usr/bin/env bash
# sotOs · terminal-fidelity · re-stamp the embedded busybox version string so
# `busybox | head -1` reports v1.36.1 (Alpine 3.20's busybox) instead of the
# prebuilt fixture's v1.35.0 — coherent with `apk info busybox` (1.36.1-r29).
#
# This is a SAME-LENGTH byte patch (deception-appropriate · the fixture's ELF
# structure and applet code are untouched; only the printed version banner +
# build-date string change).  Idempotent: re-running on an already-patched
# binary is a no-op.  A real 1.36.1 rebuild would also align the applet LIST
# (1.36 added a few applets) — that is the deeper follow-up if ever needed.
#
#   bash tools/patch-busybox-version.sh [path-to-busybox-static.bin]
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
BIN="${1:-src/test/lucas_busybox/busybox-static.bin}"
[ -f "$BIN" ] || { echo "[bb-ver] missing $BIN" >&2; exit 2; }

python3 - "$BIN" <<'PY'
import sys
p = sys.argv[1]
b = bytearray(open(p, "rb").read())
# (old, new) · MUST be equal length (in-place patch · no offset shift).
subs = [
    (b"1.35.0",                   b"1.36.1"),                    # version (all refs)
    (b"2022-01-17 19:57:02 CET",  b"2025-11-23 14:32:18 UTC"),   # build date banner
]
total = 0
for old, new in subs:
    assert len(old) == len(new), f"length mismatch: {old!r} vs {new!r}"
    n = b.count(old)
    if n:
        b = bytearray(b.replace(old, new))
        total += n
        print(f"[bb-ver]   {old.decode()} -> {new.decode()} · {n} site(s)")
if total == 0:
    print("[bb-ver] nothing to patch (already 1.36.1?)")
else:
    open(p, "wb").write(b)
    print(f"[bb-ver] patched {total} site(s) in {p}")
PY

echo "[bb-ver] banner now:"
strings "$BIN" | grep -E "BusyBox v1\." | head -1
