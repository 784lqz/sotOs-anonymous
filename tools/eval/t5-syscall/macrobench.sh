#!/usr/bin/env bash
# EXPERIMENT T5 · SYSCALL OVERHEAD — MACRO WORKLOADS
#
# Measures real-world syscall impact via "bigger" applications:
#   1. CPython interpreter startup time (cold boot → import sys → exit)
#   2. Doom FPS (doomgeneric, E1M1, 10 seconds)
#   3. GTK3 frames/sec (gtkspike, 10 second window)
#
# These workloads reveal aggregate syscall cost across the "real software" thesis:
#   - Python: dynamic loader (mmap, mprotect, open), libm math ops, stdlib imports
#   - Doom: SDL2 (mmap, ioctl), audio (read/write), frame scheduling
#   - GTK3: Wayland surface sharing (mmap, mprotect), Cairo rendering, event polling
#
# Runs on BOTH sotOs and native Alpine; compares wall-clock time + frame rates.
#
# Prerequisites (same as microbench):
#   - just run-headless (sotOs boots and completes demo, reporting markers)
#   - just run-honeypot or persistent SSH to :18022 (native Alpine)
#
# Output:
#   tools/eval/t5-syscall/macrobench-results.csv
#   tools/eval/t5-syscall/macrobench-summary.txt

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVAL_DIR="$PROJECT_ROOT/tools/eval/t5-syscall"
BUILD_DIR="$PROJECT_ROOT/build"

RESULTS_CSV="$EVAL_DIR/macrobench-results.csv"
SUMMARY="$EVAL_DIR/macrobench-summary.txt"

mkdir -p "$EVAL_DIR"

echo "=== EXPERIMENT T5 · MACRO WORKLOADS (CPython / Doom / GTK3) ==="
echo ""

# ===========================================================================
# WORKLOAD 1: CPython startup (interpreter load → import → exit)
# ===========================================================================
echo "[1/3] CPython startup time…"

cat > "$RESULTS_CSV" << 'CSVEOF'
platform,workload,metric,value,unit
CSVEOF

# sotOs: boot, grep for [python] markers, extract timing.
echo "  sotOs…"
sotos_py_log="/tmp/t5-sotos-py-$$.log"
timeout 120 qemu-system-x86_64 \
    -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel "$BUILD_DIR/images/kernel-x86_64-pc99" \
    -initrd "$BUILD_DIR/images/sotOs-root-image-x86_64-pc99" \
    -drive file="$BUILD_DIR/images/sotfs.img",format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    > "$sotos_py_log" 2>&1 || true

# Extract timing markers: [python] handler START/DONE
if grep -q "\[python\] handler START" "$sotos_py_log" && grep -q "\[python\] handler DONE" "$sotos_py_log"; then
    echo "  ✓ CPython ran on sotOs"
    # TODO: extract wall-clock time from markers if available; else use generic timing.
else
    echo "  ⚠ CPython markers not found (check demo integration)"
fi

# Native: SSH + measure time python3 -c "import sys; print('ok')"
echo "  Native Alpine…"
native_py_time=$(ssh -p 18022 -o ConnectTimeout=5 -o StrictHostKeyChecking=no \
                     -o UserKnownHostsFile=/dev/null root@localhost \
                     "time python3 -c \"import sys; print('ok')\"" 2>&1 | grep -E "real|user|sys" | head -1 || echo "N/A")
echo "  ✓ CPython startup: $native_py_time"

echo "sotos,python-startup,marker,found,bool" >> "$RESULTS_CSV"
echo "native,python-startup,time,$native_py_time,seconds" >> "$RESULTS_CSV"

# ===========================================================================
# WORKLOAD 2: Doom E1M1 (10 seconds, measure FPS)
# ===========================================================================
echo "[2/3] Doom FPS…"

echo "  sotOs…"
sotos_doom_log="/tmp/t5-sotos-doom-$$.log"
timeout 120 qemu-system-x86_64 \
    -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel "$BUILD_DIR/images/kernel-x86_64-pc99" \
    -initrd "$BUILD_DIR/images/sotOs-root-image-x86_64-pc99" \
    -drive file="$BUILD_DIR/images/sotfs.img",format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    > "$sotos_doom_log" 2>&1 || true

# Extract doom markers + frame count from [doom] handler.
if grep -q "\[doom\] handler" "$sotos_doom_log"; then
    doom_frames=$(grep -oE "\[doom\].*frames" "$sotos_doom_log" | head -1 || echo "N/A")
    echo "  ✓ Doom on sotOs: $doom_frames"
    echo "sotos,doom-fps,frames,$doom_frames,count" >> "$RESULTS_CSV"
else
    echo "  ⚠ Doom markers not found"
fi

# Native: SSH + run doomgeneric (if available) via xvfb + headless.
echo "  Native Alpine…"
# Note: Native Doom requires X11 or SDL2 display. For headless, we'd need:
#   xvfb-run -a doomgeneric (slow, not practical for latency bench)
# Skip native Doom for now; note the gap in summary.
echo "  ⚠ Skipped (requires display server)"
echo "native,doom-fps,marker,skipped,note" >> "$RESULTS_CSV"

# ===========================================================================
# WORKLOAD 3: GTK3 frames/sec (wayland surface commits)
# ===========================================================================
echo "[3/3] GTK3 frame rate…"

echo "  sotOs…"
sotos_gtk_log="/tmp/t5-sotos-gtk-$$.log"
timeout 120 qemu-system-x86_64 \
    -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel "$BUILD_DIR/images/kernel-x86_64-pc99" \
    -initrd "$BUILD_DIR/images/sotOs-root-image-x86_64-pc99" \
    -drive file="$BUILD_DIR/images/sotfs.img",format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    > "$sotos_gtk_log" 2>&1 || true

# Extract GTK3 markers: wl_shm commits during gtkspike window.
if grep -q "\[gtkspike\]" "$sotos_gtk_log"; then
    gtk_commits=$(grep -cE "\[wl-compositor\] commit" "$sotos_gtk_log" || echo "0")
    echo "  ✓ GTK3 on sotOs: $gtk_commits wl_shm commits"
    echo "sotos,gtk3-fps,wl-commits,$gtk_commits,count" >> "$RESULTS_CSV"
else
    echo "  ⚠ GTK3 markers not found"
fi

# Native: similarly skipped (needs Wayland/display).
echo "  ⚠ Native skipped (requires Wayland display)"
echo "native,gtk3-fps,marker,skipped,note" >> "$RESULTS_CSV"

# ===========================================================================
# Summary
# ===========================================================================
cat > "$SUMMARY" << 'SUMMEOF'
=== EXPERIMENT T5 · MACRO WORKLOAD RESULTS ===

Workload-level syscall overhead via CPython, Doom, and GTK3.

WORKLOAD 1: CPython startup
  Metric: interpreter load → import sys → exit
  sotOs overhead: syscall interception (mmap, mprotect, open, read, close)
  Native baseline: stock Linux kernel, musl libc

WORKLOAD 2: Doom FPS (E1M1 over 10 sec)
  Metric: frames rendered
  sotOs syscalls: SDL2 video + audio (ioctl, mmap, read/write)
  Measurement: FPS via frame counter in doomgeneric.
  Note: Native benchmark not practical (requires X11 display forwarding).

WORKLOAD 3: GTK3 frame rate (wayland surface commits)
  Metric: Wayland wl_shm surface commits over 10 sec
  sotOs syscalls: Cairo rendering → wl_shm pool resize (mmap, mprotect) → commit
  Measurement: count of [wl-compositor] commit logs.
  Note: Native benchmark not practical (requires Wayland display).

Interpretation:
  - CPython startup reflects dynamic loader + stdlib syscall cost.
  - Doom FPS reflects real-time audio + video scheduling overhead.
  - GTK3 frame rate reflects rendering pipeline + shared memory mgmt overhead.
  - Relative overhead (sotOs / native) at macro level vs micro level reveals:
    * Whether overhead is dominated by syscall dispatch or other factors.
    * Whether caching / amortization effects improve aggregate latency.

SUMMEOF

cat "$RESULTS_CSV" >> "$SUMMARY"

echo ""
echo "=== RESULTS ==="
cat "$SUMMARY"
echo ""
echo "Output:"
echo "  CSV:     $RESULTS_CSV"
echo "  Summary: $SUMMARY"
