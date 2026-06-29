#!/usr/bin/env bash
# sotOs · run benchmarks, capture the JSON block to docs/eval/results/<ts>/
#
# As of v0.40.0-benchmarks the micro_baseline harness runs BOOT-DRIVEN: the
# sotShell demo issues `bench baseline` early in the boot sequence, which asks
# orch (ORCH_OP_SPAWN_BENCH) to spawn sotOs-bench_baseline with a copy of
# orch's STO endpoint as its argv[1] session cap. The harness prints a
# ===BENCH-JSON-BEGIN===…===BENCH-JSON-END=== block to the serial console.
#
# This script boots QEMU, captures serial, extracts the JSON block(s), and
# saves them under docs/eval/results/<timestamp>/. No source edits needed.
#
# STATUS:
#   ✓ micro_baseline  — wired + boot-driven (IPC roundtrip · STO_OP_BENCH_PING)
#   … sto_ops / throughput / sweep_cost — built but need a real STO *session*
#     (begin/commit with a per-client session badge), not just a replying
#     endpoint. Wiring those needs orch to mint a fresh STO session per bench;
#     tracked as follow-up. They are NOT yet boot-driven.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
RESULTS_DIR="$ROOT/docs/eval/results"
# Pass a timestamp as $1 for reproducible dir names (host-side).
TS="${1:-$(date +%Y%m%d-%H%M%S)}"
OUT_DIR="$RESULTS_DIR/$TS"
LOG="$OUT_DIR/boot.log"

KERNEL="$ROOT/build/images/kernel-x86_64-pc99"
INITRD="$ROOT/build/images/sotOs-root-image-x86_64-pc99"
IMG="$ROOT/build/images/sotfs.img"

if [[ ! -f "$KERNEL" || ! -f "$INITRD" ]]; then
    echo "FAIL · build artifacts missing. Run 'just build' first." >&2
    exit 2
fi

mkdir -p "$OUT_DIR"
echo "=== sotOs · benchmark driver ==="
echo "Booting QEMU (micro_baseline runs boot-driven via the sotShell demo)…"

timeout 120 qemu-system-x86_64 \
  -m 2048 -display none -serial stdio -enable-kvm -cpu host \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -drive file="$IMG",format=raw,if=none,id=sd0 \
  -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  > "$LOG" 2>&1 || true

# Extract every JSON object (one per harness that ran).
if grep -q "===BENCH-JSON-BEGIN===" "$LOG"; then
    grep -E '^\{"bench"' "$LOG" > "$OUT_DIR/benchmarks.json" || true
    echo "✓ captured JSON →  $OUT_DIR/benchmarks.json"
    echo
    cat "$OUT_DIR/benchmarks.json"
    echo
    echo "Note: min/median are the pure-IPC estimate; p99/max reflect the"
    echo "harness running concurrently with the boot demo (scheduling jitter)."
    echo "Full boot log: $LOG"
    echo "Fill in a copy of docs/eval/results-template.md as $OUT_DIR/results.md"
else
    echo "✗ no ===BENCH-JSON=== block found in the boot log." >&2
    echo "  (Rebuild a fresh image: rm -f build/images/sotfs.img && just build)" >&2
    echo "  Full boot log: $LOG" >&2
    exit 1
fi
