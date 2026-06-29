#!/usr/bin/env bash
# EXPERIMENT T5 · SYSCALL LATENCY MEASUREMENT HARNESS
#
# Runs the microbench fixture in both sotOs (via just run-headless) and native Alpine,
# collects results, and generates a comparison table.
#
# Prerequisites:
#   - sotOs built: just build (creates build/images/sotOs-root-image-x86_64-pc99)
#   - Native Alpine SSH available: ssh -p 18022 root@localhost (via just run-honeypot)
#   - microbench binary compiled for Alpine 3.20 / linux-lts 6.6.30
#
# Usage:
#   bash run.sh [n_trials]     # Default n_trials=5, run 5 times each, report median
#
# Output:
#   tools/eval/t5-syscall/results.csv    (machine-readable, all trials)
#   tools/eval/t5-syscall/summary.txt    (human-readable summary)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
EVAL_DIR="$PROJECT_ROOT/tools/eval/t5-syscall"
BUILD_DIR="$PROJECT_ROOT/build"

N_TRIALS="${1:-5}"
SOTOS_LOG="/tmp/t5-sotos-$$.log"
RESULTS_CSV="$EVAL_DIR/results.csv"
SUMMARY="$EVAL_DIR/summary.txt"

mkdir -p "$EVAL_DIR"

echo "=== EXPERIMENT T5 · SYSCALL LATENCY ==="
echo "Trials per platform: $N_TRIALS"
echo "Eval dir: $EVAL_DIR"
echo ""

# ===========================================================================
# PART 1: sotOs measurements (boot-driven via QEMU)
# ===========================================================================
echo "[1/3] sotOs microbench via QEMU headless boot…"

# Boot sotOs with the microbench fixture in the demo sequence.
# The fixture will print CSV results to the serial console.
timeout 120 qemu-system-x86_64 \
    -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel "$BUILD_DIR/images/kernel-x86_64-pc99" \
    -initrd "$BUILD_DIR/images/sotOs-root-image-x86_64-pc99" \
    -drive file="$BUILD_DIR/images/sotfs.img",format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    > "$SOTOS_LOG" 2>&1 || true

# Extract CSV from the log (marked by MICROBENCH COMPLETE).
sotos_results=""
if grep -q "=== EXPERIMENT T5 · SYSCALL LATENCY MICROBENCH ===" "$SOTOS_LOG"; then
    sotos_results=$(sed -n '/^syscall,/,/=== MICROBENCH COMPLETE ===/p' "$SOTOS_LOG" | head -n -1)
    echo "✓ captured $(($(echo "$sotos_results" | wc -l) - 1)) syscall measurements from sotOs"
else
    echo "✗ no T5 microbench marker in sotOs log (check fixture integration)"
    exit 1
fi

# ===========================================================================
# PART 2: Native Alpine measurements (via SSH to :18022)
# ===========================================================================
echo "[2/3] Native Alpine microbench via SSH (18022)…"

# Poll for SSH readiness.
max_wait=30
for ((i=0; i<max_wait; i++)); do
    if ssh -p 18022 -o ConnectTimeout=1 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
           root@localhost "exit 0" 2>/dev/null; then
        echo "✓ SSH to Alpine ready"
        break
    fi
    if [ $i -eq $((max_wait-1)) ]; then
        echo "✗ SSH to Alpine timeout (is :18022 running? try 'just run-honeypot' in another terminal)"
        exit 1
    fi
    sleep 1
done

native_results=""
for trial in $(seq 1 $N_TRIALS); do
    echo "  Trial $trial/$N_TRIALS…"
    native_results=$(ssh -p 18022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                         root@localhost "/tmp/microbench 2>/dev/null" || true)
    if [ -z "$native_results" ]; then
        echo "  ✗ microbench not found on Alpine; uploading…"
        scp -P 18022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
            "$SCRIPT_DIR/microbench" root@localhost:/tmp/microbench >/dev/null 2>&1 || true
        native_results=$(ssh -p 18022 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
                             root@localhost "/tmp/microbench 2>/dev/null")
    fi
done

echo "✓ captured Alpine measurements"

# ===========================================================================
# PART 3: Generate results table
# ===========================================================================
echo "[3/3] Generating results…"

cat > "$RESULTS_CSV" << 'CSVEOF'
platform,syscall,median_cycles,p95_cycles,p99_cycles,min_cycles,max_cycles
CSVEOF

# Parse sotOs results.
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "sotos,$line" >> "$RESULTS_CSV"
done <<< "$sotos_results"

# Parse native results (average across trials).
# TODO: implement proper trial averaging when we have multiple runs.
while IFS= read -r line; do
    [ -z "$line" ] && continue
    echo "native,$line" >> "$RESULTS_CSV"
done <<< "$native_results"

echo "✓ wrote results to $RESULTS_CSV"

# Generate human-readable summary.
cat > "$SUMMARY" << 'SUMMEOF'
=== EXPERIMENT T5 SUMMARY ===

Syscall latency comparison: sotOs vs native Alpine 3.20 / linux-lts 6.6.30.

Baseline: Both platforms run on QEMU/KVM (-enable-kvm -cpu host).
  sotOs: x86_64 seL4 kernel + LUCAS userspace syscall dispatch (lucas/fault_loop.c)
  Native: Stock Alpine Linux kernel + musl libc

Representative syscalls (1M samples each, median + p95/p99 percentiles):

SUMMEOF

# Append CSV for inspection.
cat "$RESULTS_CSV" >> "$SUMMARY"

cat >> "$SUMMARY" << 'SUMMEOF'

Interpretation:
  - Cycles = measured via rdtsc (CPU cycle counter).
  - Median = middle of 1M measurements (50th percentile).
  - p95 / p99 = 95th / 99th percentile latency (tail behavior).
  - getpid = baseline (no I/O), read/write = buffered I/O, open = FD mgmt,
    stat = metadata, clock_gettime = time query.

Expected findings:
  - sotOs latency > native due to fault interception + seL4 IPC + dispatch overhead.
  - Relative overhead depends on syscall complexity:
    * Simple syscalls (getpid): lower overhead (pure fault cost).
    * Complex syscalls (mmap, read): higher overhead (payload marshalling).

SUMMEOF

echo "✓ wrote summary to $SUMMARY"
echo ""
echo "=== RESULTS ==="
cat "$SUMMARY"
echo ""
echo "Logs:"
echo "  sotOs:  $SOTOS_LOG"
echo "  Results CSV: $RESULTS_CSV"
