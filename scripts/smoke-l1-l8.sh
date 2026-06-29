#!/bin/bash
# sotOs · L1-L8 smoke regression check
#
# Boots the kernel + root + orchestrator in QEMU, captures serial
# stdout for ~30 seconds, then greps for the headline lines from
# each milestone.  Exit 0 if all PASS, 1 if anything's missing.
#
# Usage:
#   bash scripts/smoke-l1-l8.sh
#
# Designed to be runnable from CI once the build is current.  Does
# NOT rebuild · assumes `just build` has produced fresh images.

set -u
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
LOG="$(mktemp -t sotos-smoke-XXXXXX.log)"
trap 'rm -f "$LOG"' EXIT

KERNEL="$ROOT/build/images/kernel-x86_64-pc99"
INITRD="$ROOT/build/images/sotOs-root-image-x86_64-pc99"

if [[ ! -f "$KERNEL" || ! -f "$INITRD" ]]; then
  echo "FAIL · build artifacts missing.  Run 'just build' first." >&2
  exit 2
fi

echo "Booting sotOs in QEMU (120s budget · PR 8 bumped from 90s for 10x simreboot stress · virtio-blk per-read log throttled)..."
timeout 120 qemu-system-x86_64 \
  -m 2048 -display none -serial stdio -enable-kvm -cpu host \
  -kernel "$KERNEL" -initrd "$INITRD" \
  -drive file="$ROOT/build/images/sotfs.img",format=raw,if=none,id=sd0 \
  -device virtio-blk-pci,drive=sd0 \
  -netdev user,id=net0 \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
  > "$LOG" 2>&1 || true

# Expected signatures, one per milestone where reachable in a
# single boot (subject to the known allocman-pool limit · see the
# in docs).
declare -a CHECKS=(
  # L1 boot · kernel loaded + root + orchestrator alive
  "L1·kernel:Booting all finished, dropped to user space"
  "L1·root:\\[root\\] bootstrap OK"
  "L3a·orch:\\[orch\\] BOOTSTRAP "
  "L3a·orch:\\[orch\\] vka ready · sanity EP"
  # L4 sotShell + asymmetry tagline
  "L4·sotshell:sotos> sotinfo"
  "L4·tagline:you are NOT on Linux. you are on sotOs."
  # L5 profile switch
  "L5·profile:\\[vfs\\] profile = UBUNTU"
  # L6 silenced mode silent rollback
  "L6·silenced:\\[silenced\\] pid=1 write"
  "L6·silenced:SILENT \\(rollback #1\\)"
  # L7 Tier 2 mirror synth canary content
  "L7·tier2:\\[vfs\\] TIER 2 · canary content active"
  "L7·canary:admin:x:1000:1000:Administrator"
  "L7·canary:backer:x:1001:1001:Backup Service"
  "L7·canary:ops:x:1002:1002:OpsEng"
  # L8 canary-access tracking
  "L8·canary-log:\\[canary\\] pid=1 read /etc/passwd"
  # obsd-β: arc4random CSPRNG seeded at orch bootstrap
  "obsd-β·arc4random:\\[orch\\] arc4random seeded"
  # obsd-γ: guard-page + ASLR jitter log line from LucAs_sys_mmap
  "obsd-γ·guard:\\[mmap\\] pid=. obsd-γ vaddr="
  # sotFS-α Phase 2: DPO graph backend mounted at /tmp
  "sotFS-α·mount:\\[sotfs\\] mounted /tmp · root_id="
  # sotFS-α Phase 2 demo: busybox cat reads DPO-graph content
  "sotFS-α·demo:HOLA from sotFS-α DPO"
  # sotFS-β: STO transaction log lines wrap each DPO rewrite
  "sotFS-β·sto:\\[sto\\] tx=[0-9]* COMMIT"
  # A3·anomaly: in-orch rule engine fires write_count > threshold
  "A3·anomaly:\\[anomaly\\] pid=. · trigger=write_count"
  # sotFS-η·graph_curvature: Forman-Ricci curvature monitor emits [graph-curvature] line after init
  "sotFS-η·graph_curvature:\\[graph-curvature\\] op=sotfs:.* mean_k="
  # sotFS-ζ·install: canary-installing API installs bait credential file (canary value)
  "sotFS-ζ·install:AKIAFAKECANARY0SOTOS"
  # sotFS-ε·mirror: Tier 2 write silenced by isolated-write path branching
  "sotFS-ε·mirror:\\[isolated\\] pid=. tier=2 · sotfs"
  # sotFS-ι·functor: deception functor transition log line (anomaly probe fires F_0→F_1)
  "sotFS-ι·functor:\\[functor\\] pid=. transition .* → F_"
  # sotFS-γ·wal: WAL emitter fires for committed DPO rewrites (install is the first at boot)
  "sotFS-γ·wal:\\[wal\\] tx=. kind=install"
  # virtio-blk Phase 2b: PCI discovery finds the virtio-blk device on bus 0
  "virtio-blk·discovery:\\[virtio-blk\\] FOUND at"
  # virtio-blk Phase 2c: virtqueue init + first block read succeeds
  "virtio-blk·read:\\[virtio-blk\\] read sector 0 OK"
  # sotFS-γ·persist: Phase 2d · WAL backend swapped to virtio-blk persistent storage
  "sotFS-γ·persist:\\[sotfs\\] WAL backend = virtio-blk"
  # sotNet-β-1·discovery: virtio-net PCI device found on bus 0
  "sotNet-β-1·discovery:\\[virtio-net\\] FOUND at"
  # sotNet-β-2·init: virtio-net queue setup completes with DRIVER_OK
  "sotNet-β-2·init:\\[virtio-net\\] init done · DRIVER_OK"
  # sotNet-β-3·init: sotnet minimal stack initialised with our IP + MAC
  "sotNet-β-3·init:\\[sotnet\\] init · IP="
  # sotNet-β-4·sendto: LucAs sendto routes a UDP packet through the sotnet stack
  "sotNet-β-4·sendto:\\[sotnet-β\\] UDP send"
  # L10 full: PTY VFS backend mounted at /dev/p alongside /proc + / + /tmp
  "L10·pty-mount:installed mount table \\(4 entries"
  # C5-A: Path-D anomaly-ext spawned · receiving on IPC EP
  "Path-D·anomaly-spawn:\\[anomaly-ext\\] spawned.*receiving on EP"
  # C5-A: A3 Phase-B round-trip · orch processes anomaly-driven promotion
  "A3·round-trip:\\[orch\\] anomaly-driven promotion.*pid="
  # C5-A: sotFS-θ Forman-Ricci RANSOMWARE candidate trigger fires at init
  "sotFS-θ·trigger:\\[sotfs-θ\\] RANSOMWARE candidate"
  # C5-A: sotShell mkdir · STO IPC confirms real VFS op (real IPC path)
  "sotShell·mkdir:\\[sto\\] tx=[0-9]* BEGIN op=sotfs:mkdir"
  # C5-A: sotShell ls post-mkdir · 8 entries visible after operator-dir installed
  "sotShell·ls:sotos> ls /tmp.*8 entries"
  # C5-A: sotShell grep command executed against honey-aws-creds
  "sotShell·grep:sotos> grep aws_access /tmp/honey-aws-creds"
  # C5-A: sotShell tail command executed against honey-readme
  "sotShell·tail:sotos> tail /tmp/honey-readme.txt"
  # γ Phase 3-D-1: close-the-loop · synth→orch callback fires after response_profile_dispatch
  "γ-Phase-3-D·loop:\\[orch\\] synth.*response · pid="
  # C5-A: L4-Phase-C interactive-input polling · scripted demo completes cleanly
  "L4-Phase-C·prompt:\\[sotshell\\] scripted demo complete.*polling for interactive input"
  # sotNet-ζ: sotShell dns lookup HIT against pre-seeded canary domain (tripwire armed)
  "sotShell·dns-lookup:\\[dns\\] HIT · ransomware-pay\\.example"
  # sotNet-ε Phase 2: orch-side dns_lookup HIT fires anomaly-ext audit event
  "anomaly·dns-hit:\\[anomaly-ext\\] DNS HIT · operator-lookup canary-domain=malicious-c2"
  # γ Phase 3-D-2: sotShell synth-trigger · operator-driven redirect demo acknowledged
  "sotShell·synth-trigger:\\[synth-trigger\\] orch acknowledged"
  # γ Phase 3-D-2: pending_recv queue · orch enqueues synthetic synth response for later recvfrom
  "γ-Phase-3-D-2·queue:\\[sotnet-γ\\] queued recv · pid="
  # PR1: procd Path D scaffold · banner-and-sleep ELF spawned by root
  "PROCD·alive:\\[procd\\] alive · ep="
  # SP2 PR1 · WAL was at 60 MiB (64 MiB image) · SUPERSEDED by LIBC·wal-offset below
  # (tcc-libc PR1 relocated the WAL to 76 MiB / 80 MiB image · only one WAL offset can exist)
  # SP2 PR2 · binstore region populated + round-trip read of tcc.bin
  "SP2·binstore-selftest:\\[binstore\\] selftest tcc.bin · elf-magic OK · size=423896"
  # SP2 PR5 · writable graph was 256 blocks · SUPERSEDED by LIBC·graph-cap below
  # (tcc-libc PR5 bumped the graph to 1024 blocks · the capacity log prints the
  #  live macros, so only one graph-cap assertion can match)
  # tcc-libc PR5 · writable graph bumped 256 -> 1024 blocks for hosted emitted ELFs
  "LIBC·graph-cap:\\[sotfs\\] graph capacity · inodes=64 edges=128 blocks=1024"
  # tcc-libc PR1 · WAL was at 76 MiB (80 MiB image) · SUPERSEDED by RWBIN·wal-offset below
  # (A2 PR1 relocated the WAL to 92 MiB / 96 MiB image · only one WAL offset can exist)
  # A2 PR1 · WAL relocated to 92 MiB after image grew to 96 MiB
  "RWBIN·wal-offset:\\[wal\\] init · backend capacity=[0-9]+ bytes · WAL offset=96468992"
  # A2 PR2 · rwbinstore backend initializes (empty on a fresh image)
  "RWBIN·ready:\\[rwbinstore\\] ready · [0-9]+ entries"
  # A2 PR3 · rwbinstore write -> read-back round-trip
  # (the literal '+' in "wrote+read" is escaped so grep -E treats it as a
  #  literal, not the one-or-more quantifier; the boot prints "wrote+read")
  "RWBIN·selftest:\\[rwbinstore\\] selftest OK · wrote\\+read 4 bytes 'RWBT'"
  # tcc-libc PR4 · sysroot backend mounted, header read-back + getdents
  "LIBC·sysroot-ready:\\[sysroot\\] ready · [0-9]+ entries · mounted /usr"
)

pass=0
fail=0
for ent in "${CHECKS[@]}"; do
  label="${ent%%:*}"
  rest="${ent#*:}"
  if grep -qE "$rest" "$LOG"; then
    printf "  ✓ %-30s %s\n" "$label" "$rest"
    ((pass++))
  else
    printf "  ✗ %-30s %s (MISSING)\n" "$label" "$rest"
    ((fail++))
  fi
done

echo
echo "──────────────────────────────────────────────"
echo "Summary: $pass passed, $fail failed"
echo "Log saved to: $LOG (will be deleted on exit)"
echo "──────────────────────────────────────────────"

if (( fail == 0 )); then
  echo "All L1-L8 minimal-viable signatures present · regression PASS"
  exit 0
fi

# On failure, show the last 50 lines of the log for diagnosis.
echo
echo "Last 50 lines of serial output for diagnosis:"
echo "──────────────────────────────────────────────"
tail -50 "$LOG"

exit 1
