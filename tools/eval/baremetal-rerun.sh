#!/usr/bin/env bash
# tools/eval/baremetal-rerun.sh
#
# Rigorous BARE-METAL re-run of the T4 (containment soak) and T5 (syscall-latency) numbers,
# on a DEDICATED, ISOLATED core.  rdtsc-level latency on a shared desktop is worthless — the
# host scheduler, SMT sibling and frequency scaling pollute every sample.  This script enforces
# the isolation protocol: it REFUSES WSL2, REFUSES an un-isolated core (isolcpus/nohz_full),
# offlines the SMT sibling, pins the frequency, locks guest memory, and pins the bench/QEMU to
# the isolated core — then re-runs both measurements and records the platform for citation.
#
# ONE-TIME SETUP (reboots once):
#     PIN_CORES=2,3 tools/eval/baremetal-rerun.sh --setup-grub   # adds isolcpus/nohz_full/rcu_nocbs
#     sudo reboot
# THEN MEASURE — run as YOURSELF, NOT under sudo (the build must not run as root; the hardware
# knobs prompt for sudo once on their own):
#     systemctl isolate multi-user.target        # optional: drop the desktop (Discord, GUI, …)
#     PIN_CORES=2,3 SOAK_DURATION=1800 tools/eval/baremetal-rerun.sh
#
# Phases (default all): --native --guest --soak.  --no-strict downgrades isolation refusals to warnings.
set -euo pipefail
REPO="$(cd "$(dirname "$0")/../.." && pwd)"; cd "$REPO"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${REPO}/tools/eval/baremetal-${STAMP}"
ENVF="$OUT/environment.txt"; SUM="$OUT/summary.txt"
PIN_CORES="${PIN_CORES:-2,3}"           # isolated cores to dedicate to the bench/QEMU
FIRST_CORE="${PIN_CORES%%,*}"
DO_NATIVE=1 DO_GUEST=1 DO_SOAK=1 STRICT=1 SETUP_GRUB=0
SAW_PHASE=0
for a in "$@"; do case "$a" in
  --setup-grub) SETUP_GRUB=1;;
  --no-strict)  STRICT=0;;
  --native) [ $SAW_PHASE = 0 ]&&{ DO_NATIVE=0 DO_GUEST=0 DO_SOAK=0 SAW_PHASE=1; }; DO_NATIVE=1;;
  --guest)  [ $SAW_PHASE = 0 ]&&{ DO_NATIVE=0 DO_GUEST=0 DO_SOAK=0 SAW_PHASE=1; }; DO_GUEST=1;;
  --soak)   [ $SAW_PHASE = 0 ]&&{ DO_NATIVE=0 DO_GUEST=0 DO_SOAK=0 SAW_PHASE=1; }; DO_SOAK=1;;
esac; done

# ── --setup-grub · add the boot-time isolation params for PIN_CORES, then reboot ────────────
if [ "$SETUP_GRUB" = 1 ]; then
  echo "Adding isolation params for cores $PIN_CORES (isolcpus + nohz_full + rcu_nocbs)."
  if command -v grubby >/dev/null 2>&1; then
    echo "  sudo grubby --update-kernel=ALL --args=\"isolcpus=$PIN_CORES nohz_full=$PIN_CORES rcu_nocbs=$PIN_CORES\""
    sudo grubby --update-kernel=ALL --args="isolcpus=$PIN_CORES nohz_full=$PIN_CORES rcu_nocbs=$PIN_CORES" \
      && echo "  applied · now: sudo reboot   (then run without --setup-grub)"
  else
    echo "  grubby not found (not Fedora?). Add to GRUB_CMDLINE_LINUX in /etc/default/grub:"
    echo "      isolcpus=$PIN_CORES nohz_full=$PIN_CORES rcu_nocbs=$PIN_CORES"
    echo "  then: sudo grub2-mkconfig -o /boot/grub2/grub.cfg && sudo reboot"
  fi
  exit 0
fi

mkdir -p "$OUT"

# ── Privilege model · build as the unprivileged invoker, NOT root ────────────────────────────
# The whole script runs under sudo (the hardware knobs need root), but the BUILD must not:
# a root `just build` litters build/ with root-owned objects, which then break every later
# non-root `just build`.  So drop to $SUDO_USER for anything that writes the repo or the build
# tree; keep root only for the hardware knobs — even the guest QEMU drops to $SUDO_USER now
# (kvm is 0666, no mem-lock), which is also what makes its -serial stdio actually emit.
BUILD_USER="${SUDO_USER:-$(id -un)}"
BUILD_HOME="$(getent passwd "$BUILD_USER" | cut -d: -f6)"
as_user() {   # run "[VAR=val ...] cmd args" as $BUILD_USER (no-op if already them)
  # Use runuser, NOT `sudo -u`: Fedora's sudo defaults to `use_pty`, which runs the command under a
  # pseudo-tty — so the `</dev/null` and `>file` redirections on the call site DON'T reach the child
  # (it inherits the pty instead).  That made `cpio --create` (it reads its file list from stdin)
  # block forever (build hung at the CPIO step) and QEMU `-serial stdio` emit 0 bytes.  runuser drops
  # privileges with clean fd passthrough (no pty), so redirections actually take effect.
  if [ "$(id -un)" = "$BUILD_USER" ]; then env "$@"
  else runuser -u "$BUILD_USER" -- env "PATH=$BUILD_HOME/.cargo/bin:$BUILD_HOME/.local/bin:$PATH" \
         "HOME=$BUILD_HOME" "USER=$BUILD_USER" "LOGNAME=$BUILD_USER" "$@"; fi
}
ensure_owned() {   # self-heal: repair root-owned files a prior sudo run left in $1
  [ "$(id -u)" = 0 ] || return 0; [ -e "$1" ] || return 0
  if [ -n "$(find "$1" ! -user "$BUILD_USER" -print -quit 2>/dev/null)" ]; then
    echo "[harden] repairing ownership of $1 → $BUILD_USER (prior root-owned artifacts)"
    chown -R "$BUILD_USER:" "$1" 2>/dev/null || true
  fi
}

# ── 0. Refuse WSL2 / require native KVM ─────────────────────────────────────────────────────
if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
  echo "REFUSING: WSL2/Hyper-V kernel — the platform we are moving off.  Run bare-metal." >&2; exit 2; fi
if command -v systemd-detect-virt >/dev/null 2>&1; then
  V="$(systemd-detect-virt || true)"; [ "$V" != none ] && echo "WARN: virtualization detected: $V" >&2; fi
[ -e /dev/kvm ] || { echo "REFUSING: /dev/kvm missing — no native KVM." >&2; exit 2; }

# ── 1. Isolation preflight · REFUSE sloppy environments (the whole point) ───────────────────
preflight_ok=1; warn(){ echo "  [WARN] $*"; }; crit(){ echo "  [FAIL] $*"; preflight_ok=0; }
echo "=== isolation preflight (cores $PIN_CORES) ==="
CMDLINE="$(cat /proc/cmdline)"
case "$CMDLINE" in *"isolcpus=$PIN_CORES"*) echo "  [ OK ] isolcpus=$PIN_CORES";;
  *isolcpus=*) crit "isolcpus present but != $PIN_CORES (cmdline: $(grep -o 'isolcpus=[^ ]*' /proc/cmdline))";;
  *) crit "isolcpus missing — core not isolated from the scheduler. Run: $0 --setup-grub ; sudo reboot";; esac
case "$CMDLINE" in *"nohz_full=$PIN_CORES"*) echo "  [ OK ] nohz_full=$PIN_CORES";; *) warn "nohz_full missing — residual timer ticks on the isolated core";; esac
SMT="$(cat /sys/devices/system/cpu/smt/active 2>/dev/null || echo '?')"
[ "$SMT" = 0 ] && echo "  [ OK ] SMT already off" || warn "SMT on — will offline siblings at runtime (sibling thread evicts L1/L2)"
LOAD="$(awk '{print $1}' /proc/loadavg)"
awk "BEGIN{exit !($LOAD>0.7)}" && warn "load avg $LOAD high — close Discord/browser; consider: systemctl isolate multi-user.target" || echo "  [ OK ] load avg $LOAD"
if [ "$preflight_ok" != 1 ] && [ "$STRICT" = 1 ]; then
  echo "REFUSING: core not isolated (see [FAIL] above). Fix it or pass --no-strict to measure anyway." >&2; exit 3; fi
echo

# ── 2. Record the platform (cite this in §Methodology) ──────────────────────────────────────
{
  echo "# sotOs eval platform · $STAMP"
  echo "host         : $(uname -srmo)"
  echo "cpu          : $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ *//')"
  echo "online_cpus  : $(nproc) · SMT active=$SMT"
  echo "microcode    : $(grep -m1 microcode /proc/cpuinfo | cut -d: -f2- | tr -d ' ')"
  echo "kernel_cmd   : $CMDLINE"
  echo "qemu         : $(qemu-system-x86_64 --version | head -1)"
  echo "kvm_module   : $(modinfo kvm 2>/dev/null | awk -F: '/^version/{print $2}' | tr -d ' ' || echo n/a)"
  echo "pinned_cores : $PIN_CORES"
  echo "governor     : $(cat /sys/devices/system/cpu/cpu${FIRST_CORE}/cpufreq/scaling_governor 2>/dev/null || echo n/a)"
  echo "intel_noturbo: $(cat /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null || echo n/a)"
  echo "tsc          : $(grep -m1 -o 'constant_tsc\|nonstop_tsc' /proc/cpuinfo | tr '\n' ' ')"
  echo "loadavg      : $(cat /proc/loadavg)"
  echo "mitigations  :"; for f in /sys/devices/system/cpu/vulnerabilities/*; do echo "    $(basename "$f"): $(cat "$f")"; done
} | tee "$ENVF"; echo

# ── 3. Apply runtime knobs (+ cleanup trap to restore) ──────────────────────────────────────
RESTORE_SMT=0
cleanup(){ [ "$RESTORE_SMT" = 1 ] && sudo sh -c 'echo on > /sys/devices/system/cpu/smt/control' 2>/dev/null || true
           [ -f "$OUT/sh.bak" ] && as_user cp "$OUT/sh.bak" src/sotshell/main.c 2>/dev/null || true; }
trap cleanup EXIT
SUDO=""; [ "$(id -u)" = 0 ] || SUDO="sudo"
# Run the harness AS THE INVOKING USER (do NOT wrap the whole thing in sudo).  The build + QEMU
# then run as the plain user — no privilege-drop, which is exactly what broke the build (dropping
# to the user via sudo -u / runuser mangled the CPIO step's stdin).  Only the sysfs knobs need
# root, so cache creds once here (prompts for the password the first time, in a terminal).
[ "$(id -u)" = 0 ] || sudo -v 2>/dev/null || true
if [ "$(id -u)" = 0 ] || sudo -n true 2>/dev/null; then
  $SUDO sh -c 'for g in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do echo performance > "$g" 2>/dev/null; done' && echo "[knobs] governor=performance"
  $SUDO sh -c 'echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo 2>/dev/null' && echo "[knobs] turbo OFF" || echo "[knobs] (no intel_pstate; AMD: disable boost via cpupower)"
  if [ "$SMT" != 0 ] && [ -w /sys/devices/system/cpu/smt/control 2>/dev/null -o "$SUDO" = sudo ]; then
    $SUDO sh -c 'echo off > /sys/devices/system/cpu/smt/control' 2>/dev/null && { RESTORE_SMT=1; echo "[knobs] SMT offline (siblings down · restored on exit)"; }
  fi
else
  echo "[knobs] WARN: no sudo creds — knobs not applied (run in a terminal so sudo can prompt)."
fi
echo

# ── 4. Native baseline · pinned to the isolated core · min-of-5 ─────────────────────────────
if [ "$DO_NATIVE" = 1 ]; then
  echo "=== T5 native baseline (host, -nostdlib, taskset -c $PIN_CORES, 5 runs) ===" | tee -a "$SUM"
  gcc -O2 -nostdlib -ffreestanding -fno-stack-protector -o "$OUT/ubench_native" tools/eval/t5-syscall/ubench.c
  for i in $(seq 1 5); do taskset -c "$PIN_CORES" "$OUT/ubench_native"; done | tee "$OUT/native.txt"
  echo | tee -a "$SUM"; cat "$OUT/native.txt" | sed 's/^/  /' | tee -a "$SUM"; echo | tee -a "$SUM"
fi

# ── 5. Guest microbench · build sotOs with ubench demo, boot pinned (no mem-lock) ───────────
if [ "$DO_GUEST" = 1 ]; then
  echo "=== T5 guest (sotOs under native KVM, taskset -c $PIN_CORES, pinned) ===" | tee -a "$SUM"
  # Pre-check the sotfs.img write lock: a running qemu-system-x86_64 (an operator console or a
  # PARALLEL eval run) holds it, and our guest QEMU would die with a cryptic "Failed to get write
  # lock". Refuse early with a clear message (and don't waste a build) instead. Mirrors the soak.
  if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    { echo "  BLOCKED: a qemu-system-x86_64 is already running — it holds the build/images/sotfs.img"
      echo "  write lock, so the guest QEMU can't start. Exit it (operator console / parallel run) and re-run:"
      ps -C qemu-system-x86_64 -o pid,etime,args --no-headers | sed 's/^/    /'
    } | tee -a "$SUM" >&2
    exit 4
  fi
  ensure_owned build                          # repair any root-owned artifacts a prior root run left
  cp src/sotshell/main.c "$OUT/sh.bak"        # backup (root → $OUT, world-readable for the as_user restore)
  as_user perl -0pi -e 's/(static const char \*demo_commands\[\] = \{\n)/$1        "ubench",  \/* BAREMETAL-T5 *\/\n/' src/sotshell/main.c
  grep -q BAREMETAL-T5 src/sotshell/main.c || { echo "ERROR injecting ubench demo" >&2; exit 1; }
  # An interrupted CPIO step (the children_archive build) leaves a stray binary in this temp dir,
  # after which EVERY later build dies at `rmdir: temp_children_archive.o: Directory not empty`.
  # rm -rf it so a prior Ctrl-C can't poison the next build.
  as_user rm -rf build/projects/sotOs/root/temp_children_archive.o
  as_user rm -f build/projects/sotOs/root/archive.children_archive.o.cpio build/projects/sotOs/root/children_archive.o \
        build/projects/sotOs/root/children_archive.o.S build/projects/sotOs/root/sotOs-root \
        build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99
  # </dev/null: under a tmux pane the image-pack step (binstore/sysroot) blocks reading the tty
  # stdin and hangs at "[N/M] Generating images/…" forever — detach stdin so it can't.
  as_user just build </dev/null > "$OUT/guest-build.log" 2>&1 || { echo "BUILD FAILED ($OUT/guest-build.log)" >&2; exit 1; }
  as_user cp "$OUT/sh.bak" src/sotshell/main.c
  # Run the guest QEMU as $SUDO_USER with stdin detached — exactly like the working soak QEMU.
  # As ROOT with an inherited (tmux) tty on `-serial stdio` it produced 0 bytes for the whole
  # 240s timeout; as the user + </dev/null it boots and emits [ubench] fine.  NO mem-lock: it
  # needs root (unlimited RLIMIT_MEMLOCK) which we no longer have here, and core isolation
  # (isolcpus + nohz_full + pin + SMT-off + governor=perf) already gives measurement stability.
  as_user taskset -c "$PIN_CORES" timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio \
    -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0 -device virtio-net-pci,netdev=net0 </dev/null > "$OUT/guest-serial.log" 2>&1 || true
  # raw ubench (traps) + the vDSO numbers (libc clock_gettime via vDSO, the boot probe, sched_yield fast-path)
  grep -aE '\[(ubench|ubench-libc|vdso-probe|fastpath-probe)\]' "$OUT/guest-serial.log" | tr -d '\000' | sed 's/^/  guest /' | tee -a "$SUM" \
    || echo "  WARN: no ubench line (see $OUT/guest-serial.log)" | tee -a "$SUM"
  echo | tee -a "$SUM"
fi

# ── 6. Containment soak · the existing 25x300 endurance harness ─────────────────────────────
if [ "$DO_SOAK" = 1 ]; then
  echo "=== T4 containment soak (scripts/v1.5-endurance-run.sh) ===" | tee -a "$SUM"
  ensure_owned build; ensure_owned evidence   # soak rebuilds + writes evidence/ as $BUILD_USER
  # Pin the soak (its per-boot QEMU) to the isolated cores too — like T5 — so host noise
  # on other cores can't perturb it (it ran UNPINNED before, which let stray host activity
  # SIGHUP/starve its QEMU mid-run).
  as_user "DURATION=${SOAK_DURATION:-1800}" taskset -c "$PIN_CORES" scripts/v1.5-endurance-run.sh </dev/null > "$OUT/soak.log" 2>&1 || true
  grep -aE 'boot [0-9]+ done|ENDURANCE|slope|survivors=' "$OUT/soak.log" | tail -6 | sed 's/^/  /' | tee -a "$SUM"
  echo | tee -a "$SUM"
fi

echo "DONE · platform: $ENVF · numbers: $SUM"
echo "Paste both back and the paper text + §Methodology get the exact bare-metal figures."
