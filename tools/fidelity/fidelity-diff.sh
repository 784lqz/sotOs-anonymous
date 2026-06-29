#!/usr/bin/env bash
# sotOs · differential-fidelity harness.
#
# Runs an identical fingerprint-probe battery on (a) a REAL alpine:3.20 (podman)
# and (b) sotOs (boot + demo-injection + serial capture), normalizes volatile
# fields, and diffs per-probe.  Every divergence is a candidate fingerprint.
#
# The success metric is NOT "match count" (sotOs is a coherent 1-core Alpine VM;
# the reference host has different cores/mem — values legitimately differ between
# any two machines).  It is: NO "can't open" (serving gaps), structural parity
# (field presence/count), and internal identity coherence (uname == /proc/version
# == /sys/kernel/osrelease, os-release == busybox version).
#
# Usage:  tools/fidelity/fidelity-diff.sh ref   # capture the real-Alpine reference only
#         tools/fidelity/fidelity-diff.sh sot   # boot sotOs + capture only
#         tools/fidelity/fidelity-diff.sh       # both + diff report
#
# Requires: podman (native on Fedora: `sudo dnf install podman`).  On the WSL dev
# box podman lives in the podman-machine distro — capture the reference there with
#   wsl -d podman-machine-default podman run --rm alpine:3.20 sh -c "$(cat ...)" > build/fp-ref.txt
set -u
cd "$(git rev-parse --show-toplevel)" || exit 2
MODE="${1:-all}"
REF=build/fp-ref.txt          # generated artifact (build/ is gitignored)
SOT=/tmp/fp-sot.txt
SRC=src/sotshell/main.c

# Probe battery · ONE line (≤ ~340 chars · fits cmd_exec_real's 368-byte argv pool
# as a single busybox `sh -c`).  @FP-<label> markers section the output.  Keep this
# in sync with the perl-injected copy in capture_sot below.
BATTERY='echo @FP-uname; uname -a; echo @FP-osrel; cat /etc/os-release; echo @FP-alpinerel; cat /etc/alpine-release; echo @FP-nproc; nproc; echo @FP-cpu; cat /proc/cpuinfo; echo @FP-mem; cat /proc/meminfo; echo @FP-kver; cat /proc/version; echo @FP-sysrel; cat /sys/kernel/osrelease; echo @FP-id; id; echo @FP-END'

normalize() {
    sed -E \
        -e 's/0x[0-9a-fA-F]+/0xADDR/g' \
        -e 's/[0-9]{4,} ?kB/NUM kB/g' \
        -e 's/MHz[[:space:]]*:.*/MHz : NUM/' \
        -e 's/bogomips[[:space:]]*:.*/bogomips : NUM/' \
        -e 's/[0-9]+\.[0-9]+ [0-9]+\.[0-9]+ [0-9]+\.[0-9]+/LOAD LOAD LOAD/' \
        -e 's/^[0-9]+\.[0-9]+ [0-9]+\.[0-9]+$/UPTIME IDLE/' \
        -e 's/\r$//' \
    | sed -E '/^[[:space:]]*$/d'
}
extract_section() { awk -v s="@FP-$1" '$0 ~ s {f=1;next} /@FP-/ {f=0} f' "$2"; }

capture_ref() {
    if ! command -v podman >/dev/null 2>&1; then
        echo "[fp] podman not found.  On Fedora: sudo dnf install podman."
        echo "     (WSL dev box: capture inside podman-machine — see header.)"
        [ -s "$REF" ] && { echo "[fp] reusing existing $REF"; return 0; }
        return 2
    fi
    echo "[fp] capturing REAL alpine:3.20 reference via podman -> $REF"
    podman run --rm alpine:3.20 sh -c "$BATTERY" > "$REF" 2>&1
    echo "[fp] reference: $(wc -l < "$REF") lines"
}

capture_sot() {
    if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
        echo "[fp] BLOCKED: a QEMU is live (sotfs.img lock)."; return 3
    fi
    local BAK=/tmp/fp-main.c.bak
    cp "$SRC" "$BAK" || return 2           # snapshot WITH uncommitted edits
    trap '[ -f /tmp/fp-main.c.bak ] && cp /tmp/fp-main.c.bak '"$SRC"' && rm -f /tmp/fp-main.c.bak' RETURN
    if ! grep -q 'FP-INJECT' "$SRC"; then
      perl -0pi -e 's/(static const char \*demo_commands\[\] = \{\n)/$1        "echo \@FP-uname; uname -a; echo \@FP-osrel; cat \/etc\/os-release; echo \@FP-alpinerel; cat \/etc\/alpine-release; echo \@FP-nproc; nproc; echo \@FP-cpu; cat \/proc\/cpuinfo; echo \@FP-mem; cat \/proc\/meminfo; echo \@FP-kver; cat \/proc\/version; echo \@FP-sysrel; cat \/sys\/kernel\/osrelease; echo \@FP-id; id; echo \@FP-END",   \/* FP-INJECT *\/\n/' "$SRC"
    fi
    grep -q 'FP-INJECT' "$SRC" || { echo "[fp] inject failed"; return 2; }
    echo "[fp] rebuilding (fresh sotfs.img)..."
    rm -f build/images/sotfs.img
    just build > /tmp/fp-build.log 2>&1 || { echo "[fp] build FAILED"; tail -8 /tmp/fp-build.log; return 2; }
    local ACCEL; ACCEL=$(test -w /dev/kvm && echo "-enable-kvm -cpu host" || echo "-accel tcg -cpu max")
    echo "[fp] booting sotOs ($ACCEL)..."
    rm -f "$SOT.raw"
    timeout 600 qemu-system-x86_64 -m 2048 -display none -serial stdio $ACCEL \
        -kernel build/images/kernel-x86_64-pc99 \
        -initrd build/images/sotOs-root-image-x86_64-pc99 \
        -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
        -device virtio-blk-pci,drive=sd0 \
        -netdev user,id=net0 -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
        < /dev/null > "$SOT.raw" 2>&1
    LC_ALL=C grep -aE '@FP-|guest:' "$SOT.raw" | sed -E 's/^.*guest:[0-9]+[^ ]* //' > "$SOT"
    echo "[fp] sotOs: $(wc -l < "$SOT") probe lines ($(wc -l < "$SOT.raw") serial lines)"
}

case "$MODE" in ref|all) capture_ref || exit $? ;; esac
case "$MODE" in sot|all) capture_sot || exit $? ;; esac
[ "$MODE" = all ] || { echo "[fp] mode=$MODE done"; exit 0; }

echo ""
echo "================ DIFFERENTIAL FIDELITY REPORT ================"
LABELS="uname osrel alpinerel nproc cpu mem kver sysrel id"
match=0; diverge=0; cantopen=0
for lab in $LABELS; do
    r=$(extract_section "$lab" "$REF" | normalize)
    s=$(extract_section "$lab" "$SOT" | normalize)
    echo "$s" | grep -q "can't open" && cantopen=$((cantopen+1))
    if [ "$r" = "$s" ]; then echo "── [$lab] MATCH"; match=$((match+1))
    else
        echo "── [$lab] DIVERGE ▼"
        diff <(printf '%s\n' "$r") <(printf '%s\n' "$s") | sed 's/^/    /' | head -40
        diverge=$((diverge+1))
    fi
done
echo "============================================================="
echo "RESULT · $match match · $diverge diverge · $cantopen can't-open (serving gaps — want 0)"
echo "  ref=$REF  sot=$SOT"
