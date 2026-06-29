#!/usr/bin/env bash
# tools/vdso-deception-gate.sh — vDSO arc Task 13 · deception gate
#
# Proves that the [vdso] entry in /proc/self/maps points at a REAL mapped
# region that contains a valid, dumpable ELF, and that the maps address
# agrees with AT_SYSINFO_EHDR from the auxv.  Before Task 4, the maps line
# had a hardcoded fake address with no ELF behind it — a forensic tell.
#
# Pass criteria (all must hold):
#   1. [vdso-deception] line present in serial output
#   2. elf_magic=OK   — first 4 bytes at maps_vdso are \x7fELF
#   3. match=1        — maps_vdso == AT_SYSINFO_EHDR (consistent story)
#   4. maps_vdso      — plausible address in the sotOs vDSO region
#                       (0x7f5000000000..0x7f5000010000)
#
# Exit 0 on PASS, non-zero on failure (serial tail printed).
#
# Usage:
#   tools/vdso-deception-gate.sh
#   SKIP_BUILD=1 tools/vdso-deception-gate.sh
#   TIMEOUT=300  tools/vdso-deception-gate.sh

set -uo pipefail
export LC_ALL=C

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

SERIAL_LOG="$(mktemp /tmp/sotos-vdso-deception-serial.XXXXXX)"
QPID=0

cleanup() {
    [ "$QPID" -gt 0 ] && kill "$QPID" 2>/dev/null || true
    rm -f "$SERIAL_LOG"
}
trap cleanup EXIT

TIMEOUT="${TIMEOUT:-240}"
SKIP_BUILD="${SKIP_BUILD:-0}"

# ── 1. Build ────────────────────────────────────────────────────────────────
if [ "$SKIP_BUILD" != "1" ]; then
    echo "[vdso-deception-gate] building (just build) …"
    just build </dev/null > /tmp/sotos-vdso-deception-build.log 2>&1 || {
        echo "[vdso-deception-gate] BUILD FAILED — see /tmp/sotos-vdso-deception-build.log"
        tail -20 /tmp/sotos-vdso-deception-build.log
        exit 2
    }
    echo "[vdso-deception-gate] build OK"
fi

# Verify the required images are present.
for img in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$img" ] || { echo "[vdso-deception-gate] MISSING: $img"; exit 2; }
done

# ── 2. Boot headless QEMU ───────────────────────────────────────────────────
echo "[vdso-deception-gate] booting QEMU headless (timeout=${TIMEOUT}s) …"
: > "$SERIAL_LOG"

timeout "$TIMEOUT" qemu-system-x86_64 \
    -m 4096 \
    -display none \
    -serial "file:${SERIAL_LOG}" \
    -enable-kvm \
    -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0 \
    -device virtio-net-pci,netdev=net0 \
    </dev/null &
QPID=$!

# Poll until the deception marker appears or QEMU exits.
DEADLINE=$(( $(date +%s) + TIMEOUT - 10 ))
while true; do
    if LC_ALL=C grep -qaF '[vdso-deception]' "$SERIAL_LOG" 2>/dev/null; then
        break
    fi
    if ! kill -0 "$QPID" 2>/dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "[vdso-deception-gate] TIMEOUT waiting for [vdso-deception] marker"
        echo "--- serial tail (last 40 lines) ---"
        tail -40 "$SERIAL_LOG" | tr -d '\000'
        exit 1
    fi
    sleep 2
done

kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
QPID=0

echo "[vdso-deception-gate] QEMU stopped · checking serial output …"

# ── 3. Validate the gate marker ────────────────────────────────────────────
FAIL=0

DEC_LINE="$(LC_ALL=C grep -aF '[vdso-deception]' "$SERIAL_LOG" | tr -d '\000' | head -1)"

if [ -z "$DEC_LINE" ]; then
    echo "FAIL · [vdso-deception] line not found in serial output"
    FAIL=1
else
    echo "DECEPTION: $DEC_LINE"

    # ── elf_magic=OK ──────────────────────────────────────────────────────
    if echo "$DEC_LINE" | grep -q 'elf_magic=OK'; then
        echo "PASS · elf_magic=OK (first 4 bytes at maps_vdso are \\x7fELF)"
    else
        echo "FAIL · elf_magic not OK — maps [vdso] address has no ELF (the tell is still present)"
        FAIL=1
    fi

    # ── match=1 ───────────────────────────────────────────────────────────
    MATCH="$(echo "$DEC_LINE" | grep -oP '(?<=match=)[0-9]+')"
    if [ -z "$MATCH" ]; then
        echo "FAIL · could not extract match= from deception line"
        FAIL=1
    elif [ "$MATCH" -eq 1 ]; then
        echo "PASS · match=1 (maps_vdso == AT_SYSINFO_EHDR — consistent story)"
    else
        echo "FAIL · match=${MATCH} (maps_vdso != AT_SYSINFO_EHDR — auxv and maps disagree)"
        FAIL=1
    fi

    # ── maps_vdso in expected sotOs vDSO region ───────────────────────────
    MAPS_VDSO="$(echo "$DEC_LINE" | grep -oP '(?<=maps_vdso=)0x[0-9a-fA-F]+')"
    if [ -z "$MAPS_VDSO" ]; then
        echo "FAIL · could not extract maps_vdso= address"
        FAIL=1
    else
        MAPS_NUM=$(( MAPS_VDSO ))
        VDSO_LO=$(( 0x7f5000000000 ))
        VDSO_HI=$(( 0x7f5000010000 ))
        if [ "$MAPS_NUM" -ge "$VDSO_LO" ] && [ "$MAPS_NUM" -lt "$VDSO_HI" ]; then
            echo "PASS · maps_vdso=${MAPS_VDSO} is in vDSO region [0x7f5000000000, 0x7f5000010000)"
        else
            echo "FAIL · maps_vdso=${MAPS_VDSO} (${MAPS_NUM}) not in expected vDSO region"
            FAIL=1
        fi
    fi
fi

# ── 4. Summary ─────────────────────────────────────────────────────────────
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "[vdso-deception-gate] FAIL — serial tail:"
    tail -50 "$SERIAL_LOG" | tr -d '\000'
    exit 1
fi

echo ""
echo "[vdso-deception-gate] PASS — [vdso] in /proc/self/maps points at a real dumpable ELF; auxv and maps agree"
exit 0
