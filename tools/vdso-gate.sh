#!/usr/bin/env bash
# tools/vdso-gate.sh — vDSO arc Task 5 · F1 boot gate
#
# Builds sotOs, boots headless QEMU, and asserts:
#   1. [vdso-probe] resolved=0x<addr>  — non-zero address in the vDSO range
#   2. real=<epoch>                    — plausible 2026 epoch (≥ 1781514000)
#   3. mono=<sec>.<nsec>               — monotonic reads and is >= 0
#
# Exit 0 on PASS, non-zero on failure (serial tail printed).
#
# Usage:
#   tools/vdso-gate.sh
#   SKIP_BUILD=1 tools/vdso-gate.sh   # skip rebuild (use existing images)
#   TIMEOUT=300 tools/vdso-gate.sh    # override QEMU timeout (default 240s)

set -uo pipefail
export LC_ALL=C

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

SERIAL_LOG="$(mktemp /tmp/sotos-vdso-serial.XXXXXX)"
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
    echo "[vdso-gate] building (just build) …"
    just build </dev/null > /tmp/sotos-vdso-build.log 2>&1 || {
        echo "[vdso-gate] BUILD FAILED — see /tmp/sotos-vdso-build.log"
        tail -20 /tmp/sotos-vdso-build.log
        exit 2
    }
    echo "[vdso-gate] build OK"
fi

# Verify the required images are present.
for img in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$img" ] || { echo "[vdso-gate] MISSING: $img"; exit 2; }
done

# ── 2. Boot headless QEMU ───────────────────────────────────────────────────
echo "[vdso-gate] booting QEMU headless (timeout=${TIMEOUT}s) …"
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

# Poll until both the vdso-probe AND the ubench-libc output appear, or until
# QEMU exits (all demo commands ran and the VM halted naturally).
# ubench-libc is spawned right after vdso-probe in demo_commands, so we need
# to keep QEMU alive until both markers are in the log.
DEADLINE=$(( $(date +%s) + TIMEOUT - 10 ))
while true; do
    HAVE_PROBE=0
    HAVE_LIBC=0
    LC_ALL=C grep -qaE '\[vdso-probe\] (resolved=|FAIL)' "$SERIAL_LOG" 2>/dev/null && HAVE_PROBE=1
    LC_ALL=C grep -qaE '\[ubench-libc\] clock_gettime min=' "$SERIAL_LOG" 2>/dev/null && HAVE_LIBC=1
    if [ "$HAVE_PROBE" -eq 1 ] && [ "$HAVE_LIBC" -eq 1 ]; then
        break
    fi
    # Check if QEMU exited (normal: boot finishes all demo commands and halts).
    if ! kill -0 "$QPID" 2>/dev/null; then
        break
    fi
    if [ "$(date +%s)" -ge "$DEADLINE" ]; then
        echo "[vdso-gate] TIMEOUT waiting for [vdso-probe] + [ubench-libc] markers"
        echo "--- serial tail (last 40 lines) ---"
        tail -40 "$SERIAL_LOG" | tr -d '\000'
        exit 1
    fi
    sleep 2
done

# Kill QEMU once we have what we need.
kill "$QPID" 2>/dev/null || true
wait "$QPID" 2>/dev/null || true
QPID=0

echo "[vdso-gate] QEMU stopped · checking serial output …"

# ── 3. Validate the gate marker ────────────────────────────────────────────
FAIL=0
PROBE_LINE=""

# Extract the probe output line (the one from the sotbox, not the orch spawn confirmation).
PROBE_LINE="$(LC_ALL=C grep -aE '\[vdso-probe\] (resolved=|FAIL)' "$SERIAL_LOG" | tr -d '\000' | head -1)"

if [ -z "$PROBE_LINE" ]; then
    echo "FAIL · [vdso-probe] line not found in serial output"
    FAIL=1
else
    echo "PROBE: $PROBE_LINE"

    # Check for FAIL message.
    if echo "$PROBE_LINE" | grep -q '\[vdso-probe\] FAIL'; then
        echo "FAIL · probe reported a failure: $PROBE_LINE"
        FAIL=1
    else
        # Extract resolved address (hex).
        RESOLVED="$(echo "$PROBE_LINE" | grep -oP '(?<=resolved=)0x[0-9a-fA-F]+')"
        if [ -z "$RESOLVED" ]; then
            echo "FAIL · could not extract resolved= address"
            FAIL=1
        else
            # Numeric value for range check.
            # SOTOS_VDSO_BASE = 0x7f5000000000 (PML4 entry 254, below seL4
            # KERNEL_RESERVED_START boundary at 0x7f8000000000).
            # load_bias = SOTOS_VDSO_EHDR + PT_LOAD.p_offset = +0x2000
            # __vdso_clock_gettime st_value ≈ 0x23e → runtime ≈ 0x7f500000223e
            RESOLVED_NUM=$(( RESOLVED ))   # bash arithmetic: 0x... is auto-hex
            VDSO_LO=$(( 0x7f5000000000 ))
            VDSO_HI=$(( 0x7f5000010000 ))
            if [ "$RESOLVED_NUM" -ge "$VDSO_LO" ] && [ "$RESOLVED_NUM" -lt "$VDSO_HI" ]; then
                echo "PASS · resolved=${RESOLVED} is in vDSO range [0x7f5000000000, 0x7f5000010000)"
            else
                echo "FAIL · resolved=${RESOLVED} (${RESOLVED_NUM}) not in vDSO range"
                FAIL=1
            fi
        fi

        # Extract and validate real= epoch.
        REAL_SEC="$(echo "$PROBE_LINE" | grep -oP '(?<=real=)-?[0-9]+')"
        if [ -z "$REAL_SEC" ]; then
            echo "FAIL · could not extract real= epoch"
            FAIL=1
        else
            MIN_EPOCH=1781514000   # 2026-06-14 (conservative floor)
            if [ "$REAL_SEC" -ge "$MIN_EPOCH" ]; then
                echo "PASS · real=${REAL_SEC} >= ${MIN_EPOCH} (plausible 2026 epoch)"
            else
                echo "FAIL · real=${REAL_SEC} < ${MIN_EPOCH} (not a plausible 2026 epoch)"
                FAIL=1
            fi
        fi

        # Extract and validate mono= (must be >= 0).
        MONO_SEC="$(echo "$PROBE_LINE" | grep -oP '(?<=mono=)-?[0-9]+')"
        if [ -z "$MONO_SEC" ]; then
            echo "FAIL · could not extract mono= value"
            FAIL=1
        else
            if [ "$MONO_SEC" -ge 0 ]; then
                echo "PASS · mono=${MONO_SEC} >= 0"
            else
                echo "FAIL · mono=${MONO_SEC} is negative"
                FAIL=1
            fi
        fi

        # ── No-trap proof (Task 6) ───────────────────────────────────────────
        # cgt_cycles = cost of ONE __vdso_clock_gettime(CLOCK_MONOTONIC) call,
        # measured rdtsc-to-rdtsc.  A trapping (syscall) call is ~8000-17000
        # cyc; a real in-guest vDSO call is in the hundreds.  Assert < 1500.
        CGT_CYC="$(echo "$PROBE_LINE" | grep -oP '(?<=cgt_cycles=)[0-9]+')"
        if [ -z "$CGT_CYC" ]; then
            echo "FAIL · could not extract cgt_cycles= (no-trap proof missing)"
            FAIL=1
        else
            if [ "$CGT_CYC" -lt 1500 ]; then
                echo "PASS · cgt_cycles=${CGT_CYC} < 1500 (no trap — real in-guest vDSO)"
            else
                echo "FAIL · cgt_cycles=${CGT_CYC} >= 1500 (looks like a trapping syscall)"
                FAIL=1
            fi
        fi

        # Monotonic must strictly increase across back-to-back reads.
        MONO_INC="$(echo "$PROBE_LINE" | grep -oP '(?<=mono_inc=)[0-9]+')"
        if [ -z "$MONO_INC" ]; then
            echo "FAIL · could not extract mono_inc="
            FAIL=1
        else
            if [ "$MONO_INC" -eq 1 ]; then
                echo "PASS · mono_inc=1 (CLOCK_MONOTONIC strictly increased)"
            else
                echo "FAIL · mono_inc=${MONO_INC} (CLOCK_MONOTONIC did not advance)"
                FAIL=1
            fi
        fi
    fi
fi

        # ── Task 7: gettimeofday / time / clock_getres fast-path (step 10) ─────
        GTOD_LINE="$(LC_ALL=C grep -aE '\[vdso-probe\] gtod=' "$SERIAL_LOG" | tr -d '\000' | head -1)"
        if [ -z "$GTOD_LINE" ]; then
            echo "FAIL · [vdso-probe] gtod= line not found (Task 7 fast-path missing)"
            FAIL=1
        else
            echo "PROBE: $GTOD_LINE"

            if echo "$GTOD_LINE" | grep -q '\[vdso-probe\] FAIL'; then
                echo "FAIL · Task 7 probe reported failure: $GTOD_LINE"
                FAIL=1
            else
                # gtod seconds
                GTOD_SEC="$(echo "$GTOD_LINE" | grep -oP '(?<=gtod=)-?[0-9]+')"
                if [ -z "$GTOD_SEC" ]; then
                    echo "FAIL · could not extract gtod= seconds"
                    FAIL=1
                elif [ "$GTOD_SEC" -ge 1781514000 ]; then
                    echo "PASS · gtod=${GTOD_SEC} >= 1781514000 (plausible 2026 epoch)"
                else
                    echo "FAIL · gtod=${GTOD_SEC} < 1781514000 (not a plausible epoch)"
                    FAIL=1
                fi

                # time() seconds
                TIME_SEC="$(echo "$GTOD_LINE" | grep -oP '(?<=time=)-?[0-9]+')"
                if [ -z "$TIME_SEC" ]; then
                    echo "FAIL · could not extract time= value"
                    FAIL=1
                elif [ "$TIME_SEC" -ge 1781514000 ]; then
                    echo "PASS · time=${TIME_SEC} >= 1781514000 (plausible 2026 epoch)"
                else
                    echo "FAIL · time=${TIME_SEC} < 1781514000 (not a plausible epoch)"
                    FAIL=1
                fi

                # clock_getres: expect res=0.000000001
                RES_NSEC="$(echo "$GTOD_LINE" | grep -oP '(?<=res=[0-9]\.)[0-9]+')"
                RES_SEC="$(echo "$GTOD_LINE" | grep -oP '(?<=res=)-?[0-9]+(?=\.)')"
                if [ -z "$RES_NSEC" ] || [ -z "$RES_SEC" ]; then
                    echo "FAIL · could not extract res= value"
                    FAIL=1
                elif [ "$RES_SEC" -eq 0 ] && [ "$RES_NSEC" -eq 1 ]; then
                    echo "PASS · res=0.000000001 (1ns resolution as expected)"
                else
                    echo "FAIL · res=${RES_SEC}.${RES_NSEC} != 0.000000001"
                    FAIL=1
                fi
            fi
        fi

        # ── Task 8: libc clock_gettime via vDSO (ubench-libc fast-path) ────────
        LIBC_LINE="$(LC_ALL=C grep -aE '\[ubench-libc\] clock_gettime min=' "$SERIAL_LOG" | tr -d '\000' | head -1)"
        if [ -z "$LIBC_LINE" ]; then
            echo "FAIL · [ubench-libc] clock_gettime line not found (Task 8 libc vDSO bench missing)"
            FAIL=1
        else
            echo "PROBE: $LIBC_LINE"
            LIBC_MIN="$(echo "$LIBC_LINE" | grep -oP '(?<=min=)[0-9]+')"
            if [ -z "$LIBC_MIN" ]; then
                echo "FAIL · could not extract min= from [ubench-libc] line"
                FAIL=1
            elif [ "$LIBC_MIN" -lt 1000 ]; then
                echo "PASS · [ubench-libc] clock_gettime min=${LIBC_MIN} < 1000 (libc routed through vDSO, no trap)"
            else
                echo "FAIL · [ubench-libc] clock_gettime min=${LIBC_MIN} >= 1000 (musl did NOT use the vDSO)"
                FAIL=1
            fi
        fi

# ── 4. Summary ─────────────────────────────────────────────────────────────
if [ "$FAIL" -ne 0 ]; then
    echo ""
    echo "[vdso-gate] FAIL — serial tail:"
    tail -50 "$SERIAL_LOG" | tr -d '\000'
    exit 1
fi

echo ""
echo "[vdso-gate] PASS — vDSO ELF parsed, __vdso_clock_gettime resolved and called"
exit 0
