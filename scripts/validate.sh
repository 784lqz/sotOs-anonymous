#!/usr/bin/env bash
# Pillar-4 P4a · headless validation harness (SCALED proxy — ~180s single pass; the
# 24h soak + leak-over-time is P4b). Asserts: 3 families spawned at DISTINCT slots +
# ran-to-success + DECEPTION FIRED (containment) + the [validate] DONE liveness proof (a
# root crash mid-run kills the fault loop so DONE never prints) + regression-delta.
# Exit 0=PASS / 1=FAIL.
set -u
LOG="${1:-/tmp/p4a.log}"
REPORT="scripts/validate-report.txt"
: > "$REPORT"
pass=0; fail=0
chk() { # name, regex
    if LC_ALL=C grep -aqE "$2" "$LOG"; then echo "PASS  $1" | tee -a "$REPORT"; pass=$((pass+1));
    else echo "FAIL  $1   (/$2/)" | tee -a "$REPORT"; fail=$((fail+1)); fi
}
echo "=== P4a validation report ($(wc -l < "$LOG") log lines) · SCALED proxy, not 24h ===" | tee -a "$REPORT"

# --- concurrency: 3 DISTINCT spawn slots (B3-ii: not the slot=2 proxy) ---
nspawn=$(LC_ALL=C grep -acE '\[validate\] spawn .* slot=' "$LOG")
ndistinct=$(LC_ALL=C grep -aoE '\[validate\] spawn .* slot=[0-9]+' "$LOG" | grep -oE 'slot=[0-9]+' | sort -u | wc -l)
if [ "$nspawn" -eq 3 ] && [ "$ndistinct" -eq 3 ]; then
    echo "PASS  3 families spawned at 3 distinct slots" | tee -a "$REPORT"; pass=$((pass+1));
else echo "FAIL  concurrent spawn ($nspawn lines, $ndistinct distinct slots; want 3/3)" | tee -a "$REPORT"; fail=$((fail+1)); fi
chk "validate START (before the loop = concurrent)" '\[validate\] START 3 families'

# --- SURVIVAL PROOF: [validate] DONE means orch serviced all 3 concurrent fixtures to
# exit (sotbox_alive_count==0) WITHOUT a fatal root fault — a root crash mid-run would
# kill the fault loop and DONE would never print. This is the authoritative liveness gate.
# (validate runs EARLY in the demo; the full demo's slow/live-drain tail does NOT reach
# ACPI POWEROFF within the headless QEMU window in this sandbox — same as the b/d boots,
# which are judged by regression-delta, not POWEROFF. So POWEROFF is informational here.)
chk "validate DONE (orch survived all 3 concurrent)" '\[validate\] DONE'
if LC_ALL=C grep -aqE 'POWEROFF' "$LOG"; then echo "PASS  clean ACPI POWEROFF (bonus)" | tee -a "$REPORT"; pass=$((pass+1));
else echo "INFO  no POWEROFF (long demo times out post-validate · expected in-sandbox; DONE is the liveness proof)" | tee -a "$REPORT"; fi

# --- per-family RAN-to-success (CALIBRATE these vs the FIRST gate-boot serial — B2-i) ---
# canary fnv 0x3719b2be is the POST-δ 1280x720 asset checksum (v0.74); re-confirm at boot.
chk "trojan canary-capture"   '\[wl-capture\] captured 1280x720 fnv1a=0x3719b2be'
chk "infostealer TLS C2"     '\[tls-probe\] handshake OK'
chk "infostealer app-data"   '\[tls-probe\] app-data OK'
chk "ransomware persistence" '\[stage7-c\] === STAGE 7 complete'

# --- CONTAINMENT: the deception actually FIRED (B2-ii: not just "ran") ---
# infostealer C2 was synth-redirected (NOT real internet); canary capture is itself
# the installed-scene proof (the fnv match above). CALIBRATE the synth marker vs serial.
chk "containment: C2 synth-redirect" '\[synth\].*(FAST-PATH|connect|redirect)'
chk "containment: canary capture traced" '(CANARY_SCREENSHOT|\[l14a-capture\]|canary view)'

# --- regression-delta vs v0.74.0 ---
chk "regression TLS 0xc02f"  'suite=0xc02f'
chk "regression invisible"   'invisible=YES'

# --- secondary fault signal (NOT the sole gate — the negative proof above is) ---
faults=$(LC_ALL=C grep -aiE 'rootserver.*fault|Unhandled .*[Ee]xception|kernel.*(panic|halt)|alloc_frame.*failed|cap fault' "$LOG" \
          | grep -aviE 'guest|VMFault|sotbox|untyped|delegating|delegated' | wc -l)
if [ "$faults" -eq 0 ]; then echo "PASS  fault-string scan (0)" | tee -a "$REPORT"; pass=$((pass+1));
else echo "WARN  fault-string scan ($faults — inspect; the [validate] DONE liveness proof is authoritative)" | tee -a "$REPORT"; fi

echo "=== $pass passed, $fail failed ===" | tee -a "$REPORT"
[ "$fail" -eq 0 ] && { echo "VALIDATION PASS"; exit 0; } || { echo "VALIDATION FAIL"; exit 1; }
