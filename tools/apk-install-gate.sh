#!/usr/bin/env bash
# sotOs · apk-fs P4 Task 8 — end-to-end apk install acid test.
#
# A real `apk add --allow-untrusted --force-non-repository /root/fixture.apk`
# (real Alpine ncurses-terminfo-base, a no-dependency data package) runs inside a
# Tier-2 SSH session and satisfies the containment invariants:
#
#   I4 fidelity:   apk.static runs + completes (APK_RC=0); `apk info` lists the
#                  installed package; no ENOSYS/abort tell in the apk client output.
#   install proof: the package's files (etc/terminfo/*) are extracted + readable
#                  in-session (they landed in the per-session sotfs upper, base+
#                  union routing from Phases 1-2 + G1 mkdir).
#   I1/I2:         a SECOND ssh session (pristine base) does NOT list the package
#                  in `apk info`, the extracted files are ABSENT, and the base
#                  /lib/apk/db/installed has no package entry. SESSB_ALIVE guards
#                  against a silent-session false-green.
#   IOC:           the serial log contains `package install` (PACKAGE_INSTALL emit
#                  on the Tier-2 write to /lib/apk/db/installed).
#
# NOTE on I3 (an installed BINARY runs): proven separately + idempotently by
# tools/apk-upperexec-gate.sh (a dynamic-musl ELF written into the upper at runtime
# executes via resolve_path's VFS-upper fallback). ncurses-terminfo-base is a
# data-only package (no ELF) chosen because it has NO shared-lib (so:) dependencies
# that apk's solver would reject against the empty seeded DB.
#
# Exit codes: 0=PASS, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU live)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PKG=ncurses-terminfo-base
# Signature mode (Task 9): 'untrusted' (default · the floor) passes --allow-untrusted
# so apk skips RSA verify; 'verify' (opt-in: APK_SIGN=verify) DROPS it so apk verifies
# the fixture's .SIGN.RSA against /etc/apk/keys/alpine-devel@...6165ee59.rsa.pub.
SIGN_MODE="${APK_SIGN:-untrusted}"
if [ "$SIGN_MODE" = verify ]; then APK_FLAGS="--force-non-repository"
else APK_FLAGS="--allow-untrusted --force-non-repository"; fi
PORT=18022
SLOG=/tmp/sotos-apk-install-serial.log
ALOG=/tmp/sotos-apk-install-sessA.log
BLOG=/tmp/sotos-apk-install-sessB.log

# ── BLOCKED guard ─────────────────────────────────────────────────────────────
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[apk-install-gate] BLOCKED: operator QEMU live"; exit 3
fi

# ── pre-flight ────────────────────────────────────────────────────────────────
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[apk-install-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

# ── boot headless ─────────────────────────────────────────────────────────────
echo "[apk-install-gate] SIGN_MODE=$SIGN_MODE (apk flags: $APK_FLAGS)"
echo "[apk-install-gate] booting honeypot headless…"
timeout 300 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT

# wait for :22 LISTEN
for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[apk-install-gate] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-apk-install-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

# Emit one command to the SSH shell, paced. Single-quote the arg to keep $?, $(),
# and embedded '...' LITERAL on the host — they reach the VM's bash unexpanded
# (no host-side eval, which was the prior quoting trap).
send(){ printf '%s\n' "$1"; sleep "${2:-3}"; }

run_ssh() {
    # $1=log file  $2=function that emits the command sequence to stdout.
    local LOG="$1" FN="$2"
    "$FN" | \
        timeout 180 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

# ── Session A — apk add + install assertions ───────────────────────────────────
echo "[apk-install-gate] session A (apk add + assertions)…"
session_a(){
    sleep 3
    send 'echo SESSA_ALIVE' 2
    # --no-network: skip the doomed APKINDEX fetch (Tier-2 has no real egress).
    # --force-non-repository: install the local file-path package (apk policy).
    send "apk --no-network add $APK_FLAGS /root/fixture.apk" 12
    send 'echo APK_RC=$?' 2
    send 'apk info; echo APK_INFO_DONE' 5
    send 'ls /etc/terminfo; echo TERMINFO_LS_DONE' 3
    send 'cat /etc/terminfo/l/linux | wc -c; echo TERMINFO_FILE_DONE' 3
    send 'cat /lib/apk/db/installed | head -20; echo INSTALLED_HEAD_DONE' 3
    send 'exit' 5
}
run_ssh "$ALOG" session_a

echo "[apk-install-gate] session A done · analysing…"
clean_a(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"; }

fail=0

# Session A liveness
[ "$(clean_a | grep -ac '^SESSA_ALIVE$')" -ge 1 ] && \
    echo "PASS · session A is alive (ran to the prompt)" || \
    { echo "FAIL · session A produced no SESSA_ALIVE marker — did not run"; fail=1; }

# I4 fidelity: apk add exited 0 (apk.static ran the full install to completion)
[ "$(clean_a | grep -ac '^APK_RC=0$')" -ge 1 ] && \
    echo "PASS · I4: apk add exited 0 (apk.static ran the install to completion)" || \
    { echo "FAIL · I4: apk add did not exit 0 (check the apk error in $ALOG)"; fail=1; }

# I4 fidelity: apk info lists the installed package (reads the DB from the upper)
[ "$(clean_a | grep -ac "^${PKG}.*")" -ge 1 ] && \
    echo "PASS · I4: apk info lists '${PKG}' (DB updated in-session)" || \
    { echo "FAIL · I4: '${PKG}' not listed in apk info"; fail=1; }

# install proof: the package's files extracted into the upper + readable in-session.
# /etc/terminfo/l/linux is a real terminfo blob shipped by the package (>0 bytes).
tf_bytes=$(clean_a | sed -n '/cat \/etc\/terminfo\/l\/linux/,/TERMINFO_FILE_DONE/p' | grep -aoE '^[0-9]+$' | head -1)
if [ -n "${tf_bytes:-}" ] && [ "${tf_bytes:-0}" -gt 0 ]; then
    echo "PASS · install: /etc/terminfo/l/linux extracted into the upper (${tf_bytes} bytes, readable in-session)"
else
    echo "FAIL · install: package files NOT extracted/readable in session A"; fail=1
fi

# I4: no ENOSYS / abort / segfault reported in the apk CLIENT output (a fidelity tell)
if clean_a | grep -qaE 'ENOSYS|Function not implemented|Segmentation fault|Aborted'; then
    echo "FAIL · I4: apk client reported an ENOSYS/abort tell"; fail=1
else
    echo "PASS · I4: no ENOSYS/abort tell in the apk client output"
fi

# IOC: PACKAGE_INSTALL emit in serial log (the Tier-2 write to /lib/apk/db/installed)
LC_ALL=C grep -qaF 'package install' "$SLOG" && \
    echo "PASS · IOC: 'package install' in serial log (PACKAGE_INSTALL fired)" || \
    { echo "FAIL · IOC: 'package install' NOT in serial log"; fail=1; }

# Fault scan (session A)
cap_faults=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true); cap_faults=${cap_faults:-0}
mac_a=$(LC_ALL=C grep -c 'Corrupted MAC' "$ALOG" 2>/dev/null || true); mac_a=${mac_a:-0}
[ "$cap_faults" -eq 0 ] && [ "$mac_a" -eq 0 ] && \
    echo "PASS · no cap/MAC fault (session A)" || \
    { echo "FAIL · cap=$cap_faults mac_a=$mac_a"; fail=1; }

# ── Session B — I1 base immutable + I2 isolation ───────────────────────────────
echo "[apk-install-gate] session B (I1 base immutable + I2 isolation)…"
sleep 2   # allow session A reap to complete
session_b(){
    sleep 3
    send 'echo SESSB_ALIVE' 2
    send 'apk info; echo APK_INFO_B_DONE' 5
    send 'cat /etc/terminfo/l/linux 2>/dev/null | wc -c; echo TERMINFO_B_DONE' 3
    send 'cat /lib/apk/db/installed | head -20; echo INSTALLED_B_DONE' 3
    send 'exit' 4
}
run_ssh "$BLOG" session_b

echo "[apk-install-gate] session B done · analysing…"
clean_b(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG"; }

# Session B liveness (HARD — prevents silent-session false-green)
[ "$(clean_b | grep -ac '^SESSB_ALIVE$')" -ge 1 ] && \
    echo "PASS · session B is alive (SESSB_ALIVE present)" || \
    { echo "FAIL · session B produced no SESSB_ALIVE — did not run (false-green risk)"; fail=1; }

# I1/I2: apk info in session B must NOT list the package
[ "$(clean_b | grep -ac "^${PKG}.*")" -eq 0 ] && \
    echo "PASS · I2: '${PKG}' NOT listed in session B apk info (base pristine)" || \
    { echo "FAIL · I2 BREACH: session B apk info lists '${PKG}'"; fail=1; }

# I1/I2: the extracted terminfo file must be ABSENT in session B (it lived in
# session A's upper only). A read returns 0 bytes (No such file → wc -c = 0).
tfb=$(clean_b | sed -n '/cat \/etc\/terminfo\/l\/linux/,/TERMINFO_B_DONE/p' | grep -aoE '^[0-9]+$' | head -1)
if [ "${tfb:-0}" -eq 0 ]; then
    echo "PASS · I1: /etc/terminfo/l/linux absent in session B (0 bytes — base pristine)"
else
    echo "FAIL · I1 BREACH: /etc/terminfo/l/linux visible in session B (${tfb} bytes)"; fail=1
fi

# I1: base /lib/apk/db/installed has no package entry (apk DB writes went to the upper)
[ "$(clean_b | grep -ac '^P:')" -eq 0 ] && \
    echo "PASS · I1: base /lib/apk/db/installed has no package entry (writes were contained)" || \
    { echo "FAIL · I1 BREACH: base apk DB has a package entry in session B"; fail=1; }

mac_b=$(LC_ALL=C grep -c 'Corrupted MAC' "$BLOG" 2>/dev/null || true); mac_b=${mac_b:-0}
[ "$mac_b" -eq 0 ] && echo "PASS · no MAC fault (session B)" || { echo "FAIL · MAC fault session B: $mac_b"; fail=1; }

# ── summary ───────────────────────────────────────────────────────────────────
echo ""
echo "=== $( [ $fail -eq 0 ] && \
    echo "[apk-install-gate] PASS (apk add ${PKG} contained · I1/I2/I4 · IOC)" || \
    echo '[apk-install-gate] FAIL' ) ==="
echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"
exit $fail
