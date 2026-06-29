#!/usr/bin/env bash
# sotOs · apk-fs slice-2 C4 spike — a NEEDED .so resolves from the session upper
#
# Proves the mechanic the real `apk add nano` depends on: ld-musl must open()+
# mmap() a NEEDED shared object (libncursesw.so.6) that exists ONLY in the
# per-session sotfs upper.  P3 (apk-upperexec-gate) proved an upper ELF runs with
# ld-musl resolving libc FROM THE BAKED SYSROOT; this proves a 2nd .so resolves
# FROM THE UPPER (libspikelib.so is NOT baked, so a successful resolve cannot be
# a sysroot fallback).
#
#   Session A:
#     1. cat /tmp/libspikelib.so > /usr/lib/libspikelib.so   (into the /usr upper)
#     2. cat /tmp/spike_dyn.bin  > /usr/bin/spikebin          (into the /usr upper)
#     3. /usr/bin/spikebin — ld-musl opens libspikelib.so from the upper, calls
#        spk_probe(), prints "[spike] upper-so OK"; assert SPIKE_RC=0.
#
#   Session B (I2): /usr/bin/spikebin ABSENT, "[spike] upper-so OK" count == 0.
#
# Exit codes: 0=PASS, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU live)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
SLOG=/tmp/sotos-apk-upperso-serial.log
ALOG=/tmp/sotos-apk-upperso-sessA.log
BLOG=/tmp/sotos-apk-upperso-sessB.log

# ── BLOCKED guard ─────────────────────────────────────────────────────────────
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[apk-upper-so] BLOCKED: operator QEMU live"; exit 3
fi

# ── pre-flight ────────────────────────────────────────────────────────────────
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[apk-upper-so] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

# ── boot headless ─────────────────────────────────────────────────────────────
echo "[apk-upper-so] booting honeypot headless…"
timeout 240 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT

for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[apk-upper-so] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-apk-upperso-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"

do_ssh() {
    local LOG="$1" PIPE="$2"
    ( eval "$PIPE" ) | \
        timeout 120 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

# ── Session A — stage BOTH blobs into the upper + execute ──────────────────────
echo "[apk-upper-so] session A (stage .so + client into the upper, exec)…"
SESS_A_PIPE='
    sleep 3
    printf "echo SESSA_ALIVE\n"; sleep 2
    printf "cat /tmp/libspikelib.so > /usr/lib/libspikelib.so\n"; sleep 2
    printf "cat /tmp/spike_dyn.bin > /usr/bin/spikebin\n"; sleep 2
    printf "ls -l /usr/lib/libspikelib.so /usr/bin/spikebin\n"; sleep 2
    printf "/usr/bin/spikebin; echo SPIKE_RC=$?\n"; sleep 4
    printf "exit\n"; sleep 4
'
do_ssh "$ALOG" "$SESS_A_PIPE"
echo "[apk-upper-so] session A done · analysing…"
clean_a(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"; }

fail=0

[ "$(clean_a | grep -ac '^SESSA_ALIVE$')" -ge 1 ] && \
    echo "PASS · session A is alive" || \
    { echo "FAIL · session A produced no SESSA_ALIVE marker"; fail=1; }

# EXEC: the client ran and resolved the upper .so
[ "$(clean_a | grep -ac '\[spike\] upper-so OK')" -ge 1 ] && \
    echo "PASS · EXEC: ld-musl resolved libspikelib.so FROM THE UPPER (spk_probe ran)" || \
    { echo "FAIL · EXEC: '[spike] upper-so OK' absent — the 2nd .so did not resolve from the upper"; fail=1; }

[ "$(clean_a | grep -ac '^SPIKE_RC=0$')" -ge 1 ] && \
    echo "PASS · EXEC: spikebin exited 0 (RC=0)" || \
    { echo "FAIL · EXEC: SPIKE_RC is not 0 (or absent)"; fail=1; }

# the FAIL variant must NOT appear (would mean the .so loaded but the global was wrong)
[ "$(clean_a | grep -ac '\[spike\] upper-so FAIL')" -eq 0 ] || \
    { echo "FAIL · EXEC: spk_probe returned the wrong value (RW PT_LOAD mis-mapped)"; fail=1; }

# the loader actually went through the VFS upper read path for the .so or the client
{ LC_ALL=C grep -qaF "libspikelib.so" "$SLOG" || LC_ALL=C grep -qaF "spikebin" "$SLOG"; } && \
    echo "PASS · upper read path exercised (libspikelib.so / spikebin in serial)" || \
    echo "WARN · no libspikelib.so/spikebin marker in serial (check $SLOG)"

# no cap fault from the spike
faults_a=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true)
faults_a=${faults_a:-0}
[ "${faults_a}" -eq 0 ] && \
    echo "PASS · runtime endured the spike (no cap fault)" || \
    { echo "FAIL · cap faults=$faults_a during the spike"; fail=1; }

# ── Session B — I2 isolation ──────────────────────────────────────────────────
echo "[apk-upper-so] session B (I2 isolation)…"
SESS_B_PIPE='
    sleep 3
    printf "echo SESSB_ALIVE\n"; sleep 2
    printf "ls /usr/bin | grep -c spikebin; echo LSCOUNT_DONE\n"; sleep 2
    printf "/usr/bin/spikebin 2>&1; echo SPIKEB_RC=$?\n"; sleep 3
    printf "exit\n"; sleep 4
'
do_ssh "$BLOG" "$SESS_B_PIPE"
echo "[apk-upper-so] session B done · analysing…"
clean_b(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG"; }

[ "$(clean_b | grep -ac '^SESSB_ALIVE$')" -ge 1 ] && \
    echo "PASS · session B is alive" || \
    { echo "FAIL · session B produced no SESSB_ALIVE marker"; fail=1; }

# I2: session B must NOT run session A's upper binary
[ "$(clean_b | grep -ac '\[spike\] upper-so OK')" -eq 0 ] && \
    echo "PASS · I2: session B did NOT run spikebin (upper isolation)" || \
    { echo "FAIL · I2 BREACH: session B ran session A's upper binary"; fail=1; }

faults_b=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true)
faults_b=${faults_b:-0}
[ "${faults_b}" -eq 0 ] || { echo "FAIL · cap faults during session B"; fail=1; }

echo
if [ "$fail" -eq 0 ]; then
    echo "=== apk-upper-so-gate: PASS (a NEEDED .so resolves from the session upper · I2) ==="
    echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"
    exit 0
else
    echo "=== apk-upper-so-gate: FAIL (check the logs) ==="
    echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"
    exit 1
fi
