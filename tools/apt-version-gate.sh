#!/usr/bin/env bash
# sotOs · apt-version-gate — Phase 0 · real Debian apt staged + LOADS, no network.
#
# Proves the REAL Debian apt toolchain (apt 3.0.3 · glibc-dynamic C++) is staged
# into the sysroot and LOADS under the Debian persona of a Tier-2 SSH session —
# contained, read-only (no install), no network.
#
# THE DEBIAN PERSONA IS THE 2ND ROUND-ROBIN SSH SESSION:
#   session 1 of a boot = Alpine (discard) · session 2 = Debian (run apt probes).
# So this gate opens TWO consecutive SSH sessions in one boot (mirrors
# tools/second-persona-gate.sh) and runs the apt probes in session 2.
#
# Proof (against the SESSION-2 / Debian client log):
#   PASS · real banner `apt 3.0.3 (amd64)` appears
#   PASS · real help section `Most used commands:` appears
#   PASS · `deb http://deb.debian.org/debian trixie` (sources.list readable)
#   PASS · apk ABSENT on Debian (apk --version → not found, no apk banner)
#   PASS · serial clean (no VMFault/UserException/Fatal/loading-shared-libraries)
#   PASS · no SESSION WRITE in Phase 0 (no PACKAGE_INSTALL IOC / no apt overlay write)
#
# Exit codes: 0=PASS, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18029
SLOG=/tmp/sotos-apt-serial.log
ALOG=/tmp/sotos-apt-sessA.log   # session 1 · Alpine (discarded)
BLOG=/tmp/sotos-apt-sessB.log   # session 2 · Debian (apt probes)

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[apt-version-gate] BLOCKED: operator QEMU live"; exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[apt-version-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

echo "[apt-version-gate] booting honeypot headless…"
timeout 320 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18081-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18444-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT

echo "[apt-version-gate] waiting up to 90s for :22 LISTEN…"
for i in $(seq 1 90); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[apt-version-gate] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-apt-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
send(){ printf '%s\n' "$1"; sleep "${2:-2}"; }
run_ssh() {
    local LOG="$1" FN="$2"
    "$FN" | timeout 150 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

# session 1 (Alpine) · minimal probe, just advance the round-robin then disconnect.
probe_alpine(){
    sleep 3
    send 'echo P1_START' 1
    send 'uname -r' 1
    send 'echo P1_END' 1
    send 'exit' 3
}
# session 2 (Debian) · the real apt probes.
probe_debian(){
    sleep 3
    send 'echo P2_START' 1
    send 'echo OSREL:; cat /etc/os-release 2>&1 | head -1' 1
    send 'echo APTV:; apt-get --version 2>&1 | head -1' 2
    send 'echo APTH:; apt-get -h 2>&1' 3
    send 'echo APKV:; apk --version 2>&1' 1
    send 'echo SRCL:; cat /etc/apt/sources.list 2>&1' 1
    send 'echo P2_END' 1
    send 'exit' 3
}

echo "[apt-version-gate] session 1 (Alpine · discard)…"; run_ssh "$ALOG" probe_alpine
sleep 2
echo "[apt-version-gate] session 2 (Debian · apt probes)…"; run_ssh "$BLOG" probe_debian

clean(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$1"; }
[ "$(clean "$ALOG" | grep -ac 'P1_START')" -ge 1 ] || { echo "[apt-version-gate] FAIL · session 1 probe did not run"; exit 1; }
[ "$(clean "$BLOG" | grep -ac 'P2_START')" -ge 1 ] || { echo "[apt-version-gate] FAIL · session 2 probe did not run"; exit 1; }

B="$(clean "$BLOG")"
S="$(LC_ALL=C cat "$SLOG")"

echo "=== apt-version · real apt on the Debian persona (session 2) ==="
fails=0
fail(){ echo "FAIL · $1"; fails=$((fails+1)); }
ok(){ echo "OK   · $1"; }

# (sanity) session 2 must actually be the Debian persona, else round-robin slipped.
echo "$B" | grep -qaiE 'ID=debian|NAME="?Debian' && ok "session 2 is the Debian persona" || fail "session 2 is NOT Debian (round-robin slipped)"

# ── PASS: the REAL apt version banner (NOT the old facade's apt 2.4.13) ──
echo "$B" | grep -qaF 'apt 3.0.3 (amd64)' && ok "real banner · apt 3.0.3 (amd64)" || fail "real apt banner absent (expected 'apt 3.0.3 (amd64)')"

# ── PASS: the real help section header ──
echo "$B" | grep -qaF 'Most used commands:' && ok "real help · 'Most used commands:'" || fail "apt -h 'Most used commands:' absent"

# ── PASS: sources.list readable in-session ──
# Phase 1 (Task 2) added the `[trusted=yes]` trust floor to sources.list, so the
# line is now `deb [trusted=yes] http://deb.debian.org/debian trixie main`.
# Match the deb + archive URL + suite tolerantly so the trust option doesn't break it.
echo "$B" | grep -qaE 'deb (\[[^]]*\] )?http://deb\.debian\.org/debian trixie' && ok "sources.list · deb [trusted=yes] http://deb.debian.org/debian trixie" || fail "sources.list line absent"

# ── PASS: apk ABSENT on Debian (coherent persona · no apk banner) ──
APKSEG="$(echo "$B" | sed -n '/^APKV:/,/^SRCL:/p')"
if echo "$APKSEG" | grep -qaiE 'apk-tools|Installing'; then
    fail "apk LEAKS a real banner on Debian (apk-tools/Installing)"
elif echo "$APKSEG" | grep -qaiE 'not found|No such|ENOENT'; then
    ok "apk ABSENT on Debian (not found · coherent)"
else
    fail "apk --version gave no command-not-found (unexpected)"
fi

# ── PASS (serial): the C++ runtime loaded cleanly ──
if echo "$S" | grep -qaiE 'error while loading shared libraries|cannot open shared object'; then
    echo "$S" | grep -aiE 'error while loading shared libraries|cannot open shared object' | head -3
    fail "loader error in serial — a .so is missing from the sysroot closure"
else
    ok "no loader error in serial (apt C++ closure resolved)"
fi
if echo "$S" | grep -qaE 'VMFault|UserException|Fatal'; then
    echo "$S" | grep -aE 'VMFault|UserException|Fatal' | head -3
    fail "fault/exception in serial during apt run"
else
    ok "serial clean · no VMFault/UserException/Fatal"
fi

# ── PASS: Phase 0 is read-only — no install / no session overlay write by apt ──
if echo "$S" | grep -qaiE 'PACKAGE_INSTALL'; then
    fail "PACKAGE_INSTALL IOC fired in Phase 0 (apt should not install here)"
else
    ok "no PACKAGE_INSTALL IOC (read-only Phase 0)"
fi
if echo "$S" | grep -qaiE 'OVERLAY.*apt|apt.*OVERLAY .*write|session OVERLAY write.*apt'; then
    fail "apt wrote to the session overlay in Phase 0 (should be read-only)"
else
    ok "no apt session-overlay write (read-only Phase 0)"
fi

echo
echo "=== apt-version: $fails fail(s) ==="
if [ "$fails" -eq 0 ]; then
    echo "[apt-version-gate] PASS"
    echo "(serial: $SLOG · sess1: $ALOG · sess2: $BLOG)"; exit 0
else
    echo "[apt-version-gate] FAIL ($fails)"
    echo "(serial: $SLOG · sess1: $ALOG · sess2: $BLOG)"; exit 1
fi
