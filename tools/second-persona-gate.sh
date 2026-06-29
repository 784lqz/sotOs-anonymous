#!/usr/bin/env bash
# sotOs · second-persona-gate — round-robin Alpine/Debian coexistence.
#
# Opens TWO consecutive honey SSH sessions in one boot.  The round-robin persona
# selector serves session 1 = Alpine (musl, prod-db-01) and session 2 = Ubuntu
# (glibc, ubuntu-host).  This gate asserts each session tells ONE coherent story
# for ITS OWN persona AND that the two stories DIVERGE — proving the M3
# per-session seam serves distinct personas, not a global skin.
#
# Exit codes: 0=PASS, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
SLOG=/tmp/sotos-2persona-serial.log
ALOG=/tmp/sotos-2persona-sessA.log   # session 1 · Alpine
BLOG=/tmp/sotos-2persona-sessB.log   # session 2 · Ubuntu

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[2persona] BLOCKED: operator QEMU live"; exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[2persona] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

echo "[2persona] booting honeypot headless…"
timeout 260 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT

for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[2persona] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-2persona-ask.sh
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

probe(){
    sleep 3
    send 'echo P2_START' 1
    send 'uname -r' 1
    send 'cat /etc/os-release' 1
    send 'echo LSB:; cat /etc/lsb-release 2>&1' 1
    send 'echo DEBVER:; cat /etc/debian_version 2>&1' 1
    send 'echo ALPV:; cat /etc/alpine-release 2>&1' 1
    send 'echo HOST:; hostname' 1
    send 'echo GLIBC:; ls /lib/x86_64-linux-gnu 2>&1 | head -1' 1
    send 'echo APKV:; apk --version 2>&1' 1
    send 'echo APTV:; apt-get --version 2>&1 | head -1' 1
    send 'echo LSVER:; ls --version 2>&1 | head -1' 1
    send 'echo IDVER:; id --version 2>&1 | head -1' 1
    send 'echo WCVER:; wc --version 2>&1 | head -1' 1
    send 'echo GREPV:; grep --version 2>&1 | head -1' 1
    send 'echo CPV:; cp --version 2>&1 | head -1' 1
    send 'echo DPKGV:; dpkg --version 2>&1 | head -1' 1
    send 'echo DPKGL:; dpkg -l 2>&1 | grep -E "^ii  (nginx|dpkg) " | head -1' 1
    send 'echo BAIT:; head -3 /root/.bash_history 2>&1; cat /etc/apt/sources.list 2>&1 | head -1' 1
    send 'echo HBLS:; ls -1 /home; echo HBKEY:; head -1 /home/admin/.ssh/id_rsa /home/deploy/.ssh/id_rsa 2>&1; echo HBEND:' 1
    send 'echo P2_END' 1
    send 'exit' 3
}

echo "[2persona] session 1 (expect Alpine)…"; run_ssh "$ALOG" probe
sleep 2
echo "[2persona] session 2 (expect Debian)…"; run_ssh "$BLOG" probe

clean(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$1"; }
[ "$(clean "$ALOG" | grep -ac 'P2_START')" -ge 1 ] || { echo "[2persona] FAIL · session 1 probe did not run"; exit 1; }
[ "$(clean "$BLOG" | grep -ac 'P2_START')" -ge 1 ] || { echo "[2persona] FAIL · session 2 probe did not run"; exit 1; }

echo "=== SECOND PERSONA · Alpine (sess1) vs Debian 13 (sess2) coexistence ==="
fails=0
fail(){ echo "FAIL · $1"; fails=$((fails+1)); }
ok(){ echo "OK   · $1"; }

A="$(clean "$ALOG")"
B="$(clean "$BLOG")"

# ── session 1 must be a coherent ALPINE story ──
echo "$A" | grep -qaE '6\.6\.30-0-lts'            && ok "sess1 uname → Alpine 6.6.30-0-lts" || fail "sess1 uname not Alpine kernel"
echo "$A" | grep -qaiE '^ID=alpine|NAME="?Alpine' && ok "sess1 os-release → Alpine"        || fail "sess1 os-release not Alpine"
echo "$A" | grep -qaE 'prod-db-01'                && ok "sess1 hostname → prod-db-01"       || fail "sess1 hostname not the Alpine canary"
# Alpine pkg-mgr: apk works, apt is NOT found
echo "$A" | sed -n '/^APKV:/,/^APTV:/p' | grep -qaiE 'apk-tools|^[0-9]' && ok "sess1 apk present (Alpine pkg-mgr)" || fail "sess1 apk not working"
echo "$A" | sed -n '/^APTV:/,/^LSVER:/p' | grep -qaiE 'not found|No such|ENOENT' && ok "sess1 apt-get NOT found (coherent Alpine)" || fail "sess1 apt-get present (Alpine tell)"
# Alpine busybox ls has no --version (rejects it) → NOT GNU coreutils
if echo "$A" | sed -n '/^LSVER:/,/^IDVER:/p' | grep -qaiE 'GNU coreutils'; then
    fail "sess1 ls is GNU coreutils (Alpine should be busybox)"
else
    ok "sess1 ls → busybox (no GNU --version · Alpine-coherent)"
fi
# Alpine has NO dpkg (apk world) → dpkg --version must be command-not-found
echo "$A" | sed -n '/^DPKGV:/,/^DPKGL:/p' | grep -qaiE 'not found|No such|ENOENT' && ok "sess1 dpkg NOT found (coherent Alpine)" || fail "sess1 dpkg present (Alpine tell)"
if echo "$A" | sed -n '/^GLIBC:/,/^P2_END/p' | grep -qaiE 'libc\.so\.6|No such|not found|cannot access'; then
    # either hidden (ENOENT) is fine; a real libc.so.6 listing would be the tell
    echo "$A" | sed -n '/^GLIBC:/,/^P2_END/p' | grep -qaiE 'libc\.so\.6' \
        && fail "sess1 (Alpine) LEAKS glibc /lib/x86_64-linux-gnu" \
        || ok "sess1 glibc multiarch hidden (musl-coherent)"
else
    ok "sess1 glibc multiarch hidden (musl-coherent)"
fi
# per-persona /home bait · sess1 (Alpine canary) sees admin + a honey id_rsa, NOT deploy
echo "$A" | sed -n '/^HBLS:/,/^HBKEY:/p' | grep -qaE '^deploy|^dbadmin' && fail "sess1 leaks the Debian canary's /home users" || ok "sess1 /home has no Debian users (canary isolated)"
echo "$A" | sed -n '/^HBKEY:/,/^HBEND:/p' | grep -qaE 'BEGIN OPENSSH PRIVATE KEY' && ok "sess1 /home/admin/.ssh/id_rsa honey key present (tripwire)" || fail "sess1 admin honey key absent"

# ── session 2 must be a coherent DEBIAN 13 (trixie) story ──
echo "$B" | grep -qaE '6\.12\.43\+deb13'          && ok "sess2 uname → Debian 6.12.43+deb13"  || fail "sess2 uname not Debian kernel"
echo "$B" | grep -qaiE '^ID=debian|NAME="?Debian' && ok "sess2 os-release → Debian"           || fail "sess2 os-release not Debian"
echo "$B" | sed -n '/^DEBVER:/,/^ALPV:/p' | grep -qaE '^13\.[0-9]+' && ok "sess2 /etc/debian_version → 13.x" || fail "sess2 /etc/debian_version not Debian 13"
echo "$B" | grep -qaE 'debian-app-01'             && ok "sess2 hostname → debian-app-01"       || fail "sess2 hostname not Debian"
# Debian has NO /etc/lsb-release by default → must be absent/empty (coherence)
echo "$B" | sed -n '/^LSB:/,/^DEBVER:/p' | grep -qaiE 'DISTRIB_ID' && fail "sess2 has /etc/lsb-release (Debian default has none)" || ok "sess2 no /etc/lsb-release (Debian-coherent)"
# Debian pkg-mgr: apt works, apk is NOT found
echo "$B" | sed -n '/^APTV:/,/^LSVER:/p' | grep -qaiE 'apt 2\.|apt [0-9]' && ok "sess2 apt present (Debian pkg-mgr)" || fail "sess2 apt not working"
echo "$B" | sed -n '/^APKV:/,/^APTV:/p' | grep -qaiE 'not found|No such|ENOENT' && ok "sess2 apk NOT found (coherent Debian)" || fail "sess2 apk present (Debian tell)"
# GNU coreutils (glibc) — the extended set: ls + id + wc all GNU, not busybox
echo "$B" | sed -n '/^LSVER:/,/^IDVER:/p' | grep -qaiE 'GNU coreutils' && ok "sess2 ls → GNU coreutils (not busybox)" || fail "sess2 ls not GNU coreutils"
echo "$B" | sed -n '/^IDVER:/,/^WCVER:/p' | grep -qaiE 'GNU coreutils' && ok "sess2 id → GNU coreutils (extended set)" || fail "sess2 id not GNU coreutils"
echo "$B" | sed -n '/^WCVER:/,/^GREPV:/p' | grep -qaiE 'GNU coreutils' && ok "sess2 wc → GNU coreutils (extended set)" || fail "sess2 wc not GNU coreutils"
echo "$B" | sed -n '/^GREPV:/,/^CPV:/p' | grep -qaiE 'GNU grep' && ok "sess2 grep → GNU grep (layout-bump set)" || fail "sess2 grep not GNU"
echo "$B" | sed -n '/^CPV:/,/^DPKGV:/p' | grep -qaiE 'GNU coreutils' && ok "sess2 cp → GNU coreutils (file-op set)" || fail "sess2 cp not GNU coreutils"
# dpkg coherence · Debian has dpkg (version + installed-package list)
echo "$B" | sed -n '/^DPKGV:/,/^DPKGL:/p' | grep -qaiE "Debian 'dpkg'|dpkg package" && ok "sess2 dpkg --version → Debian dpkg" || fail "sess2 dpkg --version not Debian"
echo "$B" | sed -n '/^DPKGL:/,/^BAIT:/p' | grep -qaE '^ii  (nginx|dpkg) ' && ok "sess2 dpkg -l lists packages" || fail "sess2 dpkg -l no package list"
# rich canary bait · the Debian prod-app-server honeytokens an attacker recon's
echo "$B" | sed -n '/^BAIT:/,/^HBLS:/p' | grep -qaiE 'systemctl|PGPASSWORD|pg_dump|deb.debian.org' && ok "sess2 rich canary bait present (.bash_history / sources.list)" || fail "sess2 canary bait absent"
# per-persona /home bait · sess2 (Debian) sees deploy/dbadmin/ops + a honey id_rsa, NOT admin
echo "$B" | sed -n '/^HBLS:/,/^HBKEY:/p' | grep -qaE '^deploy' && ok "sess2 /home → Debian users (deploy/dbadmin/ops)" || fail "sess2 /home not Debian users"
echo "$B" | sed -n '/^HBKEY:/,/^HBEND:/p' | grep -qaE 'BEGIN OPENSSH PRIVATE KEY' && ok "sess2 /home/deploy/.ssh/id_rsa honey key present (tripwire)" || fail "sess2 deploy honey key absent"
echo "$B" | sed -n '/^HBLS:/,/^HBKEY:/p' | grep -qaE '^admin' && fail "sess2 leaks the Alpine canary's /home/admin" || ok "sess2 /home has no admin (Alpine canary isolated)"
# Debian must NOT carry the Alpine story
if echo "$B" | grep -qaiE '^ID=alpine|6\.6\.30-0-lts|prod-db-01'; then
    fail "sess2 (Debian) LEAKS the Alpine story (os-release/uname/hostname)"
else
    ok "sess2 has no Alpine leak (clean Debian story)"
fi

# ── the two stories must DIVERGE (real per-session personas, not a skin) ──
if [ "$(echo "$A" | grep -aoE 'ID=alpine|ID=debian' | head -1)" != "$(echo "$B" | grep -aoE 'ID=alpine|ID=debian' | head -1)" ]; then
    ok "the two sessions wear DIFFERENT personas (coexistence proven)"
else
    fail "both sessions show the SAME persona — round-robin not diverging"
fi

echo
echo "=== second-persona: $fails fail(s) ==="
if [ "$fails" -eq 0 ]; then
    echo "=== second-persona-gate: PASS (Alpine + Debian coexist · coherent per session) ==="
    echo "(serial: $SLOG · sess1: $ALOG · sess2: $BLOG)"; exit 0
else
    echo "=== second-persona-gate: FAIL ($fails) ==="
    echo "(serial: $SLOG · sess1: $ALOG · sess2: $BLOG)"; exit 1
fi
