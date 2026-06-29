#!/usr/bin/env bash
# sotOs · persona-coherence-gate (M0) — the Tier-2 honey SSH session must tell
# ONE coherent Alpine story, with ZERO Ubuntu/Debian leak.
#
# This is the freeze/baseline gate + the embryo of the anti-sandbox coherence
# matrix.  It opens the honey shell, probes every persona-defining surface, and
# asserts they all belong to the SAME story (Alpine 3.20.10 / kernel 6.6.30-0-lts
# / musl / apk / busybox).  A human analyst needs only ONE contradiction; this
# gate hunts for it.
#
# Exit codes: 0=PASS, 1=FAIL (a tell), 2=missing image, 3=BLOCKED (operator QEMU)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
SLOG=/tmp/sotos-persona-serial.log
ALOG=/tmp/sotos-persona-sessA.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[persona] BLOCKED: operator QEMU live"; exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[persona] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG"

echo "[persona] booting honeypot headless…"
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
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[persona] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-persona-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
send(){ printf '%s\n' "$1"; sleep "${2:-2}"; }
run_ssh() {
    local LOG="$1" FN="$2"
    "$FN" | \
        timeout 150 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

session_a(){
    sleep 3
    send 'echo PERSONA_PROBE_START' 1
    send 'uname -a' 1
    send 'uname -r' 1
    send 'cat /etc/os-release' 1
    send 'cat /etc/alpine-release 2>&1' 1
    send 'echo LSB:; cat /etc/lsb-release 2>&1' 1
    send 'echo DEBVER:; cat /etc/debian_version 2>&1' 1
    send 'cat /proc/version' 1
    send 'echo SHELLS:; cat /etc/shells 2>&1' 1
    send 'echo MUSL:; ls /lib/ld-musl-x86_64.so.1 2>&1' 1
    send 'echo GLIBC:; ls /lib/x86_64-linux-gnu 2>&1' 1
    send 'echo APKV:; apk --version 2>&1' 1
    send 'echo APT:; command -v apt dpkg 2>&1' 1
    send 'echo HOST:; hostname' 1
    send 'echo PASSWD:; head -2 /etc/passwd' 1
    send 'echo MAPS:; head -4 /proc/self/maps 2>&1' 1
    send 'echo EXE:; readlink /proc/self/exe 2>&1' 1
    send 'echo PERSONA_PROBE_END' 1
    send 'exit' 3
}
echo "[persona] session A (persona coherence probe)…"
run_ssh "$ALOG" session_a
clean(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"; }

[ "$(clean | grep -ac 'PERSONA_PROBE_START')" -ge 1 ] || { echo "[persona] FAIL · probe did not run"; exit 1; }

echo "=== PERSONA COHERENCE · honey session must tell ONE Alpine story ==="
tells=0
tell(){ echo "TELL · $1"; tells=$((tells+1)); }
ok(){ echo "OK   · $1"; }

# 1 · uname is Alpine kernel
clean | grep -qaE 'Linux .* 6\.6\.30-0-lts' && ok "uname → Alpine LTS kernel 6.6.30-0-lts" \
    || tell "uname is NOT the Alpine 6.6.30-0-lts kernel string"
clean | grep -qaiE '#1-Alpine SMP' && ok "uname version → #1-Alpine SMP" \
    || tell "uname version string is not the Alpine build (#1-Alpine SMP)"

# 2 · os-release says alpine, NOT ubuntu/debian
if clean | sed -n '/cat \/etc\/os-release/,/alpine-release/p' | grep -qaiE '^ID=alpine|NAME="?Alpine'; then
    ok "/etc/os-release → ID=alpine"
else
    tell "/etc/os-release does NOT say Alpine (ID=alpine / NAME=Alpine)"
fi
if clean | sed -n '/cat \/etc\/os-release/,/alpine-release/p' | grep -qaiE 'ubuntu|debian'; then
    tell "/etc/os-release LEAKS ubuntu/debian (incoherent with Alpine uname)"
else
    ok "/etc/os-release has no ubuntu/debian leak"
fi

# 3 · /etc/alpine-release present, no Ubuntu lsb / debian_version leak in honey
clean | grep -qaE '^3\.(18|19|20|21)\.' && ok "/etc/alpine-release → 3.x present" \
    || tell "/etc/alpine-release missing or wrong"
if clean | sed -n '/^LSB:/,/^DEBVER:/p' | grep -qaiE 'DISTRIB_ID=Ubuntu|Ubuntu'; then
    tell "/etc/lsb-release leaks Ubuntu in the honey session"
else
    ok "no Ubuntu /etc/lsb-release leak"
fi

# 4 · /proc/version coherent with Alpine kernel
clean | sed -n '/cat \/proc\/version/,/SHELLS:/p' | grep -qaiE '6\.6\.30|Alpine' \
    && ok "/proc/version coherent with the Alpine kernel" \
    || tell "/proc/version does not match the Alpine kernel string"

# 5 · libc = musl, not glibc multiarch dir
clean | sed -n '/^MUSL:/,/^GLIBC:/p' | grep -qaE 'ld-musl-x86_64' \
    && ok "musl ld-musl present (Alpine libc)" \
    || tell "musl ld-musl-x86_64.so.1 not present"
if clean | sed -n '/^GLIBC:/,/^APKV:/p' | grep -qaiE 'libc\.so\.6|x86_64-linux-gnu/'; then
    tell "glibc multiarch dir /lib/x86_64-linux-gnu present (Ubuntu/Debian tell)"
else
    ok "no glibc /lib/x86_64-linux-gnu (coherent with musl)"
fi

# 6 · apk present; apt/dpkg not the advertised manager
clean | sed -n '/^APKV:/,/^APT:/p' | grep -qaiE 'apk-tools|^[0-9]' \
    && ok "apk present + reports a version" \
    || tell "apk not present / not working in the honey persona"

# 7 · hostname coherent with canary persona
clean | sed -n '/^HOST:/,/^PASSWD:/p' | grep -qaE 'prod-db-01|alpine' \
    && ok "hostname coherent with the canary persona" \
    || echo "INFO · hostname not the expected canary value (check $ALOG)"

# INFO · procfs-live preview (M1 target — not a fail here)
if clean | sed -n '/^MAPS:/,/^EXE:/p' | grep -qaE '^[0-9a-f]+-[0-9a-f]+ '; then
    echo "INFO · /proc/self/maps returns map-like lines (verify they are REAL in M1)"
else
    echo "INFO · /proc/self/maps empty/absent → procfs-live-M1 target"
fi

echo
echo "=== persona-coherence: $tells tell(s) ==="
if [ "$tells" -eq 0 ]; then
    echo "=== persona-coherence-gate: PASS (one coherent Alpine story · no Ubuntu leak) ==="
    echo "(serial: $SLOG · sess: $ALOG)"; exit 0
else
    echo "=== persona-coherence-gate: FAIL ($tells coherence tell(s) — see above) ==="
    echo "(serial: $SLOG · sess: $ALOG)"; exit 1
fi
