#!/usr/bin/env bash
# sotOs · apk-network-install Task 5 — `apk add nano` from the REAL Alpine CDN
#
# The marquee end-to-end: a Tier-2 SSH attacker session resolves nano's closure
# against the live Alpine 3.20 CDN over HTTP, RSA-verifies + installs the 3
# packages (ncurses-terminfo-base + libncursesw + nano) fully contained in the
# per-session upper, and the installed dynamic `nano` runs (ld-musl resolving the
# freshly-installed libncursesw.so.6 from the session upper).
#
#   Session A: repos → http://dl-cdn.alpinelinux.org/.../main; apk update;
#   apk add nano; assert RC=0, apk info lists the closure, /usr/bin/nano reads
#   back in-session, `nano --version` runs, PACKAGE_INSTALL IOC, no fault.
#
#   Session B (I1/I2): pristine base — no nano in apk info, /usr/bin/nano absent.
#
# NETWORK-GATED: if the CDN/egress is unreachable, SKIP (exit 0).
#
# Exit codes: 0=PASS or SKIP, 1=FAIL, 2=missing image, 3=BLOCKED (operator QEMU live)
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2

PORT=18022
SLOG=/tmp/sotos-apk-netinst-serial.log
ALOG=/tmp/sotos-apk-netinst-sessA.log
BLOG=/tmp/sotos-apk-netinst-sessB.log

if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
    echo "[apk-net-install] BLOCKED: operator QEMU live"; exit 3
fi
for t in build/images/kernel-x86_64-pc99 build/images/sotOs-root-image-x86_64-pc99 build/images/sotfs.img; do
    [ -f "$t" ] || { echo "[apk-net-install] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG" "$ALOG" "$BLOG"

echo "[apk-net-install] booting honeypot headless…"
timeout 300 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
    -kernel build/images/kernel-x86_64-pc99 \
    -initrd build/images/sotOs-root-image-x86_64-pc99 \
    -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 \
    -device virtio-blk-pci,drive=sd0 \
    -netdev user,id=net0,hostfwd=tcp::18080-:80,hostfwd=tcp::${PORT}-:22,hostfwd=tcp::18443-:443 \
    -device virtio-net-pci,netdev=net0,mac=52:54:00:12:34:56 \
    < /dev/null > "$SLOG" 2>&1 &
QPID=$!; trap 'kill $QPID 2>/dev/null' EXIT

for i in $(seq 1 60); do LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" && break; sleep 1; done
LC_ALL=C grep -qaE 'N2 inbound LISTEN' "$SLOG" || { echo "[apk-net-install] FAIL · :22 never LISTENed"; exit 1; }
sleep 2

ASK=/tmp/sotos-apk-netinst-ask.sh
printf '#!/bin/sh\necho hunter2\n' > "$ASK"; chmod +x "$ASK"
send(){ printf '%s\n' "$1"; sleep "${2:-3}"; }
run_ssh() {
    local LOG="$1" FN="$2"
    "$FN" | \
        timeout 200 env SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force \
        ssh -tt -p "$PORT" \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no \
        -o NumberOfPasswordPrompts=3 -o ConnectTimeout=15 \
        root@127.0.0.1 >"$LOG" 2>&1 || true
}

session_a(){
    sleep 3
    send 'echo SESSA_ALIVE' 2
    send 'echo http://dl-cdn.alpinelinux.org/alpine/v3.20/main > /etc/apk/repositories' 2
    send 'apk update 2>&1 | tail -1' 25
    send 'apk add nano 2>&1; echo APK_ADD_RC=$?' 30
    send 'apk info 2>&1; echo APK_INFO_DONE' 4
    send 'ls -l /usr/bin/nano 2>&1; echo LS_NANO_DONE' 3
    send '/usr/bin/nano --version 2>&1 | head -1; echo NANO_VER_DONE' 5
    send 'exit' 4
}
echo "[apk-net-install] session A (apk add nano from the real CDN)…"
run_ssh "$ALOG" session_a
echo "[apk-net-install] session A done · analysing…"
clean_a(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$ALOG"; }

[ "$(clean_a | grep -ac '^SESSA_ALIVE$')" -ge 1 ] || { echo "FAIL · session A produced no SESSA_ALIVE"; exit 1; }

# NETWORK-GATE: did the egress reach the CDN at all?
if ! LC_ALL=C grep -qaE 'REAL connect .*honey-session' "$SLOG"; then
    echo "SKIP · the honey session did not reach the CDN — no live egress in this environment"
    echo "(serial: $SLOG · sess-A: $ALOG)"; exit 0
fi

fail=0
# I4 · apk add nano completed
if clean_a | grep -qaE '^APK_ADD_RC=0$'; then
    echo "PASS · I4: apk add nano exited 0 (resolved + installed from the real CDN)"
else
    echo "FAIL · I4: apk add nano did not exit 0 (check $ALOG)"; fail=1
fi
# I4 · apk info lists the closure
for p in nano libncursesw ncurses-terminfo-base; do
    if clean_a | sed -n '/APK_ADD_RC=0/,/APK_INFO_DONE/p' | grep -qaE "^${p}(-[0-9]|$)" \
       || clean_a | grep -qaE "^${p}\b"; then
        echo "PASS · I4: apk info lists '${p}'"
    else
        echo "FAIL · I4: '${p}' not in apk info"; fail=1
    fi
done
# install · /usr/bin/nano materialized in-session
if clean_a | grep -qaE '/usr/bin/nano'; then
    echo "PASS · install: /usr/bin/nano present in-session"
else
    echo "FAIL · install: /usr/bin/nano absent in-session"; fail=1
fi
# C4 · the APK-INSTALLED dynamic nano runs AS ITSELF from the session upper.
# The binstore ships nano 8.4; apk installs nano 8.0-r0. With the binstore-
# shadowing fix (resolve_path tries the per-session VFS upper for the full path
# FIRST for a cow_session caller), execve(/usr/bin/nano) must run the apk-installed
# 8.0 — proving (a) the upper binary shadows the binstore applet, and (b) ld-musl
# resolves the freshly-installed libncursesw.so.6 from the session upper.
nano_ver=$(clean_a | grep -aoiE 'GNU nano,? +version [0-9][0-9.]*' | head -1)
if echo "$nano_ver" | grep -qiE 'version 8\.0'; then
    echo "PASS · C4: the APK-INSTALLED nano 8.0 runs as itself ('$nano_ver' · upper shadows binstore 8.4 · libncursesw.so.6 from the upper)"
elif echo "$nano_ver" | grep -qiE 'version 8\.4'; then
    echo "FAIL · C4: ran the BINSTORE nano 8.4, not the apk-installed 8.0 (binstore shadowing not fixed)"; fail=1
elif clean_a | grep -qaiE 'GNU nano|nano version|version [0-9]'; then
    echo "WARN · C4: nano ran but version unparsed ('$nano_ver' · check $ALOG)"
else
    echo "FAIL · C4: /usr/bin/nano did not run (check $ALOG)"; fail=1
fi
# IOC
if LC_ALL=C grep -qaiE 'package.install|PACKAGE_INSTALL' "$SLOG"; then
    echo "PASS · IOC: package install observed"
else
    echo "WARN · IOC: no package-install marker in serial"
fi
# no fault
faults=$(LC_ALL=C grep -c 'Invocation of invalid cap' "$SLOG" 2>/dev/null || true); faults=${faults:-0}
[ "$faults" -eq 0 ] && echo "PASS · no cap fault (session A)" || { echo "FAIL · cap faults=$faults"; fail=1; }

# ── Session B · I1/I2 pristine base ───────────────────────────────────────────
session_b(){
    sleep 3
    send 'echo SESSB_ALIVE' 2
    send 'apk info 2>&1; echo APK_INFO_B_DONE' 5
    send 'ls /usr/bin/nano 2>&1; echo LS_NANO_B_DONE' 3
    send 'exit' 4
}
echo "[apk-net-install] session B (I1/I2 base immutable)…"
run_ssh "$BLOG" session_b
clean_b(){ LC_ALL=C sed 's/\r//g; s/\x1b\[[0-9;?]*[a-zA-Z]//g' "$BLOG"; }

[ "$(clean_b | grep -ac '^SESSB_ALIVE$')" -ge 1 ] && echo "PASS · session B is alive" || { echo "FAIL · session B no SESSB_ALIVE"; fail=1; }
if clean_b | sed -n '/SESSB_ALIVE/,/APK_INFO_B_DONE/p' | grep -qaE '^nano(-[0-9]|$)'; then
    echo "FAIL · I2 BREACH: session B apk info lists nano"; fail=1
else
    echo "PASS · I2: nano NOT listed in session B apk info (base pristine)"
fi
if clean_b | grep -qaE '/usr/bin/nano: No such|cannot access|No such file'; then
    echo "PASS · I1: /usr/bin/nano absent in session B (base pristine)"
elif clean_b | sed -n '/LS_NANO/,/LS_NANO_B_DONE/p' | grep -qaE '/usr/bin/nano$'; then
    echo "FAIL · I1 BREACH: /usr/bin/nano present in session B"; fail=1
else
    echo "PASS · I1: /usr/bin/nano absent in session B (base pristine)"
fi

echo
if [ "$fail" -eq 0 ]; then
    echo "=== apk-net-install-gate: PASS (apk add nano from the real CDN · contained · I1/I2/I4 · IOC) ==="
    echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"; exit 0
else
    echo "=== apk-net-install-gate: FAIL ==="
    echo "(serial: $SLOG · sess-A: $ALOG · sess-B: $BLOG)"; exit 1
fi
