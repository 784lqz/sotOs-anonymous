#!/usr/bin/env bash
# sotOs guided-demo launcher · see DEMO.md for the 3-act runbook.
#
# Preflight (build + Wine staging) then opens the interactive QEMU window.
# The window boots into the attacker canary shell; F12 toggles to the operator
# console.  SSH is forwarded on :18022 (attacker), HTTP/HTTPS on :18080/:18443.
#
#   ./demo.sh            launch (build/stage only if needed)
#   ./demo.sh --rebuild  force a clean rebuild first
#   ./demo.sh --check    preflight only, do not launch
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || { echo "not in the sotOs repo"; exit 2; }

REBUILD=0; CHECK_ONLY=0
for a in "$@"; do case "$a" in
  --rebuild) REBUILD=1;; --check) CHECK_ONLY=1;;
  *) echo "unknown arg: $a (use --rebuild | --check)"; exit 2;; esac; done

# Never disturb a live operator QEMU (it holds the sotfs.img lock).
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then
  echo "[demo] a QEMU is already running — close it first (Ctrl-A X), or it holds sotfs.img."
  exit 3
fi

IMGS="build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99"
need_build=$REBUILD
for f in $IMGS; do [ -f "$f" ] || need_build=1; done
# Wine subset (for Act 3 `wine-crt`) lives in build/wine-sysroot — a clean build
# wipes it, and a later `just build` would repack the image WITHOUT it.  A staged
# DLL (kernel32) is the reliable marker; hello_crt.exe is a committed source file
# CMake copies into the image at build time.
need_wine=0; [ -f build/wine-sysroot/lib/wine/x86_64-windows/kernel32.dll ] || need_wine=1

if [ "$REBUILD" = 1 ]; then
  echo "[demo] clean rebuild…"; rm -rf build
  just build >/tmp/demo-build.log 2>&1 || { echo "[demo] build FAILED · see /tmp/demo-build.log"; exit 1; }
  need_wine=1
elif [ "$need_build" = 1 ]; then
  echo "[demo] images missing · building…"
  just build >/tmp/demo-build.log 2>&1 || { echo "[demo] build FAILED · see /tmp/demo-build.log"; exit 1; }
fi

if [ "$need_wine" = 1 ]; then
  echo "[demo] staging Wine (hello_crt.exe etc.) + repacking the image…"
  bash tools/wine-stage.sh >/tmp/demo-wine.log 2>&1 || echo "[demo] WARN · wine-stage failed (wine-crt may be unavailable) · see /tmp/demo-wine.log"
  just build >/tmp/demo-build2.log 2>&1 || { echo "[demo] repack FAILED · see /tmp/demo-build2.log"; exit 1; }
fi

echo "[demo] preflight OK:"
echo "       images: present"
echo "       wine:   $( [ -f build/wine-sysroot/lib/wine/x86_64-windows/kernel32.dll ] && echo 'staged (wine-crt ready)' || echo 'ABSENT (Act 3 wine-crt unavailable)')"
[ "$CHECK_ONLY" = 1 ] && { echo "[demo] --check done."; exit 0; }

cat <<'EON'

[demo] launching the window. Follow DEMO.md:
   ACT 1  canary shell (attacker) → whoami/id/uname -a/cat /etc/passwd/cat /honey-aws-creds
          F12 → operator: list · anomaly-log · sottrace graph · watch
   ACT 2  shell --trusted → python3 -c ... → pip install six → import six → exit
   ACT 3  gtk3-demo · doomwl · wine-crt
   (F12 = attacker⇄operator · Ctrl-A X in this terminal = quit QEMU)

EON
exec just run-interactive
