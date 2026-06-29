# shellcheck shell=bash
# Sourced by arc gates whose demo lives in the FULL-wrapped half of the headless
# demo battery (src/sotshell/main.c · demo_commands[] · FULL(...)).  The default
# `just build` is LEAN — those demos are NULL-skipped, so their boot markers
# never appear and the gate would go RED.  ensure_full_demos rebuilds the image
# with -DSOTOS_DEMO_FULL=ON; demo_lean_restore puts the fast LEAN default back on
# exit so the next apt/ssh/smoke gate boots fast.  Mirrors the SOTOS_FS_GATE
# reconfigure pattern in fs-gate.sh.  Both functions are idempotent.
#
# Usage in a gate (after `cd "$(git rev-parse --show-toplevel)"` and the
# operator-QEMU-live check, before the image checks / boot):
#     . tools/lib/demo-full.sh
#     ensure_full_demos || exit 2
# Foreground-`timeout` gates need nothing more (ensure_full_demos installs the
# restore EXIT trap).  Gates that later set their own `trap '... kill ...' EXIT`
# must append `; demo_lean_restore` to that trap (it would otherwise clobber the
# helper's trap).

_DEMO_BUILD_DIR="${BUILD_DIR:-build}"
_DEMO_SWITCHED=0

demo_lean_restore() {
  [ "${_DEMO_SWITCHED:-0}" = 1 ] || return 0
  _DEMO_SWITCHED=0
  echo "[demo-full] restoring fast LEAN default (-DSOTOS_DEMO_FULL=OFF)…"
  if [ -d "$_DEMO_BUILD_DIR" ]; then
    ( cd "$_DEMO_BUILD_DIR" \
        && cmake -DSOTOS_DEMO_FULL=OFF .. >/tmp/demo-full-restore.log 2>&1 \
        && ninja >>/tmp/demo-full-restore.log 2>&1 ) || true
  fi
}

ensure_full_demos() {
  if [ ! -d "$_DEMO_BUILD_DIR" ]; then
    just configure || return 2
  fi
  echo "[demo-full] reconfigure -DSOTOS_DEMO_FULL=ON + build (this arc demo is lean-skipped)…"
  ( cd "$_DEMO_BUILD_DIR" \
      && cmake -DSOTOS_DEMO_FULL=ON .. >/tmp/demo-full-cfg.log 2>&1 \
      && ninja >>/tmp/demo-full-cfg.log 2>&1 ) \
    || { echo "[demo-full] FULL build FAILED (see /tmp/demo-full-cfg.log)"; return 2; }
  _DEMO_SWITCHED=1
  trap demo_lean_restore EXIT
}
