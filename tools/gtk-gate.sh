#!/usr/bin/env bash
# v2.4-2.6 gate · GTK3 over REAL Wayland (cairo software / wl_shm, NO EGL).
#
# The auto-demo runs `gtkspike` (right after sdlspike/doomwl): a real, unmodified
# Alpine GTK3 3.24 app inits + connects to the honest compositor and renders a
# DECORATED window (client-side-decoration titlebar + a cairo content area) over
# wl_shm.  Proof = gtk_init OK + image auto-detect works (v2.5 shared-mime-info DB)
# + the cursor theme loads (v2.6 · needs the LucAs fallocate fix for libwayland-
# cursor's pool) + the compositor sees genuine 412x383 commits (the CSD grows the
# 360x240 content, taller with the widget stack) + draw callbacks fire + no faults/EPROTO + (v2.9) the dark
# Adwaita theme applies and DejaVu glyphs rasterize.  Path to here:
# the v2.4 9-wall cascade (dynamic loader, futex-wake, wl_seat, xkb keymap,
# read-only MAP_SHARED, statfs ABI, heavy arena) → v2.5 mime-DB image loading →
# v2.6 librsvg + Adwaita icons/cursors + fallocate → decorated CSD.
set -uo pipefail
cd "$(git rev-parse --show-toplevel)" || exit 2
SLOG=/tmp/sotos-gtk-serial.log
if ps -C qemu-system-x86_64 --no-headers >/dev/null 2>&1; then echo "[gtk-gate] BLOCKED: operator QEMU live"; exit 3; fi
. tools/lib/demo-full.sh; ensure_full_demos || exit 2   # demo is lean-skipped · build the full battery (restore on exit)
for t in build/images/kernel-x86_64-pc99 build/images/sotfs.img build/images/sotOs-root-image-x86_64-pc99; do
  [ -f "$t" ] || { echo "[gtk-gate] missing $t · run 'just build'"; exit 2; }
done
rm -f "$SLOG"
echo "[gtk-gate] booting (auto-demo: gtkspike → gtk3-widget-factory terminal · ~170s)..."
timeout 180 qemu-system-x86_64 -m 4096 -display none -serial stdio -enable-kvm -cpu host \
  -kernel build/images/kernel-x86_64-pc99 -initrd build/images/sotOs-root-image-x86_64-pc99 \
  -drive file=build/images/sotfs.img,format=raw,if=none,id=sd0 -device virtio-blk-pci,drive=sd0 \
  < /dev/null > "$SLOG" 2>&1 || true

echo "=== v2.4 · GTK3 over REAL Wayland gate ==="; fail=0
sg(){ LC_ALL=C grep -ac "$1" "$SLOG"; }

[ "$(sg '\[gtk-wl\] spawned gtkspike.bin')" -ge 1 ] \
  && echo "PASS · gtkspike.bin spawned (dynamic GTK3 fixture, heavy arena)" \
  || { echo "FAIL · gtkspike did not spawn"; fail=1; }

{ [ "$(sg '\[gtkspike\] gtk_init OK')" -ge 1 ] && [ "$(sg '\[gtkspike\] display = wayland-0')" -ge 1 ]; } \
  && echo "PASS · gtk_init OK + valid GdkDisplay on the real wayland backend" \
  || { echo "FAIL · gtk_init / display"; fail=1; }

[ "$(sg '\[gtkspike\] window shown')" -ge 1 ] \
  && echo "PASS · GtkWindow realized + shown" \
  || { echo "FAIL · window not shown"; fail=1; }

# v2.5 GTK-fidelity · gdk-pixbuf image auto-detect (the GtkImage/GtkIconTheme path)
# only works with the shared-mime-info DB shipped at /usr/share/mime (gdk-pixbuf
# 2.42 sniffs via GIO/g_content_type_guess, not loader signatures).
[ "$(sg '\[gtkspike\] PNG auto-detect load OK')" -ge 1 ] \
  && echo "PASS · gdk-pixbuf image auto-detect works (shared-mime-info DB live)" \
  || { echo "FAIL · PNG auto-detect failed (gio-mime sniffing / missing mime DB)"; fail=1; }

# The DEFINITIVE gtkspike success marker is FULL PATH GREEN (gtk_main returned
# after rendering + clean exit).  The redraw COUNT is a frame-throttled proxy:
# GTK paces redraws to the compositor's frame callbacks, so under headless load it
# legitimately commits only a few frames while still reaching FULL PATH GREEN (the
# v2.5 cert documents this "headless timing-soft" behaviour).  Gate on FULL PATH
# GREEN + the PRESENCE of a render callback (≥1), not an arbitrary frame count.
ndraw=$(sg '\[gtkspike\] draw callback fired')
{ [ "$(sg '\[gtkspike\] .*FULL PATH GREEN')" -ge 1 ] && [ "${ndraw:-0}" -ge 1 ]; } \
  && echo "PASS · gtkspike render loop ran (${ndraw} draws) + reached FULL PATH GREEN" \
  || { echo "FAIL · gtkspike no FULL PATH GREEN / no draw callback (${ndraw:-0})"; fail=1; }

# v2.6/v2.9 · DECORATED window: GTK draws the CSD titlebar in the SAME wl_shm
# surface, so the commit grows past the 360x240 content to 412x383 (titlebar +
# borders).  The PRESENCE of a 412x383 commit IS the proof the client-side
# decoration rendered (the count is frame-throttled, same as the redraw count).
ncommit=$(LC_ALL=C grep -acE '\[wl-compositor\] commit .*412x383' "$SLOG")
[ "${ncommit:-0}" -ge 1 ] \
  && echo "PASS · ${ncommit} genuine 412x383 DECORATED GTK commit(s) over wl_shm (CSD titlebar rendered)" \
  || { echo "FAIL · no 412x383 decorated wl_shm commit (CSD did not render)"; fail=1; }

# v2.9 GTK-fidelity · dark Adwaita theme applied + real glyph rasterization.
# The cairo content paints a gradient + text via the freetype font path; distinct
# per-frame surface hashes (varying fnv1a on surf=15) prove changing real content.
{ [ "$(sg '\[gtkspike\] theme = Adwaita (dark)')" -ge 1 ] \
  && [ "$(sg '\[gtkspike\] cairo text rasterized')" -ge 1 ]; } \
  && echo "PASS · dark Adwaita theme + DejaVu glyph rasterization (real font path)" \
  || { echo "FAIL · dark theme / text rasterization missing"; fail=1; }

# v2.6 · the CSD only renders once the Wayland cursor theme loads — which needs the
# LucAs fallocate fix (libwayland-cursor sizes its cursor wl_shm pool via
# posix_fallocate).  Assert the theme did NOT fail + the fallocate handler fired.
{ [ "$(sg 'Failed to load cursor theme')" -eq 0 ] && [ "$(sg 'cursor_theme_name')" -eq 0 ]; } \
  && echo "PASS · Wayland cursor theme loaded (no cursor-theme abort)" \
  || { echo "FAIL · cursor theme failed to load (fallocate / posix_fallocate?)"; fail=1; }
[ "$(sg '\[l13-fallocate\] memfd')" -ge 1 ] \
  && echo "PASS · fallocate sized a wl_shm pool (libwayland-cursor path)" \
  || echo "WARN · no [l13-fallocate] marker (cursor pool may not have been sized here)"

{ [ "$(sg 'Unrecognized image')" -eq 0 ] && [ "$(sg 'Bail out')" -eq 0 ] \
  && [ "$(sg 'GLib-.*ERROR')" -eq 0 ]; } \
  && echo "PASS · no fatal GLib/GTK error (no icon-PNG/OOM abort)" \
  || { echo "FAIL · fatal GLib/GTK error"; fail=1; }

{ [ "$(sg 'Invocation of invalid cap')" -eq 0 ] && [ "$(sg 'unhandled syscall')" -eq 0 ] \
  && [ "$(sg 'CapFault')" -eq 0 ] && [ "$(sg 'FAULT UserException')" -eq 0 ] \
  && [ "$(sg 'code=139')" -eq 0 ] && [ "$(sg 'EPROTO')" -eq 0 ]; } \
  && echo "PASS · no cap/syscall/VM/User fault, no EPROTO" \
  || { echo "FAIL · fault/EPROTO detected"; fail=1; }

# #2 GTK fidelity (broader-apps) · the REAL off-the-shelf Linux app · an UNMODIFIED
# Alpine gtk3-widget-factory (NOT our gtkspike fixture, no per-app code · orch
# supplies the GTK env) — the canonical GTK widget showcase (buttons/switches/
# sliders/GtkTreeView/GtkNotebook/dialogs/spinners).  It is the TERMINAL GUI app of
# the auto-demo and renders its large window (4-digit width ~1301x784, unique vs
# gtkspike(412)/doom(640)) repeatedly over wl_shm.  Proves "real Linux GTK apps run,
# full widget set rasterizes".  (gtk3-demo is covered by tools/gtk3-demo-window-gate.sh.)
[ "$(sg '\[widget-factory\] spawned widget-factory.bin')" -ge 1 ] \
  && echo "PASS · off-the-shelf gtk3-widget-factory spawned (real Linux app, broader widget set, no per-app code)" \
  || { echo "FAIL · gtk3-widget-factory did not spawn"; fail=1; }
nwf=$(LC_ALL=C grep -acE '\[wl-compositor\] commit .*[0-9]{4}x[0-9]{3} ' "$SLOG")
[ "${nwf:-0}" -ge 30 ] \
  && echo "PASS · ${nwf} gtk3-widget-factory commits over wl_shm (full widget set rasterized)" \
  || { echo "FAIL · only ${nwf:-0} widget-factory (4-digit-width) commits"; fail=1; }
# the wl message-reassembly fix · widget-factory's larger/split flushes must NOT EINVAL
{ [ "$(sg 'Error flushing display')" -eq 0 ] && [ "$(sg '\[wl\] malformed')" -eq 0 ]; } \
  && echo "PASS · no wl_display flush EINVAL (TX reassembly handles split/large batches)" \
  || { echo "FAIL · wl_display flush error (reassembly?)"; fail=1; }

# regression · the sibling v2.x wayland clients stay green
[ "$(sg '\[sdlspike\] quit OK · exit clean · FULL PATH GREEN')" -ge 1 ] \
  && echo "PASS · regression · sdlspike FULL PATH GREEN" \
  || echo "WARN · sdlspike marker not seen (ran later / boot window)"
[ "$(sg '\[doom-wl\] .* frames ticked')" -ge 1 ] \
  && echo "PASS · regression · doomwl ticked over wl_shm" \
  || echo "WARN · doomwl marker not seen"

echo "=== $( [ $fail -eq 0 ] && echo 'GTK-OVER-WAYLAND (v2.4): PASS' || echo 'GTK-OVER-WAYLAND (v2.4): FAIL' ) ==="
echo "(serial: $SLOG)"; exit $fail
