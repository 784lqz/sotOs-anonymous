#!/usr/bin/env bash
# Build sotmark.deb — a minimal Debian package whose postinst has an OBSERVABLE
# /etc side effect (install-arc Phase 1b).  dpkg unpacks control.tar → the
# maintainer script /var/lib/dpkg/info/sotmark.postinst, then `configure` runs it
# via fork+execve("/bin/sh") (binfmt_script shebang → busybox sh), which writes
# /etc/sotmark.conf in the writable /etc union upper.
#
# No dpkg-deb on the build host → assemble the .deb by hand: it is an `ar`
# archive of {debian-binary, control.tar.xz, data.tar.xz}, exactly like hello.deb
# (verify with `ar t hello.deb`).  Reproducible: run this to regenerate the blob.
set -euo pipefail
cd "$(dirname "$0")"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── control.tar.xz · the metadata + the postinst maintainer script ───────────
mkdir -p "$WORK/control"
cat > "$WORK/control/control" <<'CTRL'
Package: sotmark
Version: 1.0
Architecture: amd64
Maintainer: sotOs <root@sotos>
Installed-Size: 1
Depends: libc6
Section: admin
Priority: optional
Description: sotOs postinst /etc side-effect demo
 Its postinst writes /etc/sotmark.conf via /bin/sh on configure — the install-arc
 Phase-1b maintainer-script proof.
CTRL

cat > "$WORK/control/postinst" <<'POST'
#!/bin/sh
set -e
case "$1" in
  configure)
    echo "sotmark: configured by postinst (dpkg $2)" > /etc/sotmark.conf
    echo "[sotmark.postinst] wrote /etc/sotmark.conf via /bin/sh configure"
    ;;
esac
exit 0
POST
chmod 0755 "$WORK/control/postinst"

( cd "$WORK/control" && tar --numeric-owner --owner=0 --group=0 \
    -czf "$WORK/control.tar.gz" ./control ./postinst )

# ── data.tar.xz · a token shipped file (so data is non-empty + observable) ───
mkdir -p "$WORK/data/usr/share/doc/sotmark"
cat > "$WORK/data/usr/share/doc/sotmark/README" <<'DOC'
sotmark — install-arc Phase 1b postinst demo package.
DOC
( cd "$WORK/data" && tar --numeric-owner --owner=0 --group=0 \
    -czf "$WORK/data.tar.gz" ./usr )

# ── debian-binary + ar-assemble the .deb (member ORDER matters to dpkg) ──────
printf '2.0\n' > "$WORK/debian-binary"
rm -f sotmark.deb
ar rc sotmark.deb "$WORK/debian-binary" "$WORK/control.tar.gz" "$WORK/data.tar.gz"

echo "built sotmark.deb:"; ar t sotmark.deb
