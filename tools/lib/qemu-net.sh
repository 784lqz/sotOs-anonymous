#!/usr/bin/env bash
# sotOs · shared QEMU networking selector.  SOURCE this (don't exec):
#     . "$(dirname "$0")/lib/qemu-net.sh"
#
# Picks the guest netdev based on SOTOS_NET_MODE and exposes a uniform set of
# variables so a gate works on either fabric without per-gate branching:
#
#   NET_MODE      "slirp" (default) | "vhost"
#   GUEST_IP      127.0.0.1 (slirp · via hostfwd) | 10.7.0.50 (vhost · tap)
#   QEMU_NETARGS  the -netdev + -device virtio-net-pci args (one string)
#   SSH_HOST      where the harness SSHes the guest's :22
#   SSH_PORT_ARG  "-p <fwd>" under slirp · "" under vhost (direct :22)
#
# slirp keeps the historical behaviour (default) so existing gates are
# unchanged.  Per-gate hostfwd ports are overridable via env:
#   SOTOS_FWD_SSH / SOTOS_FWD_HTTP / SOTOS_FWD_HTTPS  (default 18022/18080/18443)
# vhost requires the host fabric up first: `sudo tools/net-tap-setup.sh`.
#
# Override knobs: SOTOS_NET_MODE, SOTOS_GUEST_IP, SOTOS_GUEST_MAC, SOTOS_TAP.

NET_MODE="${SOTOS_NET_MODE:-slirp}"
SOTOS_GUEST_MAC="${SOTOS_GUEST_MAC:-52:54:00:12:34:56}"

if [ "$NET_MODE" = "vhost" ]; then
    GUEST_IP="${SOTOS_GUEST_IP:-10.7.0.50}"
    _TAP="${SOTOS_TAP:-sotos0}"
    QEMU_NETARGS="-netdev tap,id=net0,ifname=${_TAP},script=no,downscript=no,vhost=on -device virtio-net-pci,netdev=net0,mac=${SOTOS_GUEST_MAC}"
    SSH_HOST="$GUEST_IP"
    SSH_PORT_ARG=""
else
    NET_MODE="slirp"
    GUEST_IP="127.0.0.1"
    _FWD_SSH="${SOTOS_FWD_SSH:-18022}"
    _FWD_HTTP="${SOTOS_FWD_HTTP:-18080}"
    _FWD_HTTPS="${SOTOS_FWD_HTTPS:-18443}"
    QEMU_NETARGS="-netdev user,id=net0,hostfwd=tcp::${_FWD_HTTP}-:80,hostfwd=tcp::${_FWD_SSH}-:22,hostfwd=tcp::${_FWD_HTTPS}-:443 -device virtio-net-pci,netdev=net0,mac=${SOTOS_GUEST_MAC}"
    SSH_HOST="127.0.0.1"
    SSH_PORT_ARG="-p ${_FWD_SSH}"
fi

export NET_MODE GUEST_IP QEMU_NETARGS SSH_HOST SSH_PORT_ARG SOTOS_GUEST_MAC
