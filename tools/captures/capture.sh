#!/usr/bin/env bash
# capture.sh — drive a REAL boot and record the attacker-vs-operator split panes,
# so the representative SVG/PNG figures in docs/captures/ can be replaced with
# authentic captures.  Two scenarios, mirroring the figures:
#
#   ./capture.sh inhost   Scenario A · in-host payload (agent_deception.py)
#                         LEFT  = sotos shell (attacker/malware stdout)
#                         RIGHT = tail -F of the serial (operator ground truth)
#   ./capture.sh recon    Scenario B · external recon
#                         attacker = nmap/openssl/ssh from the host
#                         operator = sottrace lines -> sottrace_netgraph.py
#
# Best run on a box with KVM — TCG works but is slow.  Recording
# is optional (asciinema if present).  This is the bridge from "representative" to
# "real": run it, screenshot the panes (or export the .cast), drop into the deck.
#
# Refs: docs/demo-agent-deception-runbook.md (§3 layout, §10 quick-ref),
#       tools/sottrace_netgraph.py, tools/{tls13,ja3s-ems,ssh-kex}-gate.sh.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

MODE="${1:-help}"
LOG="${SOTOS_TRACE_LOG:-/tmp/sotos-trace.log}"
SESS="sotos-capture"
HOST="${HONEYPOT_HOST:-127.0.0.1}"
P443="${HONEYPOT_443:-8443}"   # host port forwarded to guest :443
P22="${HONEYPOT_22:-8022}"     # host port forwarded to guest :22

have(){ command -v "$1" >/dev/null 2>&1; }
note(){ printf '\033[36m[capture]\033[0m %s\n' "$*"; }

# operator-side filter: the read-aloud tags (runbook §3)
OP_FILTER='sentinel-ext|functor|ghost|phantom|sotnet|dns|tier2|procd|sottrace|ja3s|orch] (SPAWN|honey|VFORK)'

inhost() {
  have tmux || { note "tmux required for the split-pane layout"; exit 1; }
  note "Scenario A · in-host payload.  Serial → $LOG"
  note "LEFT = sotos shell (attacker) · RIGHT = operator ground truth"
  REC=""
  if have asciinema; then REC="asciinema rec -q -c 'tmux attach -t $SESS' docs/captures/scenario-A.cast"; fi

  tmux kill-session -t "$SESS" 2>/dev/null || true
  # LEFT: boot piped through tee so the operator pane can tail it
  tmux new-session -d -s "$SESS" -x 220 -y 50 \
    "just run-tpm 2>&1 | tee '$LOG'; read -p '[left] boot exited — enter to close'"
  # RIGHT: the operator's filtered ground-truth feed
  tmux split-window -h -t "$SESS" \
    "until [ -f '$LOG' ]; do sleep 0.3; done; tail -F '$LOG' | grep --line-buffered -E '$OP_FILTER'"
  tmux select-pane -t "$SESS".0
  cat <<EOF

  ── now drive the demo in the LEFT pane (runbook §10) ──────────────────
    sotos> plant /honey-scripts/agent_deception.py "\$(cat scripts/demo/agent_deception.py)"
    sotos> sotinfo
    sotos> inject-script /honey-scripts/agent_deception.py
    ... watch the RIGHT pane: HONEY_READ → F_0→F_1 ghost → TCP_OPEN → F_1→F_2
        phantom (no SYN) → DNS HIT → PHANTOM_FORK
    sotos> sotinfo ; sentinel-log ; tpm-pcrs        # postmortem
  ───────────────────────────────────────────────────────────────────────
  Screenshot both panes (the figure), or export the asciinema .cast.
EOF
  if [ -n "$REC" ]; then note "recording: $REC"; eval "$REC"; else tmux attach -t "$SESS"; fi
}

recon() {
  note "Scenario B · external recon against $HOST (:$P443 TLS, :$P22 SSH)"
  note "Boot sotOs FIRST with host-forwards, e.g.:"
  note "  qemu ... -netdev user,id=n0,hostfwd=tcp::$P443-:443,hostfwd=tcp::$P22-:22 ..."
  note "and tee the serial to $LOG (operator pane: tail -F '$LOG' | grep -E 'sottrace|ja3s')"
  echo
  note "── attacker probes (host side) ──"
  ( set -x
    nmap -sV -p "$P443","$P22" "$HOST" || true
    printf 'GET / HTTP/1.0\r\nHost: honeypot\r\n\r\n' | \
      timeout 15 openssl s_client -connect "$HOST:$P443" -tls1_3 -ign_eof 2>&1 | \
      grep -iE 'Protocol|Cipher|subject=|verify' || true
    ssh-keyscan -p "$P22" -t ed25519 "$HOST" 2>&1 | grep -v '^#' || true
  ) || true
  echo
  note "── operator forensic graph from the captured serial ──"
  if [ -f "$LOG" ]; then
    python3 tools/sottrace_netgraph.py "$LOG" && \
      mv -f sottrace.netgraph.dot docs/captures/ 2>/dev/null || true
    python3 tools/captures/render_netgraph.py docs/captures/sottrace.netgraph.dot \
      docs/captures/sottrace-netgraph.svg
    note "wrote docs/captures/sottrace-netgraph.svg (render to PNG: see README)"
  else
    note "no serial at $LOG yet — boot + tee first, then re-run 'recon'"
  fi
}

case "$MODE" in
  inhost) inhost ;;
  recon)  recon ;;
  *) sed -n '2,20p' "$0" ;;
esac
