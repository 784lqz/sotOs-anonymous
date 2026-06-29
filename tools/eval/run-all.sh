#!/usr/bin/env bash
# tools/eval/run-all.sh — ONE-SHOT orchestrator for the sotOs paper evaluation (T1-T5).
# Detects tooling + docker perms, brings up the docker references, runs every experiment
# it can, SKIPS the rest with a clear reason, and writes a consolidated RESULTS.md.
# Idempotent + re-runnable. sotOs must already be booted (just run-4pane / just run).
#
# Usage:
#   tools/eval/run-all.sh                 # all experiments, 3 runs each
#   tools/eval/run-all.sh --runs 5
#   tools/eval/run-all.sh --only "t1 t3"  # subset
#   tools/eval/run-all.sh --no-install    # don't auto apt/pip
#   tools/eval/run-all.sh --keep-refs     # leave the docker refs up afterwards
set -uo pipefail
cd "$(git rev-parse --show-toplevel)"

RUNS="${RUNS:-3}"; DO_INSTALL=1; KEEP_REFS=0; ONLY=""
while [ $# -gt 0 ]; do case "$1" in
  --runs) RUNS="$2"; shift 2;;
  --no-install) DO_INSTALL=0; shift;;
  --keep-refs) KEEP_REFS=1; shift;;
  --only) ONLY="$2"; shift 2;;
  *) echo "unknown arg: $1"; exit 1;;
esac; done

TS=$(date +%Y%m%d_%H%M%S)
RUNDIR="tools/eval/run-${TS}"; mkdir -p "$RUNDIR"
SUMMARY="$RUNDIR/RESULTS.md"; : > "$SUMMARY"
declare -A VERDICT
say(){ echo "$*" | tee -a "$SUMMARY"; }
mark(){ VERDICT[$1]="$2"; }
have(){ command -v "$1" >/dev/null 2>&1; }
want(){ [ -z "$ONLY" ] && return 0; case " $ONLY " in *" $1 "*) return 0;; *) return 1;; esac; }

say "# sotOs evaluation — run $TS  (RUNS=$RUNS)"
say ""

# ---- detection -------------------------------------------------------------
DOCKER=""
if have docker; then
  if docker info >/dev/null 2>&1; then DOCKER="docker"
  elif sudo -n docker info >/dev/null 2>&1; then DOCKER="sudo docker"; fi
fi
NSUDO=""; [ "$(id -u)" -ne 0 ] && NSUDO="sudo"
# resolve jarm/jarm.py in the USER's PATH now, so it survives sudo's secure_path (which
# drops ~/.local/bin) — passed to T1 via env below.
JARM_BIN="$(command -v jarm jarm.py 2>/dev/null | head -1 || true)"
SOTOS_UP=0; ss -tln 2>/dev/null | grep -q ':18443' && SOTOS_UP=1
say "## environment"
say "- docker:   ${DOCKER:-UNAVAILABLE (not in 'docker' group + no passwordless sudo)}"
say "- sotOs up: $([ $SOTOS_UP = 1 ] && echo 'yes (:18022/:18080/:18443)' || echo 'NO — boot it with just run-4pane')"
for t in tcpdump nmap p0f sshpass openssl; do say "- $t: $(have $t && echo yes || echo MISSING)"; done
say "- jarm: ${JARM_BIN:-MISSING -- install jarm/jarm.py for T1 real JARM row}"
say ""
bash tools/eval/00-environment.sh >/dev/null 2>&1 && say "- versions pinned → tools/eval/environment.txt"
say ""

# ---- optional dependency install ------------------------------------------
if [ "$DO_INSTALL" = 1 ]; then
  miss=""; for t in tcpdump nmap p0f sshpass; do have "$t" || miss="$miss $t"; done
  if [ -n "$miss" ]; then
    if sudo -n true 2>/dev/null; then say "[deps] sudo apt-get install$miss"; sudo apt-get install -y $miss >/dev/null 2>&1 || true
    else say "[deps] NOTE: run yourself →  sudo apt-get install -y$miss"; fi
  fi
  have jarm || { pip3 install --quiet jarm >/dev/null 2>&1 && say "[deps] pip installed jarm" || say "[deps] NOTE: pip3 install jarm (real JARM row of T1)"; }
fi

# ---- docker references -----------------------------------------------------
setup_nginx(){
  [ -n "$DOCKER" ] || return 1
  $DOCKER rm -f ref-nginx >/dev/null 2>&1 || true
  $DOCKER run -d --name ref-nginx -p 18444:443 nginx:alpine sh -c \
    'apk add --no-cache openssl >/dev/null 2>&1; \
     openssl req -x509 -newkey rsa:2048 -keyout /k -out /c -days 1 -nodes -subj /CN=ref >/dev/null 2>&1; \
     printf "server{listen 443 ssl;ssl_certificate /c;ssl_certificate_key /k;}" > /etc/nginx/conf.d/tls.conf; \
     nginx -t 2>/dev/null && nginx -g "daemon off;"' >/dev/null 2>&1 || return 1
  local dg; dg=$($DOCKER inspect --format='{{index .RepoDigests 0}}' nginx:alpine 2>/dev/null)
  echo "nginx ref digest: $dg" >> tools/eval/environment.txt
  return 0
}
setup_alpine(){
  [ -n "$DOCKER" ] || return 1
  $DOCKER rm -f ref-alpine >/dev/null 2>&1 || true
  $DOCKER run -d --name ref-alpine -p 2222:22 alpine:3.20 sh -c \
    'apk add openssh >/dev/null 2>&1; ssh-keygen -A; echo root:root | chpasswd; \
     sed -i "s/#\?PermitRootLogin.*/PermitRootLogin yes/" /etc/ssh/sshd_config; \
     /usr/sbin/sshd -D' >/dev/null 2>&1 || return 1
  return 0
}

# ---- T1 · TLS fingerprint --------------------------------------------------
if want t1; then
  if [ $SOTOS_UP = 0 ]; then mark t1 "SKIP(sotOs not up)"
  elif ! have tcpdump; then mark t1 "SKIP(need tcpdump)"
  elif [ -z "$DOCKER" ]; then mark t1 "SKIP(need docker for the nginx ref)"
  else
    say "[T1] starting nginx ref + capture …"
    setup_nginx && sleep 2 || { mark t1 "SKIP(nginx ref failed)"; }
    if [ "${VERDICT[t1]:-}" = "" ]; then
      $NSUDO env IFACE=lo JARM_BIN="$JARM_BIN" bash tools/eval/t1-tls-fp/run.sh "$RUNS" > "$RUNDIR/t1.log" 2>&1 || true
      cp tools/eval/t1-tls-fp/results-*/t1-table.txt "$RUNDIR/t1-table.txt" 2>/dev/null || true
      if grep -q 'RESULT: PASS' "$RUNDIR/t1.log"; then mark t1 PASS
      elif grep -q 'RESULT: FAIL' "$RUNDIR/t1.log"; then mark t1 FAIL
      else mark t1 "RAN(see t1.log)"; fi
    fi
  fi
fi

# ---- T2 · TCP/IP fingerprint (NAT caveat) ----------------------------------
if want t2; then
  if [ $SOTOS_UP = 0 ]; then mark t2 "SKIP(sotOs not up)"
  elif ! have nmap; then mark t2 "SKIP(need nmap+p0f)"
  else
    say "[T2] nmap -O (⚠ user-mode NAT caveat) …"
    $NSUDO bash tools/eval/t2-tcp-fp/run.sh "$RUNS" > "$RUNDIR/t2.log" 2>&1 || true
    mark t2 "RAN(⚠ QEMU SLIRP fingerprints the NAT not sotOs-delta — needs TAP for a valid number)"
  fi
fi

# ---- T3 · shell recon battery ----------------------------------------------
if want t3; then
  if [ $SOTOS_UP = 0 ]; then mark t3 "SKIP(sotOs not up)"
  elif [ -z "$DOCKER" ]; then mark t3 "SKIP(need docker for the alpine ref)"
  else
    say "[T3] starting alpine ref + recon battery …"
    setup_alpine && sleep 3 || { mark t3 "SKIP(alpine ref failed)"; }
    if [ "${VERDICT[t3]:-}" = "" ]; then
      bash tools/eval/t3-shell-recon/run.sh --ref-host 127.0.0.1 --ref-port 2222 \
           --honey-port 18022 --iterations "$RUNS" --output-dir "$RUNDIR" > "$RUNDIR/t3.log" 2>&1 || true
      if grep -q 'RESULT: PASS' "$RUNDIR/t3.log"; then mark t3 PASS
      elif grep -q 'RESULT: FAIL' "$RUNDIR/t3.log"; then mark t3 FAIL
      else mark t3 "RAN(see t3.log — check honey-SSH auth flow if no SSH)"; fi
    fi
  fi
fi

# ---- T4 · containment soak -------------------------------------------------
if want t4; then
  if [ -f /tmp/p4b.log ]; then
    say "[T4] analyzing existing /tmp/p4b.log …"
    bash tools/eval/t4-containment/soak.sh /tmp/p4b.log > "$RUNDIR/t4.log" 2>&1 || true
    grep -q 'VERDICT' "$RUNDIR/t4.log" && mark t4 "RAN(see t4.log)" || mark t4 "RAN"
  elif pgrep -f 'qemu-system-x86_64.*sotfs.img' >/dev/null 2>&1; then
    mark t4 "SKIP(run-4pane holds sotfs.img — kill it, then: scripts/v1.5-endurance-run.sh → /tmp/p4b.log)"
  else
    mark t4 "SKIP(no /tmp/p4b.log — run scripts/v1.5-endurance-run.sh first)"
  fi
fi

# ---- T5 · syscall overhead -------------------------------------------------
if want t5; then
  mark t5 "SKIP(build microbench.bin into the binstore first — see tools/eval/t5-syscall/CMakeLists.txt + just build)"
fi

# ---- teardown + summary ----------------------------------------------------
if [ "$KEEP_REFS" = 0 ] && [ -n "$DOCKER" ]; then
  $DOCKER rm -f ref-nginx ref-alpine >/dev/null 2>&1 || true
fi

say ""
say "## results"
for t in t1 t2 t3 t4 t5; do say "- **${t^^}**: ${VERDICT[$t]:-not-run}"; done
say ""
say "Artifacts in \`$RUNDIR/\` (logs + tables). Pin versions: tools/eval/environment.txt"
echo ""; echo "================== SUMMARY =================="; cat "$SUMMARY" | sed -n '/## results/,$p'
echo "Full summary: $SUMMARY"
