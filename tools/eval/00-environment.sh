#!/usr/bin/env bash
# Reproducibility hygiene (cross-cutting, run FIRST): pin + record every version into
# environment.txt so a reviewer can regenerate any T1-T5 number. The paper ties each
# table to its gate; this file is the environment half of that contract.
set -u
cd "$(git rev-parse --show-toplevel)"
OUT="tools/eval/environment.txt"; : > "$OUT"
log(){ echo "$*" | tee -a "$OUT"; }
log "=== sotOs eval environment · $(date -u +%FT%TZ) ==="
log "sotOs commit:   $(git rev-parse HEAD 2>/dev/null)"
log "sotOs branch:   $(git rev-parse --abbrev-ref HEAD 2>/dev/null)"
log "seL4 commit:    $(git -C kernel rev-parse HEAD 2>/dev/null || echo 'see submodule/manifest')"
log "host kernel:    $(uname -a)"
log "qemu:           $(qemu-system-x86_64 --version 2>/dev/null | head -1)"
log "openssl:        $(openssl version 2>/dev/null)"
log "nmap:           $(nmap --version 2>/dev/null | head -1)"
log "p0f:            $(p0f --version 2>&1 | head -1)"
log "curl:           $(curl --version 2>/dev/null | head -1)"
log "tcpdump:        $(tcpdump --version 2>&1 | head -1)"
log "python3:        $(python3 --version 2>&1)"
log "docker:         $(docker --version 2>/dev/null)"
log "nginx ref:      nginx:alpine@sha256:<PIN-DIGEST>   # docker inspect --format='{{index .RepoDigests 0}}' nginx:alpine"
log "alpine ref:     3.20.x   # exact: cat /etc/alpine-release on the reference"
log "ja4 tool:       <FoxIO ja4 ref impl commit>        # github.com/FoxIO-LLC/ja4"
log "persona:        Alpine 3.20 / linux-lts 6.6.30 / prod-db-01 (canary tier)"
log ""
log "=== sotOs hostfwd ports (from justfile) ==="
grep -oE 'hostfwd=tcp::[0-9]+-:[0-9]+' justfile 2>/dev/null | sort -u | sed 's/^/  /' | tee -a "$OUT"
log ""
log "DONE → $OUT  (commit this alongside the result CSVs/pcaps as the artifact)"
