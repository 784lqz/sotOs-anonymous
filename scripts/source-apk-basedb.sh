#!/usr/bin/env bash
set -euo pipefail
RT="${RT:-podman}"
OUT="src/test/sotOs-apk/db/installed"
mkdir -p "$(dirname "$OUT")"
"$RT" run --rm alpine:3.20 cat /lib/apk/db/installed > "$OUT"
echo "wrote $OUT · $(grep -c '^P:' "$OUT") packages, $(wc -l < "$OUT") lines"
