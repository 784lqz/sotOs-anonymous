#!/usr/bin/env bash
# scripts/package-artifact.sh
#
# Build a clean tarball for IEEE artifact submission: no .git, no .DS_Store,
# no editor cruft, no build outputs, no evidence bundles, no host-specific paths.
#
# Usage (from repo root):
#   scripts/package-artifact.sh [output.tar.gz]
#
# Default output: ../sotOs-artifact-<UTC-stamp>.tar.gz
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${1:-$(dirname "$REPO")/sotOs-artifact-${STAMP}.tar.gz}"

cd "$REPO"

echo "[package] stripping host metadata under $REPO"
find . -name '.DS_Store' -delete 2>/dev/null || true
find . -name '._*' -delete 2>/dev/null || true

echo "[package] writing $OUT"
tar czf "$OUT" \
  --exclude='.git' \
  --exclude='.DS_Store' \
  --exclude='._*' \
  --exclude='build' \
  --exclude='build-*' \
  --exclude='external' \
  --exclude='evidence' \
  --exclude='.superpowers' \
  --exclude='.cursor' \
  --exclude='.claude' \
  --exclude='.vscode' \
  --exclude='.idea' \
  --exclude='*.swp' \
  --exclude='*.swo' \
  --exclude='*.log' \
  -C "$REPO" .

echo "[package] done · $(du -h "$OUT" | cut -f1) · sha256:"
sha256sum "$OUT" 2>/dev/null || shasum -a 256 "$OUT"
