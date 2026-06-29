#!/usr/bin/env bash
# Wrapper liviano sobre 'just build'.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" && just build "$@"
