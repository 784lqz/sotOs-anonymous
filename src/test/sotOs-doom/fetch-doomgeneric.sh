#!/usr/bin/env bash
# Vendors doomgeneric (ozkl) into external/doomgeneric for the static-musl build.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"
DEST=external/doomgeneric
rm -rf "$DEST"; mkdir -p external
git clone --depth 1 https://github.com/ozkl/doomgeneric.git "$DEST"
echo "vendored doomgeneric → $DEST/doomgeneric (the engine C sources)"
