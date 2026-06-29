# L11-β-2 · Static CPython 3.12 binary for LUCAS execution.
#
# Source: python-build-standalone (astral-sh) release 20260510 ·
#   cpython-3.12.13+20260510-x86_64-unknown-linux-musl-lto+static-full.tar.zst
#   https://github.com/astral-sh/python-build-standalone/releases/tag/20260510
#
# Acquisition (operator step · external/ is gitignored):
#   URL='https://github.com/astral-sh/python-build-standalone/releases/download/20260510/cpython-3.12.13%2B20260510-x86_64-unknown-linux-musl-lto%2Bstatic-full.tar.zst'
#   curl -sLO "$URL"
#   zstd -d cpython-*.tar.zst -o cpython-static.tar
#   tar xf cpython-static.tar
#   strip -o external/python/python3.12-static python/install/bin/python3.12
#   rm -rf cpython-* python/
#
# Provenance · stripped binary (δ-1 reference):
#   sha256: 9a5ea4d5431896b1a9778cacf61f42bc7966d0e1b9703959ddce2215ba5fcfff
#   size:   24430960 bytes (24 MB)
#   type:   ELF 64-bit LSB executable, x86-64, statically linked, stripped
#
# δ-1 STATUS · scaffold only.  CPIO embed (in src/orch/CMakeLists.txt) is
# DISABLED · 24 MB binary balloons sotOs-lucas-orch.elf to 26 MB which
# exceeds root's spawn budget (allocman frame allocation fails during
# anomaly + orch ELF segment load).  Confirmed empirically on 2026-05-23.
#
# δ-2 path forward · load python lazily from virtio-blk (sotfs.img is
# 4 MiB · too small for 24 MB binary · add second virtio-blk OR grow it).
# A spawn entry in src/root/main.c already attempts the spawn (logs
# `[orch] SPAWN 'python3.12-static' not found in CPIO`) as a marker.

set(LUCAS_PYTHON_BIN
    "${CMAKE_SOURCE_DIR}/external/python/python3.12-static"
    CACHE FILEPATH "Path to the pre-built static CPython 3.12 binary"
    FORCE)

if(NOT EXISTS "${LUCAS_PYTHON_BIN}")
    message(WARNING "lucas_python: ${LUCAS_PYTHON_BIN} not found · run:"
        "  curl -sL <python-build-standalone-static-url> | tar -xJ"
        "  strip -o external/python/python3.12-static cpython.../bin/python3.12"
        "See scripts/build-python.sh for alternative build-from-source path.")
endif()
