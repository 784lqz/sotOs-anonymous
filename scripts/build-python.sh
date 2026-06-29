#!/usr/bin/env bash
# scripts/build-python.sh
#
# L11-β-1 · Static CPython 3.12.x build pipeline for sotOs/LucAs.
#
# PURPOSE
#   Build a fully static (musl) CPython 3.12.x binary suitable for embedding
#   in the orch CPIO archive and running under LucAs (the syscall-translation
#   companion). LucAs has no dynamic loader (no ld.so, no /lib/ld-musl-*.so),
#   so the interpreter MUST be statically linked.
#
# USAGE
#   bash scripts/build-python.sh                  # build with default version
#   PY_VERSION=3.12.7 bash scripts/build-python.sh
#   bash scripts/build-python.sh --help
#
# OUTPUT
#   Docker image: sotos-python-build:cpython-${PY_VERSION}
#   Inside container: /out/python3.12              (statically linked ELF64)
#
#   To extract the binary (operator step, NOT executed by this script):
#     docker create --name sotos-py-extract sotos-python-build:cpython-${PY_VERSION}
#     mkdir -p external/python
#     docker cp sotos-py-extract:/out/python3.12 external/python/python3.12-static
#     docker rm sotos-py-extract
#     file external/python/python3.12-static
#     # expected: "ELF 64-bit LSB executable, x86-64, ..., statically linked, ..."
#
# IDEMPOTENCY
#   The image is tagged with the exact CPython version. Re-running this
#   script with the same PY_VERSION will reuse Docker layer cache and
#   produce the same binary (subject to upstream CPython tarball stability).
#
# NOTES
#   - This script does NOT execute the build automatically in CI; it is
#     intended to be run manually by a maintainer with Docker available.
#   - Build time: 30-60 minutes on a typical workstation.
#   - Image size during build: ~2 GB. Final stripped binary: ~10-15 MB.
#   - This script does NOT modify any sotOs source files. It only writes
#     a Dockerfile to a temp directory and invokes `docker build`.
#
# REQUIREMENTS
#   - docker (>= 20.x)
#   - ~3 GB free disk for the build image
#
# RELATED DOCS
#   - docs/L11-prep.md · Section 3 (build options) and Section 7 (this script)
#   - docs/L11-prep.md · Section 8 (syscall coverage gap table)

set -euo pipefail

# -------- configuration ------------------------------------------------------

PY_VERSION="${PY_VERSION:-3.12.7}"
IMAGE_TAG="sotos-python-build:cpython-${PY_VERSION}"
BASE_IMAGE="${BASE_IMAGE:-alpine:3.19}"   # alpine = musl-libc target
OUTPUT_BINARY_NAME="python3.12"

# -------- help ---------------------------------------------------------------

if [[ "${1:-}" == "--help" || "${1:-}" == "-h" ]]; then
  sed -n '1,55p' "$0"
  exit 0
fi

# -------- preflight ----------------------------------------------------------

echo "[build-python] L11-beta-1 . static CPython build pipeline"
echo "[build-python] PY_VERSION = ${PY_VERSION}"
echo "[build-python] BASE_IMAGE = ${BASE_IMAGE}"
echo "[build-python] IMAGE_TAG  = ${IMAGE_TAG}"

if ! command -v docker >/dev/null 2>&1; then
  echo "[build-python] ERROR: docker not found in PATH" >&2
  exit 1
fi

if ! docker info >/dev/null 2>&1; then
  echo "[build-python] ERROR: docker daemon not reachable" >&2
  exit 1
fi

# -------- Dockerfile generation ---------------------------------------------

BUILD_DIR="$(mktemp -d -t sotos-build-python-XXXXXX)"
trap 'rm -rf "${BUILD_DIR}"' EXIT

echo "[build-python] staging Dockerfile in ${BUILD_DIR}"

cat > "${BUILD_DIR}/Dockerfile" <<DOCKERFILE
# syntax=docker/dockerfile:1
FROM ${BASE_IMAGE} AS builder

# musl toolchain + headers for CPython static build.
# We intentionally avoid optional deps (openssl, zlib, libffi, sqlite,
# readline, ncurses) since LucAs has no dynamic loader and we want the
# minimum module set for L11-gamma (print("hello")).
RUN apk add --no-cache \\
        build-base \\
        gcc \\
        make \\
        musl-dev \\
        linux-headers \\
        wget \\
        ca-certificates \\
        xz \\
        binutils

WORKDIR /build

# Lock CPython version explicitly . do not pull "latest".
ARG PY_VERSION=${PY_VERSION}
RUN wget -q https://www.python.org/ftp/python/\${PY_VERSION}/Python-\${PY_VERSION}.tar.xz \\
    && tar xf Python-\${PY_VERSION}.tar.xz \\
    && rm Python-\${PY_VERSION}.tar.xz

WORKDIR /build/Python-${PY_VERSION}

# Modules/Setup.local . explicitly list which modules to compile statically
# into the interpreter. This is the minimal set for "import sys; print(...)".
# Any module not listed here is NOT available . CPython will report
# ModuleNotFoundError at import time. Acceptable for L11-gamma.
#
# Intentionally omitted to keep dependencies minimal:
#   _ssl, _hashlib   (require OpenSSL static libs)
#   _ctypes          (requires libffi)
#   readline, ncurses, sqlite3, zlib, bz2, lzma, curses
#   _pickle          (not needed for hello-world; can be added later)
RUN cat > Modules/Setup.local <<'SETUP'
*static*
array     arraymodule.c
math      mathmodule.c _math.c
_struct   _struct.c
_json     _json.c
time      timemodule.c
_functools _functoolsmodule.c
_operator _operator.c
_collections _collectionsmodule.c
_heapq    _heapqmodule.c
_bisect   _bisectmodule.c
_random   _randommodule.c
binascii  binascii.c
SETUP

# Configure for fully static linking against musl.
# Key flags:
#   --disable-shared            . do not build libpython3.12.so
#   --without-static-libpython  . embed the interpreter directly in python3
#                                  (no separate libpython.a)
#   --without-pymalloc-mimalloc . keep PyMalloc (mimalloc requires extra deps)
#   --disable-test-modules      . drop the test suite (saves ~5MB)
#   --without-ensurepip         . no installer (we have no network anyway)
#   --without-decimal-contextvar. avoid the contextvars C-extension dep
#   LDFLAGS="-static"           . force fully static link . no ld.so reference
#   PY_UNSUPPORTED_OPENSSL_BUILD=static . suppress OpenSSL warning (we skip _ssl)
ENV LDFLAGS="-static"
ENV CFLAGS="-static -Os -fno-stack-protector"
ENV PY_UNSUPPORTED_OPENSSL_BUILD=static

RUN ./configure \\
        --prefix=/opt/python-static \\
        --disable-shared \\
        --without-static-libpython \\
        --without-pymalloc-mimalloc \\
        --disable-test-modules \\
        --without-ensurepip \\
        --without-decimal-contextvar \\
        --with-system-ffi=no \\
        --enable-optimizations=no \\
        ac_cv_file__dev_ptmx=no \\
        ac_cv_file__dev_ptc=no

RUN make -j"\$(nproc)" LINKFORSHARED=" "

# Strip and stage the output binary at a stable path.
RUN mkdir -p /out \\
    && cp ./python /out/${OUTPUT_BINARY_NAME} \\
    && strip --strip-all /out/${OUTPUT_BINARY_NAME} \\
    && file /out/${OUTPUT_BINARY_NAME} \\
    && ls -lh /out/${OUTPUT_BINARY_NAME}

# Minimal runtime stage . just the binary, for easy docker cp.
FROM ${BASE_IMAGE}
COPY --from=builder /out/${OUTPUT_BINARY_NAME} /out/${OUTPUT_BINARY_NAME}
CMD ["/bin/sh", "-c", "ls -lh /out/${OUTPUT_BINARY_NAME} && file /out/${OUTPUT_BINARY_NAME}"]
DOCKERFILE

# -------- build --------------------------------------------------------------

echo "[build-python] running: docker build -t ${IMAGE_TAG} ${BUILD_DIR}"
echo "[build-python] (this is the heavy step . 30-60 min on first run)"

docker build \
    --build-arg "PY_VERSION=${PY_VERSION}" \
    -t "${IMAGE_TAG}" \
    "${BUILD_DIR}"

echo "[build-python] image built: ${IMAGE_TAG}"

# -------- extraction instructions -------------------------------------------

echo ""
echo "[build-python] To extract the static binary, run:"
echo ""
echo "    mkdir -p external/python"
echo "    docker create --name sotos-py-extract ${IMAGE_TAG}"
echo "    docker cp sotos-py-extract:/out/${OUTPUT_BINARY_NAME} \\"
echo "              external/python/${OUTPUT_BINARY_NAME}-static"
echo "    docker rm sotos-py-extract"
echo "    file external/python/${OUTPUT_BINARY_NAME}-static"
echo ""
echo "[build-python] expected: 'statically linked' in file output."
echo "[build-python] expected size: 10-15 MB (stripped)."
echo "[build-python] done."
