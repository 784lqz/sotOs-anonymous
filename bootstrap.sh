#!/usr/bin/env bash
# sotOs bootstrap · zero-to-buildable en Fedora o Ubuntu/Debian (incl. WSL2)
# Idempotente: corrible varias veces sin romper nada.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EXT_DIR="$SCRIPT_DIR/external"

log()  { printf '\033[1;34m[sotOs]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[err]\033[0m %s\n' "$*" >&2; exit 1; }

# --- 1. Detectar distro / package manager ---
. /etc/os-release
case "${ID:-} ${ID_LIKE:-}" in
    *fedora*|*rhel*)   PKG=dnf ;;
    *ubuntu*|*debian*) PKG=apt ;;
    *) die "Distro no soportada (${ID:-?}): se esperaba Fedora o Ubuntu/Debian." ;;
esac
log "Distro: ${PRETTY_NAME:-$ID} · package manager: $PKG"

# --- 2. Dependencies ---
# Algunas son obligatorias para CMake/Ninja/QEMU; otras son para el build
# de musllibc y libsel4 (libxml2 para tools, etc).
if [[ "$PKG" == dnf ]]; then
    DEPS=(
        git make cmake ninja-build
        gcc gcc-c++ binutils-devel
        python3 python3-pip
        libxml2-devel
        qemu-system-x86 xorriso syslinux
        findutils which procps-ng
        # Para parsers y elfloader
        bison flex
        # Para extraer ISOs y firmar
        cpio
        # Packers de sotfs.img (stdlib zip + tarball python-build-standalone)
        zip zstd
        # Útiles
        util-linux
    )
    pkg_installed() { rpm -q "$1" >/dev/null 2>&1; }
    pkg_install()   { sudo dnf install -y "$@"; }
else
    # Mismos deps con nombres Debian/Ubuntu. Extras que Fedora trae de base
    # pero Ubuntu (sobre todo WSL minimal) no: curl, patch, libxml2-utils (xmllint).
    DEPS=(
        git make cmake ninja-build
        gcc g++ binutils-dev
        python3 python3-pip
        libxml2-dev libxml2-utils
        qemu-system-x86 xorriso syslinux
        findutils procps
        bison flex
        cpio
        util-linux
        curl patch
        # Packers de sotfs.img (stdlib zip + tarball python-build-standalone)
        zip zstd
    )
    pkg_installed() { dpkg -s "$1" >/dev/null 2>&1; }
    pkg_install()   { sudo apt-get update && sudo apt-get install -y "$@"; }
fi

log "Verificando dependencies del sistema..."
MISSING=()
for pkg in "${DEPS[@]}"; do
    pkg_installed "$pkg" || MISSING+=("$pkg")
done

if [[ ${#MISSING[@]} -gt 0 ]]; then
    warn "Faltan paquetes: ${MISSING[*]}"
    read -rp "¿Instalar con sudo $PKG? [y/N] " ans
    [[ "$ans" =~ ^[Yy]$ ]] || die "Instalá manualmente y volvé."
    pkg_install "${MISSING[@]}"
fi

# --- 3. Carpeta external/ ---
mkdir -p "$EXT_DIR"

# --- 4. Clonar los 5 repos seL4 ---
clone_if_missing() {
    local url="$1" path="$2"
    if [[ -d "$path/.git" ]]; then
        log "$(basename "$path") ya clonado, omitiendo."
    else
        log "Clonando $(basename "$path")..."
        git clone --depth 1 "$url" "$path"
    fi
}

clone_if_missing "https://github.com/seL4/seL4"         "$EXT_DIR/kernel"
clone_if_missing "https://github.com/seL4/seL4_libs"    "$EXT_DIR/seL4_libs"
clone_if_missing "https://github.com/seL4/util_libs"    "$EXT_DIR/util_libs"
clone_if_missing "https://github.com/seL4/musllibc"     "$EXT_DIR/musllibc"
clone_if_missing "https://github.com/seL4/seL4_tools"   "$EXT_DIR/seL4_tools"
clone_if_missing "https://github.com/seL4/sel4runtime"  "$EXT_DIR/sel4runtime"
# lwIP upstream source · util_libs/liblwip is only the seL4 CMake glue; the real
# stack (src/core/tcp.c, src/api sockets) lives here.  Enables the mature
# TCP/IP egress path (liblwip + libethdrivers virtio_pci + libplatsupport timers)
# that replaces the hand-rolled δ busy-poll stack for outbound connectivity.
clone_if_missing "https://github.com/seL4/lwip"         "$EXT_DIR/lwip"

# sotOs lwIP config · external/ is gitignored (cloned above), so drop our
# tracked lwipopts.h into the cloned liblwip include dir (liblwip's CMake puts
# that dir on the lwip target's include path).  Source of truth: src/sotnet/lwip.
if [[ -d "$EXT_DIR/util_libs/liblwip/include" ]]; then
    cp "$SCRIPT_DIR/src/sotnet/lwip/lwipopts.h" \
       "$EXT_DIR/util_libs/liblwip/include/lwipopts.h"
    log "lwIP egress config installed (lwipopts.h → liblwip/include)"
    # liblwip glue references a config target `liblwip_config`, but seL4's
    # add_config_library(lwip) creates `lwip_Config` → fix the name so a
    # direct link of the `lwip` target resolves (else ld: -lliblwip_config).
    sed -i 's/target_link_libraries(lwip muslc liblwip_config)/target_link_libraries(lwip muslc lwip_Config)/' \
        "$EXT_DIR/util_libs/liblwip/CMakeLists.txt" 2>/dev/null || true
fi

# --- 4b. BearSSL 0.6 · vendored TLS lib (sotNet γ-3-γ-2) ---
# Not a git repo upstream · fetched as the release tarball (sha256-pinned).
# The seL4/musl build glue is tracked at src/bearssl/CMakeLists.txt, which
# globs external/bearssl/src — so only the upstream source is fetched here.
BEARSSL_VER="0.6"
BEARSSL_SHA="6705bba1714961b41a728dfc5debbe348d2966c117649392f8c8139efc83ff14"
if [[ -f "$EXT_DIR/bearssl/inc/bearssl.h" ]]; then
    log "BearSSL ya presente, omitiendo."
else
    log "Fetching BearSSL $BEARSSL_VER..."
    tmp="$(mktemp -d)"
    curl -sSL -o "$tmp/bearssl.tgz" "https://bearssl.org/bearssl-$BEARSSL_VER.tar.gz"
    echo "$BEARSSL_SHA  $tmp/bearssl.tgz" | sha256sum -c - \
        || die "BearSSL tarball sha256 mismatch (supply-chain)."
    tar xzf "$tmp/bearssl.tgz" -C "$tmp"
    mkdir -p "$EXT_DIR/bearssl"
    cp -r "$tmp/bearssl-$BEARSSL_VER"/{src,inc,tools,T0,mk,conf,Makefile,LICENSE.txt} \
          "$EXT_DIR/bearssl/"
    rm -rf "$tmp"

    # sotOs customizations on top of pristine BearSSL 0.6 (arc-gamma byte-exact
    # JA3S: native ServerHello ec_point_formats/session_ticket/EMS extensions +
    # real RFC 7627 EMS key derivation). Tracked under patches/bearssl/, mirroring
    # patches/kernel/. The patch includes the regenerated ssl_hs_server.c, so the
    # T0 compiler is NOT needed here (only when re-editing the .t0; see
    # tools/bearssl-regen-t0.sh). --forward = idempotent (skips already-applied).
    for p in "$SCRIPT_DIR"/patches/bearssl/*.patch; do
        [ -e "$p" ] || continue
        log "Applying BearSSL patch $(basename "$p")..."
        ( cd "$EXT_DIR/bearssl" && patch -p1 --forward --silent < "$p" ) \
            || die "BearSSL patch $(basename "$p") failed to apply."
    done
fi

# sotOs kernel customizations (ADR-005 RSP-save, ADR-006 Linux-ABI syscall route).
# Tracked under patches/kernel/ (external/kernel is gitignored). --forward = idempotent
# (a patch already baked into the clone is skipped, not fatal).
for p in "$SCRIPT_DIR"/patches/kernel/*.patch; do
    [ -e "$p" ] || continue
    log "Applying kernel patch $(basename "$p")..."
    ( cd "$EXT_DIR/kernel" && patch -p1 --forward --silent < "$p" ) || true
done

# --- 5. Python dependencies para el build de seL4 ---
# `future` no está empaquetado en Fedora 44 como rpm; sel4-deps lo trae
# como transitive dep. Si pip mete un PEP 668 break, usamos --break-system-packages
# explícito porque estamos en --user y no en system site-packages.
log "Verificando Python deps de seL4..."
pip3 install --user --upgrade --break-system-packages \
    future \
    sel4-deps \
    camkes-deps \
    || pip3 install --user --upgrade future sel4-deps camkes-deps \
    || warn "Algunos pip packages fallaron; el build puede igualmente funcionar."

# --- 6. Sanity ---
test -f "$EXT_DIR/kernel/CMakeLists.txt" || die "kernel clone parece roto."
test -f "$EXT_DIR/seL4_libs/CMakeLists.txt" || die "seL4_libs clone parece roto."

# --- 7. Canonical seL4 layout via symlinks ---
# The seL4 cmake-tool expects kernel/, tools/cmake-tool/, projects/<lib>/
# and projects/<app>/ as path-literal subdirs of the source root. We keep
# the upstream clones isolated in external/ and surface them under the
# canonical names via relative symlinks. Idempotent.
log "Materializando layout canónico de seL4 (symlinks)..."
cd "$SCRIPT_DIR"
mkdir -p tools projects
ln -snf external/kernel                           kernel
ln -snf external/seL4_tools/cmake-tool/init-build.sh init-build.sh
ln -snf ../external/seL4_tools/cmake-tool         tools/cmake-tool
ln -snf ../external/musllibc                      projects/musllibc
ln -snf ../external/util_libs                     projects/util_libs
ln -snf ../external/seL4_libs                     projects/seL4_libs
ln -snf ../external/sel4runtime                   projects/sel4runtime
ln -snf ../src                                    projects/sotOs

# --- 8. Static CPython 3.12 para el binstore ---
# El runtime intercepta `python` y spawnea python3.12-static desde el binstore
# embebido en sotfs.img. Sin este fetch el build omite python silenciosamente y
# la shell responde "[python] (canary) python3.12-static not found". Idempotente
# (~24 MB; se salta si ya está presente). Necesita red — igual que los clones.
log "Fetcheando static CPython 3.12 para el binstore..."
bash "$SCRIPT_DIR/scripts/fetch-python.sh" \
    || warn "fetch-python falló (¿sin red?); corré 'just fetch-python' antes de 'just build' o python no andará."

log "Bootstrap completo."
log "Próximo paso: 'just configure && just build'  (python ya quedó fetcheado)."
