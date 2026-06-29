#!/usr/bin/env bash
# tools/vdso-elf-gate.sh — build vdso.so and validate its ELF structure.
#
# Pass criteria:
#   1. DT_HASH or DT_GNU_HASH present in the dynamic section
#   2. DT_SYMTAB present
#   3. DT_SONAME = linux-vdso.so.1
#   4. All five __vdso_* symbols in the dynamic symbol table
#   5. ZERO external relocations (R_X86_64_64 / GLOB_DAT / JUMP_SLOT /
#      PLT / R_X86_64_COPY all FAIL; R_X86_64_RELATIVE is the only
#      permitted type, though ideally zero relocations total)
#
# Exits 0 on full PASS, non-zero on any failure.

set -euo pipefail
export LC_ALL=C

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
VDSO_SRC="${REPO_ROOT}/src/vdso"
VDSO_OUT="${TMPDIR:-/tmp}/vdso-gate-$$.so"

PASS=0
FAIL=0

pass() { echo "  PASS: $*"; PASS=$((PASS + 1)); }
fail() { echo "  FAIL: $*"; FAIL=$((FAIL + 1)); }

cleanup() { rm -f "${VDSO_OUT}"; }
trap cleanup EXIT

# ── Build ──────────────────────────────────────────────────────────────────
echo "[vdso-elf-gate] building ${VDSO_OUT} ..."
gcc -shared -fPIC -fno-stack-protector -fno-asynchronous-unwind-tables \
    -nostdlib \
    -I"${VDSO_SRC}" \
    -Wl,-T,"${VDSO_SRC}/vdso.lds" \
    -Wl,--hash-style=both \
    -Wl,-soname,linux-vdso.so.1 \
    -Wl,-Bsymbolic \
    -Wl,--no-warn-rwx-segments \
    -o "${VDSO_OUT}" \
    "${VDSO_SRC}/vdso_time.c" 2>&1 | grep -v 'build-id' || true

if [[ ! -f "${VDSO_OUT}" ]]; then
    echo "FATAL: gcc did not produce ${VDSO_OUT}"
    exit 1
fi
echo "[vdso-elf-gate] build OK, validating ELF ..."

# ── Dynamic section checks ─────────────────────────────────────────────────
DYN="$(readelf -d "${VDSO_OUT}")"

echo ""
echo "=== readelf -d ==="
echo "${DYN}"
echo ""

if echo "${DYN}" | grep -qE '\(HASH\)|\(GNU_HASH\)'; then
    pass "DT_HASH or DT_GNU_HASH present"
else
    fail "neither DT_HASH nor DT_GNU_HASH found"
fi

if echo "${DYN}" | grep -q '(SYMTAB)'; then
    pass "DT_SYMTAB present"
else
    fail "DT_SYMTAB missing"
fi

SONAME="$(echo "${DYN}" | grep -oP '\(SONAME\).*\[\K[^\]]+' || true)"
if [[ "${SONAME}" == "linux-vdso.so.1" ]]; then
    pass "DT_SONAME = linux-vdso.so.1"
else
    fail "DT_SONAME wrong or missing (got: '${SONAME}')"
fi

# ── Dynamic symbol checks ─────────────────────────────────────────────────
DYNSYMS="$(readelf -W --dyn-syms "${VDSO_OUT}")"

echo ""
echo "=== readelf -W --dyn-syms ==="
echo "${DYNSYMS}"
echo ""

for sym in \
    __vdso_clock_gettime \
    __vdso_gettimeofday \
    __vdso_time \
    __vdso_clock_getres \
    __vdso_getcpu
do
    if echo "${DYNSYMS}" | grep -q "${sym}"; then
        pass "symbol ${sym} present"
    else
        fail "symbol ${sym} MISSING"
    fi
done

# ── Relocation checks (I3) ──────────────────────────────────────────────────
# The vdso.so blob is embedded via .incbin and copied VERBATIM into each guest
# (src/orch/vdso_map.c) — NO dynamic linker runs in-guest.  Any relocation,
# even an R_X86_64_RELATIVE, would therefore be silently UNAPPLIED and the code
# would crash on first use.  So we require ZERO relocations total, not merely
# the absence of "external" reloc types.
RELOCS="$(readelf -r "${VDSO_OUT}")"

echo ""
echo "=== readelf -r ==="
echo "${RELOCS}"
echo ""

if echo "${RELOCS}" | grep -qF 'There are no relocations in this file.'; then
    pass "zero relocations (blob is copied verbatim; no in-guest linker to apply any)"
else
    fail "relocations present — none can be applied in-guest (see readelf -r above)"
fi

# ── PT_LOAD layout check (I4) ───────────────────────────────────────────────
# The vvar anchor in src/vdso/vdso.lds resolves _sotos_vvar to (image - 0x2000),
# which is correct ONLY if the FIRST PT_LOAD segment has p_offset == 0x1000 and
# p_vaddr == 0 (no FILEHDR/PHDRS pulled into the load segment → header page adds
# one page, so load_bias = ehdr_va + 0x1000 and the -0x2000 lands on vvar).  A
# toolchain/linker change that altered this layout would silently break the vvar
# pointer at boot.  Catch it deterministically at build time instead.
PHDRS="$(readelf -lW "${VDSO_OUT}")"

echo ""
echo "=== readelf -lW (program headers) ==="
echo "${PHDRS}"
echo ""

FIRST_LOAD="$(echo "${PHDRS}" | awk '$1=="LOAD"{print; exit}')"
LOAD_OFF="$(echo "${FIRST_LOAD}"   | awk '{print $2}')"
LOAD_VADDR="$(echo "${FIRST_LOAD}" | awk '{print $3}')"

if [[ -z "${FIRST_LOAD}" ]]; then
    fail "no PT_LOAD segment found in program headers"
elif (( LOAD_OFF == 0x1000 )) && (( LOAD_VADDR == 0 )); then
    pass "first PT_LOAD Offset=${LOAD_OFF} VirtAddr=${LOAD_VADDR} (vvar -0x2000 offset assumption holds)"
else
    fail "first PT_LOAD layout changed (Offset=${LOAD_OFF} VirtAddr=${LOAD_VADDR}; expected 0x1000 / 0x0) — vvar -0x2000 offset in src/vdso/vdso.lds is now WRONG"
fi

# ── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "========================================"
echo " vdso-elf-gate: PASS=${PASS}  FAIL=${FAIL}"
echo "========================================"
if (( FAIL > 0 )); then
    echo "RESULT: FAIL"
    exit 1
fi
echo "RESULT: PASS"
exit 0
