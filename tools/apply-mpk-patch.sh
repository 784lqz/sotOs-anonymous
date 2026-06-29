#!/usr/bin/env bash
# sotOs OBSD-eta · apply the MPK seL4 kernel patch
#
# Applies docs/patches/obsd-eta-mpk-seL4.patch to external/kernel/ so the
# CONFIG_LucAs_MPK code path becomes available (gated by the
# KernelLucAsMPK CMake flag).
#
# The patch covers steps 1+2 of the 5-step MPK design:
#   * Step 1 · CR4_PKE macro + boot-time CPUID probe / CR4.PKE enable
#   * Step 2 · 4-bit pkey field in the x86_64 pte bitfield + call-site updates
# Steps 3-5 remain deferred (see the patch file header for details).
#
# Idempotent · checks both step markers (CR4_PKE in cpu_registers.h AND the
# pkey field in structures.bf) and exits cleanly if both are present.
#
# Usage:
#   bash tools/apply-mpk-patch.sh           # apply
#   bash tools/apply-mpk-patch.sh --revert  # revert
#
# Default-OFF workflow:
#   1. bash tools/apply-mpk-patch.sh
#   2. cd build && cmake -DKernelLucAsMPK=ON ..
#   3. cd .. && just build
#   4. (to disable at runtime) cmake -DKernelLucAsMPK=OFF .. && just build
#
# Reverting the patch:
#   bash tools/apply-mpk-patch.sh --revert
#
# See docs/obsd-zeta-mpk-design.md for the underlying design memo.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PATCH_FILE="${REPO_ROOT}/docs/patches/obsd-eta-mpk-seL4.patch"
KERNEL_DIR="${REPO_ROOT}/external/kernel"
# Step 1 marker · CR4_PKE in cpu_registers.h.
PROBE_FILE="${KERNEL_DIR}/include/arch/x86/arch/machine/cpu_registers.h"
PROBE_MARKER='CR4_PKE'
# Step 2 marker · the new pkey field in the x86_64 pte bitfield.
PROBE_FILE_STEP2="${KERNEL_DIR}/include/arch/x86/arch/64/mode/object/structures.bf"
PROBE_MARKER_STEP2='field       pkey'

REVERT=0
if [ "${1:-}" = "--revert" ] || [ "${1:-}" = "-R" ]; then
    REVERT=1
fi

if [ ! -d "${KERNEL_DIR}" ]; then
    echo "ERROR: ${KERNEL_DIR} not found.  Run 'just bootstrap' first." >&2
    exit 1
fi

if [ ! -f "${PATCH_FILE}" ]; then
    echo "ERROR: ${PATCH_FILE} not found." >&2
    exit 1
fi

cd "${KERNEL_DIR}"

# Check whether the patch is already applied · BOTH step 1 (CR4_PKE) and
# step 2 (pkey field in the pte bitfield) must be present, otherwise we
# treat the patch as not fully applied and let `git apply` handle it.
if grep -q "${PROBE_MARKER}" "${PROBE_FILE}" \
   && grep -q "${PROBE_MARKER_STEP2}" "${PROBE_FILE_STEP2}"; then
    APPLIED=1
else
    APPLIED=0
fi

if [ "${REVERT}" = "1" ]; then
    if [ "${APPLIED}" = "0" ]; then
        echo "Patch is not currently applied · nothing to revert."
        exit 0
    fi
    echo "Reverting MPK patch from ${KERNEL_DIR}..."
    git apply -R "${PATCH_FILE}"
    echo "OK · CONFIG_LucAs_MPK code paths removed from kernel source."
    echo "Remember to rebuild: 'just build' from ${REPO_ROOT}"
    exit 0
fi

if [ "${APPLIED}" = "1" ]; then
    echo "Patch already applied (steps 1+2 · CR4_PKE + pte.pkey field present)."
    echo "Nothing to do.  Toggle KernelLucAsMPK in build/ to enable/disable."
    exit 0
fi

echo "Applying MPK patch to ${KERNEL_DIR}..."
git apply "${PATCH_FILE}"

echo "OK · patch applied."
echo ""
echo "Next steps:"
echo "  1. cd ${REPO_ROOT}/build && cmake -DKernelLucAsMPK=ON .. && cd .."
echo "  2. just build"
echo "  3. (default OFF state) cmake -DKernelLucAsMPK=OFF .. && just build"
echo ""
echo "See docs/obsd-zeta-mpk-design.md for the design memo."
