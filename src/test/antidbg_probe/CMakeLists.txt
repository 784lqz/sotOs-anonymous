# Marker target for the Pillar-3 sottrace-Pro anti-debug invisibility probe
# fixture · the binary is pre-built and committed; CMake doesn't compile it.
# We expose its path as a variable for orch's CPIO bundling step (see
# src/orch/CMakeLists.txt).

set(LUCAS_ANTIDBG_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/antidbg_probe.bin"
    CACHE FILEPATH "Path to the pre-built antidbg_probe invisibility fixture"
    FORCE)

if(NOT EXISTS "${LUCAS_ANTIDBG_BIN}")
    message(WARNING "antidbg_probe: ${LUCAS_ANTIDBG_BIN} not found · run rebuild per Makefile.fixture")
endif()
