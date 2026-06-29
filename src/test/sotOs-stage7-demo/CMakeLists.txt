# Marker target for the γ Stage 7 F_persistence demo fixture · the
# binary is pre-built and committed (same pattern as shellhook_test /
# sotOs-procd-fork-test).  We expose its path as a variable for the
# orch CPIO bundling step.
#
# Distinct basename ("stage7_demo.bin") from the other fixture binaries
# so all coexist in the same CPIO archive.

set(STAGE7_DEMO_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/stage7_demo.bin"
    CACHE FILEPATH "Path to the pre-built stage7-demo F_persistence fixture"
    FORCE)

if(NOT EXISTS "${STAGE7_DEMO_BIN}")
    message(WARNING
        "sotOs-stage7-demo: ${STAGE7_DEMO_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
