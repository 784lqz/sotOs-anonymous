# Marker target for the PR 6 procd-fork-test fixture · the binary is
# pre-built and committed (same pattern as lucas_hello / lucas_fork_test).
# We expose its path as a variable for the orch CPIO bundling step.
#
# Distinct basename ("procd_fork_test.bin") from lucas_fork_test/fork_test.bin
# so both can coexist in the same CPIO archive · CPIO addressing uses the
# basename of the source path.

set(PROCD_FORK_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/procd_fork_test.bin"
    CACHE FILEPATH "Path to the pre-built procd-fork-test fixture"
    FORCE)

if(NOT EXISTS "${PROCD_FORK_TEST_BIN}")
    message(WARNING
        "sotOs-procd-fork-test: ${PROCD_FORK_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
