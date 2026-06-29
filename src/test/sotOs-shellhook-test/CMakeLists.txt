# Marker target for the PR 10 shellhook-test fixture · the binary is
# pre-built and committed (same pattern as lucas_fork_test /
# sotOs-procd-fork-test).  We expose its path as a variable for the
# orch CPIO bundling step.
#
# Distinct basename ("shellhook_test.bin") from the other fork-test
# basenames so all coexist in the same CPIO archive.

set(SHELLHOOK_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/shellhook_test.bin"
    CACHE FILEPATH "Path to the pre-built shellhook-test fixture"
    FORCE)

if(NOT EXISTS "${SHELLHOOK_TEST_BIN}")
    message(WARNING
        "sotOs-shellhook-test: ${SHELLHOOK_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
