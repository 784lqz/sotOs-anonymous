# Marker target for the SP1 PR 4 writable-executable-memory test fixture ·
# the binary is pre-built and committed (same pattern as syscall_test /
# anomaly_test / shellhook_test).  We expose its path as a variable for
# the orch CPIO bundling step.
#
# Distinct basename ("execmap_test.bin") from the other fixture binaries
# so all coexist in the same CPIO archive.

set(EXECMAP_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/execmap_test.bin"
    CACHE FILEPATH "Path to the pre-built writable-executable-memory test fixture"
    FORCE)

if(NOT EXISTS "${EXECMAP_TEST_BIN}")
    message(WARNING
        "sotOs-execmap-test: ${EXECMAP_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
