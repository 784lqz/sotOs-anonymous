# Marker target for the PR 9 procd-pg-test fixture · the binary is
# pre-built and committed (same pattern as lucas_hello / lucas_fork_test
# / sotOs-procd-fork-test).  We expose its path as a variable for the
# orch CPIO bundling step.
#
# Distinct basename ("procd_pg_test.bin") so it coexists with the PR 6
# procd_fork_test.bin in the same CPIO archive · CPIO addressing uses
# the basename of the source path.

set(PROCD_PG_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/procd_pg_test.bin"
    CACHE FILEPATH "Path to the pre-built procd-pg-test fixture"
    FORCE)

if(NOT EXISTS "${PROCD_PG_TEST_BIN}")
    message(WARNING
        "sotOs-procd-pg-test: ${PROCD_PG_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
