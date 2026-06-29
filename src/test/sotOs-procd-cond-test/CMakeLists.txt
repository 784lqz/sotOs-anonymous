# Marker target for the PR 12 procd-cond-test fixture · the binary is
# pre-built and committed (same pattern as lucas_pthread /
# sotOs-procd-fork-test / sotOs-procd-pg-test).  We expose its path as
# a variable for the orch CPIO bundling step.
#
# Distinct basename ("procd_cond_test.bin") so it coexists with the PR 6
# procd_fork_test.bin and PR 9 procd_pg_test.bin in the same CPIO
# archive · CPIO addressing uses the basename of the source path.

set(PROCD_COND_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/procd_cond_test.bin"
    CACHE FILEPATH "Path to the pre-built procd-cond-test fixture"
    FORCE)

if(NOT EXISTS "${PROCD_COND_TEST_BIN}")
    message(WARNING
        "sotOs-procd-cond-test: ${PROCD_COND_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
