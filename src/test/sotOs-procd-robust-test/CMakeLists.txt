# Marker target for the PR 13 procd-robust-test fixture · the binary is
# pre-built and committed (same pattern as sotOs-procd-fork-test /
# sotOs-procd-pg-test / sotOs-procd-cond-test).  We expose its path as
# a variable for the orch CPIO bundling step.
#
# Distinct basename ("procd_robust_test.bin") so it coexists with the PR 6
# procd_fork_test.bin, PR 9 procd_pg_test.bin, and PR 12 procd_cond_test.bin
# in the same CPIO archive · CPIO addressing uses the basename of the
# source path.

set(PROCD_ROBUST_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/procd_robust_test.bin"
    CACHE FILEPATH "Path to the pre-built procd-robust-test fixture"
    FORCE)

if(NOT EXISTS "${PROCD_ROBUST_TEST_BIN}")
    message(WARNING
        "sotOs-procd-robust-test: ${PROCD_ROBUST_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
