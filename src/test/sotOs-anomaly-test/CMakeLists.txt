# Marker target for the PR 7 weighted-score anomaly-test fixture · the
# binary is pre-built and committed (same pattern as syscall_test /
# shellhook_test / stage7_demo).  We expose its path as a variable for
# the orch CPIO bundling step.
#
# Distinct basename ("anomaly_test.bin") from the other fixture
# binaries so all coexist in the same CPIO archive.

set(ANOMALY_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/anomaly_test.bin"
    CACHE FILEPATH "Path to the pre-built weighted-score anomaly-test fixture"
    FORCE)

if(NOT EXISTS "${ANOMALY_TEST_BIN}")
    message(WARNING
        "sotOs-anomaly-test: ${ANOMALY_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
