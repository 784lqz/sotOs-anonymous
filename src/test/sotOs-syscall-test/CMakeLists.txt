# Marker target for the PR 6 POSIX-surface syscall-test fixture · the
# binary is pre-built and committed (same pattern as shellhook_test /
# stage7_demo / sotOs-procd-fork-test).  We expose its path as a
# variable for the orch CPIO bundling step.
#
# Distinct basename ("syscall_test.bin") from the other fixture
# binaries so all coexist in the same CPIO archive.

set(SYSCALL_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/syscall_test.bin"
    CACHE FILEPATH "Path to the pre-built POSIX-surface syscall-test fixture"
    FORCE)

if(NOT EXISTS "${SYSCALL_TEST_BIN}")
    message(WARNING
        "sotOs-syscall-test: ${SYSCALL_TEST_BIN} not found · "
        "rebuild per Makefile.fixture")
endif()
