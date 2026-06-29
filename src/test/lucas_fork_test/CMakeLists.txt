set(LUCAS_FORK_TEST_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/fork_test.bin"
    CACHE FILEPATH "Path to the pre-built fork_test fixture"
    FORCE)

if(NOT EXISTS "${LUCAS_FORK_TEST_BIN}")
    message(WARNING "lucas_fork_test: ${LUCAS_FORK_TEST_BIN} not found · run rebuild per README.md")
endif()
