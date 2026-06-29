# Marker target for the Pillar-2 P2b fork-bomb gate fixture · the binary is
# pre-built and committed; CMake doesn't compile it. We expose its path as a
# variable for orch's CPIO bundling step (see src/orch/CMakeLists.txt).

set(LUCAS_FORK_BOMB_BIN
    "${CMAKE_CURRENT_SOURCE_DIR}/fork_bomb.bin"
    CACHE FILEPATH "Path to the pre-built fork_bomb gate fixture"
    FORCE)

if(NOT EXISTS "${LUCAS_FORK_BOMB_BIN}")
    message(WARNING "fork_bomb: ${LUCAS_FORK_BOMB_BIN} not found · run rebuild per Makefile.fixture")
endif()
