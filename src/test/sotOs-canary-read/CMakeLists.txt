# sotOs-canary-read guest fixture (sottrace-v1 · T11).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(CANARY_READ_BIN "${CMAKE_CURRENT_SOURCE_DIR}/canary_read.bin"
    CACHE FILEPATH "Pre-built sotOs-canary-read guest binary" FORCE)
if(NOT EXISTS "${CANARY_READ_BIN}")
    message(WARNING "sotOs-canary-read: ${CANARY_READ_BIN} missing; run 'make -f Makefile.fixture'")
endif()
