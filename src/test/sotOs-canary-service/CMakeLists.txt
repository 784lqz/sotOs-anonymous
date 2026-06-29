# sotOs-canary-service guest fixture (sottrace-v1 · T10).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(CANARY_SERVICE_BIN "${CMAKE_CURRENT_SOURCE_DIR}/canary_service.bin"
    CACHE FILEPATH "Pre-built sotOs-canary-service guest binary" FORCE)
if(NOT EXISTS "${CANARY_SERVICE_BIN}")
    message(WARNING "sotOs-canary-service: ${CANARY_SERVICE_BIN} missing; run 'make -f Makefile.fixture'")
endif()
