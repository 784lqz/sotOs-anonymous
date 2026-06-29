# sotOs-dnsprobe guest fixture (Internet Egress Phase 1 · Task 5).
# Pre-built .bin (see Makefile.fixture; static musl · not compiled by CMake).
set(DNSPROBE_BIN "${CMAKE_CURRENT_SOURCE_DIR}/dnsprobe.bin"
    CACHE FILEPATH "Pre-built sotOs-dnsprobe guest binary" FORCE)
if(NOT EXISTS "${DNSPROBE_BIN}")
    message(WARNING "sotOs-dnsprobe: ${DNSPROBE_BIN} missing; run 'make -f Makefile.fixture'")
endif()
