# sotOs-egress-probe guest fixture (N1a).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(EGRESS_PROBE_BIN "${CMAKE_CURRENT_SOURCE_DIR}/egress_probe.bin"
    CACHE FILEPATH "Pre-built sotOs-egress-probe guest binary" FORCE)
if(NOT EXISTS "${EGRESS_PROBE_BIN}")
    message(WARNING "sotOs-egress-probe: ${EGRESS_PROBE_BIN} missing; run 'make -f Makefile.fixture'")
endif()
