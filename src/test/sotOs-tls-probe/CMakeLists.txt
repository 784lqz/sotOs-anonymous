# sotOs · sotOs-tls-probe guest fixture (sotNet γ-3-γ-2b).
# Pre-built .bin (see Makefile.fixture · NOT compiled by CMake · committed).
set(TLS_PROBE_BIN "${CMAKE_CURRENT_SOURCE_DIR}/tls_probe.bin"
    CACHE FILEPATH "Pre-built sotOs-tls-probe guest binary" FORCE)
if(NOT EXISTS "${TLS_PROBE_BIN}")
    message(WARNING "sotOs-tls-probe: ${TLS_PROBE_BIN} missing · run 'make -f Makefile.fixture'")
endif()
