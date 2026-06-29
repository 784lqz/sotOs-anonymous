# sotOs-wl-capture-client guest fixture (L14a-D1).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(WL_CAPTURE_CLIENT_BIN "${CMAKE_CURRENT_SOURCE_DIR}/wl_capture_client.bin"
    CACHE FILEPATH "Pre-built sotOs-wl-capture-client guest binary" FORCE)
if(NOT EXISTS "${WL_CAPTURE_CLIENT_BIN}")
    message(WARNING "sotOs-wl-capture-client: ${WL_CAPTURE_CLIENT_BIN} missing; run 'make -f Makefile.fixture'")
endif()
