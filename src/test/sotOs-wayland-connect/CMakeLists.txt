# sotOs-wayland-connect guest fixture (L12-beta).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(WAYLAND_CONNECT_BIN "${CMAKE_CURRENT_SOURCE_DIR}/wayland_connect.bin"
    CACHE FILEPATH "Pre-built sotOs-wayland-connect guest binary" FORCE)
if(NOT EXISTS "${WAYLAND_CONNECT_BIN}")
    message(WARNING "sotOs-wayland-connect: ${WAYLAND_CONNECT_BIN} missing; run 'make -f Makefile.fixture'")
endif()
