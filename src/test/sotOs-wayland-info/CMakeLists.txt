# sotOs-wayland-info guest fixture (L12-delta).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(WAYLAND_INFO_BIN "${CMAKE_CURRENT_SOURCE_DIR}/wayland_info.bin"
    CACHE FILEPATH "Pre-built sotOs-wayland-info guest binary" FORCE)
if(NOT EXISTS "${WAYLAND_INFO_BIN}")
    message(WARNING "sotOs-wayland-info: ${WAYLAND_INFO_BIN} missing; run 'make -f Makefile.fixture'")
endif()
