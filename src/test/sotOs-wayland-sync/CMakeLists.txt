# sotOs-wayland-sync guest fixture (L12-gamma).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(WAYLAND_SYNC_BIN "${CMAKE_CURRENT_SOURCE_DIR}/wayland_sync.bin"
    CACHE FILEPATH "Pre-built sotOs-wayland-sync guest binary" FORCE)
if(NOT EXISTS "${WAYLAND_SYNC_BIN}")
    message(WARNING "sotOs-wayland-sync: ${WAYLAND_SYNC_BIN} missing; run 'make -f Makefile.fixture'")
endif()
