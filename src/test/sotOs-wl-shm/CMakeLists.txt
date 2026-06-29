# sotOs-wl-shm guest fixture (L13-D1).
# Pre-built .bin (see Makefile.fixture; not compiled by CMake).
set(WL_SHM_BIN "${CMAKE_CURRENT_SOURCE_DIR}/wl_shm.bin"
    CACHE FILEPATH "Pre-built sotOs-wl-shm guest binary" FORCE)
if(NOT EXISTS "${WL_SHM_BIN}")
    message(WARNING "sotOs-wl-shm: ${WL_SHM_BIN} missing; run 'make -f Makefile.fixture'")
endif()
