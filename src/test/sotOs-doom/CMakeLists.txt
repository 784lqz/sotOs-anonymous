set(DOOM_BIN "${CMAKE_CURRENT_SOURCE_DIR}/doom.bin"
    CACHE FILEPATH "Prebuilt static-musl doomgeneric (see README.md)" FORCE)
set(DOOM_WAD "${CMAKE_CURRENT_SOURCE_DIR}/doom1.wad"
    CACHE FILEPATH "Doom shareware IWAD" FORCE)
set(CHOCODOOM_BIN "${CMAKE_CURRENT_SOURCE_DIR}/chocodoom.bin"
    CACHE FILEPATH "Phase-2 · Chocolate Doom (real SDL2 port) static-musl" FORCE)
set(DOOMSDL_BIN "${CMAKE_CURRENT_SOURCE_DIR}/doomsdl.bin"
    CACHE FILEPATH "Phase-2 · doomgeneric over real static-musl SDL2" FORCE)
set(DOOMWL_BIN "${CMAKE_CURRENT_SOURCE_DIR}/doomwl.bin"
    CACHE FILEPATH "v2.3-M5 · doomgeneric over real DYNAMIC SDL2 (wayland/SOFTWARE → wl_shm)" FORCE)
foreach(f "${DOOM_BIN}" "${DOOM_WAD}")
  if(NOT EXISTS "${f}")
    message(WARNING "sotOs-doom: ${f} not found · see README.md")
  endif()
endforeach()
