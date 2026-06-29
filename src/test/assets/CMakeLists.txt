# L14a · baked Canary Screenshot asset (GNOME+Files, BGRA 256x192).
# Pre-built raw RGBA (see gen-canary-desktop.py; not compiled by CMake).
set(CANARY_DESKTOP_RGBA "${CMAKE_CURRENT_SOURCE_DIR}/canary-desktop.rgba"
    CACHE FILEPATH "Pre-built L14a canary-screenshot asset" FORCE)
if(NOT EXISTS "${CANARY_DESKTOP_RGBA}")
    message(WARNING "L14a: ${CANARY_DESKTOP_RGBA} missing; run 'python3 gen-canary-desktop.py'")
endif()

# L14b · baked xkb_v1 keymap asset (us layout).
# Pre-built raw blob (see gen-keymap.py; not compiled by CMake).
set(KEYMAP_US_XKB "${CMAKE_CURRENT_SOURCE_DIR}/keymap-us.xkb"
    CACHE FILEPATH "Pre-built L14b xkb keymap asset" FORCE)
if(NOT EXISTS "${KEYMAP_US_XKB}")
    message(WARNING "L14b: ${KEYMAP_US_XKB} missing; run 'python3 gen-keymap.py'")
endif()
