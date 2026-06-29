# SOTOS vDSO build — host gcc, freestanding PIC shared object.
#
# Uses the HOST gcc (not the seL4 cross-compiler) to produce a
# position-independent linux-vdso.so.1 stub that a real libc can
# resolve __vdso_clock_gettime / __vdso_gettimeofday / … from.
#
# Output: ${CMAKE_BINARY_DIR}/images/vdso.so
# Task 4 (vdso-map) will embed this blob into the orchestrator image.

cmake_minimum_required(VERSION 3.16)

# Resolve the host C compiler.  Prefer an explicit HOST_CC env var, fall
# back to plain gcc (must be in PATH).
if(DEFINED ENV{HOST_CC})
    set(VDSO_CC "$ENV{HOST_CC}")
else()
    find_program(VDSO_CC gcc REQUIRED)
endif()

set(VDSO_SRC  "${CMAKE_CURRENT_SOURCE_DIR}/vdso_time.c")
set(VDSO_LDS  "${CMAKE_CURRENT_SOURCE_DIR}/vdso.lds")
set(VDSO_OUT  "${CMAKE_BINARY_DIR}/images/vdso.so")

add_custom_command(
    OUTPUT  "${VDSO_OUT}"
    COMMAND ${CMAKE_COMMAND} -E make_directory "${CMAKE_BINARY_DIR}/images"
    COMMAND "${VDSO_CC}"
            -shared -fPIC
            -fno-stack-protector
            -fno-asynchronous-unwind-tables
            -nostdlib
            -I"${CMAKE_CURRENT_SOURCE_DIR}"
            "-Wl,-T,${VDSO_LDS}"
            -Wl,--hash-style=both
            "-Wl,-soname,linux-vdso.so.1"
            -Wl,-Bsymbolic
            -Wl,--no-warn-rwx-segments
            -o "${VDSO_OUT}"
            "${VDSO_SRC}"
    DEPENDS "${VDSO_SRC}" "${VDSO_LDS}"
    COMMENT "Building vDSO stub: vdso.so"
    VERBATIM
)

add_custom_target(sotos-vdso ALL
    DEPENDS "${VDSO_OUT}"
)

# Export the path so parent CMakeLists / Task-4 can reference it without
# hardcoding the images/ sub-directory.
set(SOTOS_VDSO_SO "${VDSO_OUT}" CACHE FILEPATH "Path to the built vdso.so" FORCE)
